import configparser
import os
import subprocess
import tempfile
import threading
import time
import tkinter as tk
import urllib.request
from pathlib import Path
from shutil import which
from tkinter import messagebox, scrolledtext

import direct_sni
import ssh_socks

HTTP_PROXY = "127.0.0.1:8080"
SOCKS_PROXY = "127.0.0.1:1080"


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNI Injector")
        self.geometry("520x760")
        self.resizable(False, False)
        self.configure(bg="#0f172a")
        self.running = False
        self.socks = None
        self.bytes_up = 0
        self.bytes_down = 0
        self._pending_up = 0
        self._pending_down = 0
        self.config = configparser.ConfigParser()
        self.config.read("settings.ini")

        self._build_ui()
        self.after(500, self._flush_traffic)

    def _build_ui(self):
        tk.Label(
            self, text="SNI Injector", font=("Segoe UI", 20, "bold"),
            fg="#e2e8f0", bg="#0f172a",
        ).pack(pady=(14, 2))

        tk.Label(
            self, text="تشفير + بروكسي + ترافيك لايف",
            font=("Segoe UI", 9), fg="#94a3b8", bg="#0f172a",
        ).pack(pady=(0, 8))

        mode_frame = tk.Frame(self, bg="#0f172a")
        mode_frame.pack(padx=28, fill="x", pady=(0, 6))

        saved = self.config.get("settings", "mode", fallback="ssh").strip().lower()
        self.mode_var = tk.StringVar(value=saved if saved in ("ssh", "direct") else "ssh")

        tk.Label(mode_frame, text="طريقة الاتصال", fg="#94a3b8", bg="#0f172a",
                 font=("Segoe UI", 9)).pack(anchor="w")
        modes = tk.Frame(mode_frame, bg="#0f172a")
        modes.pack(fill="x", pady=4)
        tk.Radiobutton(
            modes, text="OpenTunnel / SSH", variable=self.mode_var, value="ssh",
            command=self._on_mode_change, fg="#e2e8f0", bg="#0f172a",
            selectcolor="#1e293b", activebackground="#0f172a", font=("Segoe UI", 9),
        ).pack(side="left", padx=(0, 12))
        tk.Radiobutton(
            modes, text="Direct SNI (بدون SSH)", variable=self.mode_var, value="direct",
            command=self._on_mode_change, fg="#e2e8f0", bg="#0f172a",
            selectcolor="#1e293b", activebackground="#0f172a", font=("Segoe UI", 9),
        ).pack(side="left")

        form = tk.Frame(self, bg="#0f172a")
        form.pack(padx=28, fill="x")

        host = self.config.get("ssh", "host", fallback="")
        sni = self.config.get("sni", "server_name", fallback="")
        user = self.config.get("ssh", "username", fallback="")
        password = self.config.get("ssh", "password", fallback="")

        self.host_var = tk.StringVar(value=host)
        self.sni_var = tk.StringVar(value=sni)
        self.user_var = tk.StringVar(value=user)
        self.pass_var = tk.StringVar(value=password)

        self._entry(form, "السيرفر", self.host_var)
        self._entry(form, "SNI", self.sni_var)
        self.user_entry = self._entry(form, "يوزر SSH", self.user_var)
        self.pass_entry = self._entry(form, "باسورد SSH", self.pass_var, show="*")

        self.mode_hint = tk.Label(
            self, text="", font=("Segoe UI", 8), fg="#64748b", bg="#0f172a",
            wraplength=440, justify="right",
        )
        self.mode_hint.pack(padx=28, pady=(4, 0))

        btns = tk.Frame(self, bg="#0f172a")
        btns.pack(pady=10)

        self.start_btn = tk.Button(
            btns, text="تشغيل التشفير", font=("Segoe UI", 13, "bold"),
            fg="#0f172a", bg="#38bdf8", activebackground="#7dd3fc",
            relief="flat", cursor="hand2", width=14, height=1, command=self.start,
        )
        self.start_btn.pack(side="left", padx=4)

        self.ip_btn = tk.Button(
            btns, text="فحص الـ IP", font=("Segoe UI", 11, "bold"),
            fg="#e2e8f0", bg="#334155", activebackground="#475569",
            relief="flat", cursor="hand2", width=10, height=1, command=self.check_ip,
        )
        self.ip_btn.pack(side="left", padx=4)

        self.chrome_btn = tk.Button(
            btns, text="فتح Chrome", font=("Segoe UI", 11, "bold"),
            fg="#0f172a", bg="#4ade80", activebackground="#86efac",
            relief="flat", cursor="hand2", width=10, height=1, command=self.open_chrome,
        )
        self.chrome_btn.pack(side="left", padx=4)

        self.status = tk.Label(
            self, text="الحالة: متوقف", font=("Segoe UI", 10),
            fg="#fbbf24", bg="#0f172a",
        )
        self.status.pack()

        box = tk.Frame(self, bg="#1e293b", padx=14, pady=10)
        box.pack(fill="x", padx=28, pady=(10, 6))

        tk.Label(box, text="بروكسي ويندوز / كروم (HTTP) — اضغط للنسخ",
                 font=("Segoe UI", 8), fg="#94a3b8", bg="#1e293b").pack()
        self.proxy_label = tk.Label(
            box, text="—", font=("Consolas", 16, "bold"),
            fg="#4ade80", bg="#1e293b", cursor="hand2",
        )
        self.proxy_label.pack(pady=(2, 0))
        self.proxy_label.bind("<Button-1>", self.copy_proxy)

        self.socks_label = tk.Label(
            box, text="—", font=("Consolas", 11),
            fg="#38bdf8", bg="#1e293b", cursor="hand2",
        )
        self.socks_label.pack(pady=(6, 0))
        self.socks_label.bind("<Button-1>", self.copy_socks)
        tk.Label(box, text="فوق = ويندوز/كروم · تحت = Firefox SOCKS5",
                 font=("Segoe UI", 8), fg="#64748b", bg="#1e293b").pack()

        stats = tk.Frame(self, bg="#0f172a")
        stats.pack(fill="x", padx=28, pady=6)
        self.up_label = tk.Label(stats, text="↑ رفع: 0 B", font=("Consolas", 10),
                                 fg="#38bdf8", bg="#0f172a")
        self.up_label.pack(side="left", expand=True)
        self.down_label = tk.Label(stats, text="↓ تنزيل: 0 B", font=("Consolas", 10),
                                   fg="#4ade80", bg="#0f172a")
        self.down_label.pack(side="right", expand=True)

        tk.Label(self, text="الترافيك / المواقع", font=("Segoe UI", 9),
                 fg="#94a3b8", bg="#0f172a").pack(anchor="w", padx=28, pady=(6, 2))

        self.log_box = scrolledtext.ScrolledText(
            self, height=14, font=("Consolas", 9), bg="#020617", fg="#cbd5e1",
            insertbackground="#e2e8f0", relief="flat", state="disabled",
        )
        self.log_box.pack(fill="both", expand=True, padx=28, pady=(0, 14))
        self.log_box.tag_config("up", foreground="#38bdf8")
        self.log_box.tag_config("down", foreground="#4ade80")
        self.log_box.tag_config("ok", foreground="#4ade80")
        self.log_box.tag_config("err", foreground="#f87171")
        self.log_box.tag_config("info", foreground="#94a3b8")
        self.log_box.tag_config("socks", foreground="#fbbf24")

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._on_mode_change()

    def _entry(self, parent, label, var, show=None):
        row = tk.Frame(parent, bg="#0f172a")
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label, width=10, anchor="e", fg="#94a3b8",
                 bg="#0f172a", font=("Segoe UI", 9)).pack(side="left")
        ent = tk.Entry(row, textvariable=var, show=show, font=("Consolas", 10),
                       fg="#e2e8f0", bg="#1e293b", insertbackground="#e2e8f0", relief="flat")
        ent.pack(side="left", fill="x", expand=True, ipady=3, padx=(8, 0))
        return ent

    def _on_mode_change(self):
        direct = self.mode_var.get() == "direct"
        state = "disabled" if direct else "normal"
        self.user_entry.configure(state=state)
        self.pass_entry.configure(state=state)
        if direct:
            self.mode_hint.configure(
                text="Direct: يحتاج VPS عليه stunnel+tinyproxy (شوف مجلد server/). "
                     "IP الخارج = IP السيرفر. OpenTunnel المجاني مش هينفع هنا."
            )
        else:
            self.mode_hint.configure(
                text="SSH: مناسب لـ OpenTunnel والحسابات اللي بتشتغل بعد WebSocket upgrade."
            )

    def log(self, msg, tag="info"):
        if not msg:
            return
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {msg}\n", tag)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def on_socks_event(self, msg, bytes_up=0, bytes_down=0, dest=""):
        if bytes_up or bytes_down:
            self._pending_up += bytes_up
            self._pending_down += bytes_down
            return
        tag = "socks" if msg.startswith("[SOCKS]") or msg.startswith("[DIRECT]") else (
            "ok" if "OK" in msg or "Listening" in msg else "info"
        )
        if "fail" in msg.lower() or "error" in msg.lower():
            tag = "err"

        def apply():
            self.log(msg, tag)
            if "[HTTP] Listening" in msg:
                self.proxy_label.configure(text=HTTP_PROXY)
                self.socks_label.configure(text=f"SOCKS5 {SOCKS_PROXY}")
                self.clipboard_clear()
                self.clipboard_append(HTTP_PROXY)
                self.status.configure(
                    text="جاهز · في ويندوز حط Address 127.0.0.1 Port 8080",
                    fg="#4ade80",
                )
                self.log(f"ويندوز/كروم → {HTTP_PROXY} (HTTP)", "ok")
                self.log(f"Firefox → {SOCKS_PROXY} (SOCKS5)", "ok")

        self.after(0, apply)

    def _flush_traffic(self):
        up, down = self._pending_up, self._pending_down
        if up or down:
            self._pending_up = 0
            self._pending_down = 0
            self.bytes_up += up
            self.bytes_down += down
            self.up_label.configure(text=f"↑ رفع: {fmt_bytes(self.bytes_up)}")
            self.down_label.configure(text=f"↓ تنزيل: {fmt_bytes(self.bytes_down)}")
            if self.running:
                self.status.configure(
                    text=f"الحالة: شغال · ↑{fmt_bytes(self.bytes_up)} ↓{fmt_bytes(self.bytes_down)}",
                    fg="#4ade80",
                )
        self.after(400, self._flush_traffic)

    def _save_settings(self):
        if "settings" not in self.config:
            self.config["settings"] = {}
        if "ssh" not in self.config:
            self.config["ssh"] = {}
        if "sni" not in self.config:
            self.config["sni"] = {}
        self.config["settings"]["mode"] = self.mode_var.get()
        self.config["ssh"]["host"] = self.host_var.get().strip()
        self.config["ssh"]["username"] = self.user_var.get().strip()
        self.config["ssh"]["password"] = self.pass_var.get()
        self.config["sni"]["server_name"] = self.sni_var.get().strip()
        with open("settings.ini", "w", encoding="utf-8") as f:
            self.config.write(f)

    def start(self):
        if self.running:
            return

        host = self.host_var.get().strip()
        sni = self.sni_var.get().strip()
        mode = self.mode_var.get()
        user = self.user_var.get().strip()
        password = self.pass_var.get()

        if not host or not sni:
            messagebox.showwarning("ناقص", "اكتب السيرفر و الـ SNI")
            return
        if mode == "ssh" and (not user or not password):
            messagebox.showwarning("ناقص", "وضع SSH محتاج يوزر وباسورد")
            return

        self._save_settings()

        self.running = True
        self.bytes_up = self.bytes_down = 0
        self._pending_up = self._pending_down = 0
        self.up_label.configure(text="↑ رفع: 0 B")
        self.down_label.configure(text="↓ تنزيل: 0 B")
        self.start_btn.configure(state="disabled", text="يعمل الآن...")
        self.status.configure(text="الحالة: تشغيل التشفير...", fg="#38bdf8")

        if mode == "direct":
            self.log("تشغيل Direct SNI (بدون SSH)...", "info")
            threading.Thread(target=self._run_direct, args=(host, sni), daemon=True).start()
        else:
            self.log("تشغيل OpenTunnel (SNI + SSH)...", "info")
            threading.Thread(
                target=self._run_ssh, args=(user, password, host), daemon=True
            ).start()

    def _run_direct(self, host, sni):
        try:
            self.after(0, lambda: self.status.configure(text="الحالة: Direct SNI...", fg="#38bdf8"))
            port = int(self.config.get("ssh", "port", fallback="443"))
            self.socks = direct_sni.DirectSNIProxy(
                host=host,
                port=port,
                sni=sni,
                on_event=self.on_socks_event,
            )
            self.socks.start()
        except Exception as e:
            err = str(e)
            self.after(0, lambda err=err: self._fail(err))

    def _run_ssh(self, user, password, host):
        try:
            self.after(0, lambda: self.status.configure(text="الحالة: SSH...", fg="#38bdf8"))
            port = int(self.config.get("ssh", "port", fallback="443"))
            self.socks = ssh_socks.SocksOverSSH(
                host=host,
                port=port,
                username=user,
                password=password,
                socks_port=1080,
                on_event=self.on_socks_event,
            )
            self.socks.start()
        except Exception as e:
            err = str(e)
            self.after(0, lambda err=err: self._fail(err))

    def _fail(self, error):
        self.running = False
        if self.socks:
            try:
                self.socks.stop()
            except Exception:
                pass
            self.socks = None
        self.start_btn.configure(state="normal", text="تشغيل التشفير")
        self.status.configure(text="خطأ", fg="#f87171")
        self.proxy_label.configure(text="—")
        self.socks_label.configure(text="—")
        self.log(error, "err")
        messagebox.showerror("خطأ", error)

    def copy_proxy(self, _=None):
        text = self.proxy_label.cget("text")
        if text and text != "—":
            self.clipboard_clear()
            self.clipboard_append(text)
            self.log(f"تم نسخ {text}", "ok")

    def copy_socks(self, _=None):
        self.clipboard_clear()
        self.clipboard_append(SOCKS_PROXY)
        self.log(f"تم نسخ {SOCKS_PROXY}", "ok")

    def _find_chrome(self):
        candidates = [
            which("chrome"),
            which("chrome.exe"),
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        ]
        for path in candidates:
            if path and Path(path).is_file():
                return path
        return None

    def open_chrome(self):
        if not self.running or not (self.socks and self.socks.ready):
            messagebox.showwarning("لسه مش جاهز", "شغّل التشفير واستنى Listening الأول")
            return
        chrome = self._find_chrome()
        if not chrome:
            messagebox.showerror("مش لاقي Chrome", "ثبّت Chrome أو Edge")
            return

        profile = os.path.join(tempfile.gettempdir(), "sni_injector_chrome")
        os.makedirs(profile, exist_ok=True)
        cmd = [
            chrome,
            f"--proxy-server=http://{HTTP_PROXY}",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "https://api.ipify.org",
        ]
        subprocess.Popen(cmd)
        self.log(f"اتفتح المتصفح على البروكسي {HTTP_PROXY}", "ok")

    def check_ip(self):
        if not self.running or not (self.socks and self.socks.ready):
            messagebox.showwarning(
                "لسه مش جاهز",
                "استنى لحد ما يظهر في اللوج:\n[HTTP] Listening on 127.0.0.1:8080",
            )
            return
        self.ip_btn.configure(state="disabled", text="...")
        self.log("فحص الـ IP عبر البروكسي...", "info")
        threading.Thread(target=self._check_ip_worker, daemon=True).start()

    def _check_ip_worker(self):
        try:
            handler = urllib.request.ProxyHandler({
                "http": f"http://{HTTP_PROXY}",
                "https": f"http://{HTTP_PROXY}",
            })
            opener = urllib.request.build_opener(handler)
            ip = opener.open("https://api.ipify.org", timeout=20).read().decode().strip()
            server = self.host_var.get().strip()
            msg = f"IP عبر البروكسي: {ip} ✓ (السيرفر {server})"
            self.after(0, lambda m=msg, i=ip: self._ip_done(m, True, i))
        except Exception as e:
            err = f"فشل الفحص: {e}"
            self.after(0, lambda m=err: self._ip_done(m, False, ""))

    def _ip_done(self, msg, ok, ip):
        self.ip_btn.configure(state="normal", text="فحص الـ IP")
        self.log(msg, "ok" if ok else "err")
        if ok and ip:
            messagebox.showinfo("فحص IP", f"التانل شغال\n\nIP الخارج:\n{ip}")
        else:
            messagebox.showerror("فشل الفحص", msg)

    def on_close(self):
        if self.socks:
            try:
                self.socks.stop()
            except Exception:
                pass
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
