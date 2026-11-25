"""SSH dynamic SOCKS5 + HTTP proxy over OpenTunnel (SNI + WebSocket + SSH)."""
from __future__ import annotations

import configparser
import select
import socket
import struct
import threading
import time

import paramiko

from http_util import parse_host_port
from tls_util import TlsSettings, wrap_socket_client

SOCKS_PORT = 1080
HTTP_PORT = 8080


def _bridge_socket(ssl_sock, prefix=b""):
    """
    Paramiko needs a real socket (select). Bridge SSL + leftover SSH bytes
    through a local socketpair. Prefix is seeded synchronously to avoid races.
    """
    local, remote = socket.socketpair()
    local.settimeout(None)
    remote.settimeout(None)
    ssl_sock.settimeout(None)
    lock = threading.Lock()

    if prefix:
        local.sendall(prefix)

    def pump():
        try:
            while True:
                with lock:
                    data = ssl_sock.recv(16384)
                if not data:
                    break
                local.sendall(data)
        except Exception:
            pass
        try:
            local.shutdown(socket.SHUT_WR)
        except Exception:
            pass

    def pump_up():
        try:
            while True:
                data = local.recv(16384)
                if not data:
                    break
                with lock:
                    ssl_sock.sendall(data)
        except Exception:
            pass
        try:
            with lock:
                ssl_sock.shutdown(socket.SHUT_WR)
        except Exception:
            pass

    threading.Thread(target=pump, daemon=True).start()
    threading.Thread(target=pump_up, daemon=True).start()
    return remote


def _connect_opentunnel_once(host, port, sni, timeout=20, tls: TlsSettings | None = None):
    """
    OpenTunnel protocol:
      TCP -> TLS(ClientHello SNI=bug-host) -> HTTP 101 -> raw SSH

    SNI spoof is not ECH / DPI obfuscation. Peer auth = [ssl] pin/hostname.
    """
    raw = socket.create_connection((host, int(port)), timeout=timeout)
    settings = tls or TlsSettings(sni=str(sni), verify="none")
    if settings.sni != str(sni):
        settings = TlsSettings(
            sni=str(sni),
            verify=settings.verify,
            verify_hostname=settings.verify_hostname,
            cert_pin_sha256=settings.cert_pin_sha256,
            ca_file=settings.ca_file,
        )
    sock = wrap_socket_client(raw, settings)
    verify_status = getattr(sock, "_sni_injector_verify_status", "")

    sock.sendall(
        f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    )

    sock.settimeout(2)
    buf = b""
    deadline = time.time() + timeout
    while b"\r\n\r\n" not in buf and time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk

    if b"\r\n\r\n" not in buf:
        sock.close()
        raise ConnectionError("OpenTunnel: no HTTP response")

    header, _, leftover = buf.partition(b"\r\n\r\n")
    http_status = header.split(b"\r\n", 1)[0]
    if b"101" not in http_status and b"200" not in http_status:
        sock.close()
        raise ConnectionError(
            f"OpenTunnel upgrade failed: {http_status.decode(errors='ignore')}"
        )

    # SSH banner غالبًا في باكت تاني — نفضل نستنى ومش نخرج من أول timeout
    sock.settimeout(2)
    end = time.time() + 15
    while not leftover.startswith(b"SSH-") and time.time() < end:
        try:
            more = sock.recv(4096)
        except socket.timeout:
            continue
        except Exception:
            break
        if not more:
            break
        leftover += more

    if not leftover.startswith(b"SSH-"):
        sock.close()
        raise ConnectionError("OpenTunnel: SSH banner not received after upgrade")

    bridged = _bridge_socket(sock, leftover)
    bridged._sni_injector_verify_status = verify_status  # type: ignore[attr-defined]
    return bridged


def connect_opentunnel(
    host, port, sni, timeout=20, retries=5, on_try=None, tls: TlsSettings | None = None
):
    """Retry flaky OpenTunnel handshakes."""
    last_err = None
    for attempt in range(1, retries + 1):
        if on_try:
            try:
                on_try(attempt, retries)
            except Exception:
                pass
        try:
            return _connect_opentunnel_once(
                host, port, sni, timeout=timeout, tls=tls
            )
        except Exception as e:
            last_err = e
            time.sleep(0.6 * attempt)
    raise ConnectionError(f"{last_err} (بعد {retries} محاولات)")


def _connect_stunnel_ssh(host, port, sni, timeout=15, tls: TlsSettings | None = None):
    """Classic stunnel: TLS+SNI then immediate SSH banner (no HTTP upgrade)."""
    raw = socket.create_connection((host, int(port)), timeout=timeout)
    settings = tls or TlsSettings(sni=str(sni), verify="none")
    if settings.sni != str(sni):
        settings = TlsSettings(
            sni=str(sni),
            verify=settings.verify,
            verify_hostname=settings.verify_hostname,
            cert_pin_sha256=settings.cert_pin_sha256,
            ca_file=settings.ca_file,
        )
    sock = wrap_socket_client(raw, settings)
    verify_status = getattr(sock, "_sni_injector_verify_status", "")
    sock.settimeout(2)
    leftover = b""
    end = time.time() + timeout
    while not leftover.startswith(b"SSH-") and time.time() < end:
        try:
            more = sock.recv(4096)
        except socket.timeout:
            continue
        if not more:
            break
        leftover += more
    if not leftover.startswith(b"SSH-"):
        sock.close()
        raise ConnectionError("stunnel: no SSH banner after TLS")
    bridged = _bridge_socket(sock, leftover)
    bridged._sni_injector_verify_status = verify_status  # type: ignore[attr-defined]
    return bridged


def _connect_plain_ssh(host, port, timeout=15):
    """Direct SSH (usually port 22) — بدون SNI، من غير bridge."""
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock.settimeout(None)
    return sock


def connect_ssh_auto(
    host, port, sni, plain_port=22, on_event=None, tls: TlsSettings | None = None
):
    """
    Try in order:
      1) OpenTunnel (TLS+SNI+HTTP 101+SSH)
      2) stunnel (TLS+SNI+SSH)
      3) plain SSH on plain_port (no SNI)
    """
    def emit(msg):
        if on_event:
            try:
                on_event(msg)
            except Exception:
                pass

    errors = []
    tls_settings = tls or TlsSettings(sni=str(sni), verify="none")
    emit(
        f"[SSH] TLS verify={tls_settings.verify} | "
        "حقن SNI ≠ ECH / obfuscation ضد DPI"
    )

    emit(f"[SSH] تجربة OpenTunnel على {host}:{port} ...")
    try:
        sock = _connect_opentunnel_once(
            host, port, sni, timeout=12, tls=tls_settings
        )
        status = getattr(sock, "_sni_injector_verify_status", "")
        emit(f"[SSH] OpenTunnel OK ({tls_settings.verify})")
        if status:
            emit(f"[SSH] {status}")
        return sock, "opentunnel"
    except Exception as e:
        errors.append(f"OpenTunnel: {e}")
        emit(f"[SSH] OpenTunnel فشل: {e}")

    emit(f"[SSH] تجربة stunnel/TLS على {host}:{port} ...")
    try:
        sock = _connect_stunnel_ssh(
            host, port, sni, timeout=12, tls=tls_settings
        )
        emit(f"[SSH] stunnel OK ({tls_settings.verify})")
        return sock, "stunnel"
    except Exception as e:
        errors.append(f"stunnel: {e}")
        emit(f"[SSH] stunnel فشل: {e}")

    emit(f"[SSH] تجربة SSH عادي على {host}:{plain_port} (من غير SNI) ...")
    try:
        sock = _connect_plain_ssh(host, plain_port, timeout=12)
        emit("[SSH] Plain SSH OK — ملاحظة: مفيش حقن SNI على المنفذ ده")
        return sock, "plain"
    except Exception as e:
        errors.append(f"plain:{plain_port}: {e}")
        emit(f"[SSH] Plain SSH فشل: {e}")

    raise ConnectionError(
        "مفيش طريقة اتصالات نجحت:\n- " + "\n- ".join(errors)
        + "\n\nالسيرفر ده على 443 غالبًا مش OpenTunnel. "
        "إمّا شغّل stunnel→SSH على منفذ، أو استخدم SSH على 22."
    )


class SocksOverSSH:
    def __init__(self, host, port, username, password, injector="127.0.0.1:9092",
                 listen="127.0.0.1", socks_port=SOCKS_PORT, http_port=HTTP_PORT, on_event=None):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        inj = injector.split(":")
        self.injector_host = inj[0]
        self.injector_port = int(inj[1])
        self.listen = listen
        self.socks_port = int(socks_port)
        self.http_port = int(http_port)
        self.on_event = on_event
        self._stop = threading.Event()
        self.client = None
        self.transport = None
        self._socks_server = None
        self._http_server = None
        self.ready = False
        self._ssh_lock = threading.Lock()
        self._sni = None
        self._plain_port = 22

    def emit(self, msg, bytes_up=0, bytes_down=0, dest=""):
        if self.on_event:
            try:
                self.on_event(msg, bytes_up, bytes_down, dest)
            except Exception:
                pass

    def start(self):
        cfg = configparser.ConfigParser()
        cfg.read("settings.ini")
        self._sni = cfg.get("sni", "server_name", fallback=self.host)
        self._plain_port = int(cfg.get("ssh", "plain_port", fallback="22"))
        self._tls = TlsSettings.from_config(cfg, sni=self._sni)

        self._connect_ssh()

        self._socks_server = self._listen(self.socks_port)
        self._http_server = self._listen(self.http_port)
        self.ready = True
        self.emit(f"[SOCKS5] Listening on {self.listen}:{self.socks_port}")
        self.emit(f"[HTTP] Listening on {self.listen}:{self.http_port}  ← ويندوز/كروم")

        threading.Thread(target=self._watchdog, daemon=True).start()
        threading.Thread(target=self._accept_loop, args=(self._socks_server, "socks"), daemon=True).start()
        self._accept_loop(self._http_server, "http")

    def _connect_ssh(self):
        self.emit(f"[SSH] الهدف {self.host} | منفذ {self.port} | SNI={self._sni}")
        sock, method = connect_ssh_auto(
            self.host,
            self.port,
            self._sni,
            plain_port=self._plain_port,
            on_event=lambda m: self.emit(m),
            tls=self._tls,
        )
        self._ssh_sock = sock
        self._method = method
        self.emit(f"[SSH] Connected via {method}, authenticating...")

        transport = paramiko.Transport(sock)
        transport.banner_timeout = 60
        transport.auth_timeout = 60
        transport.use_compression(False)
        # OpenTunnel بيحب ciphers بسيطة — chacha أحيانًا بيعمل Mismatched MAC عبر الـ bridge
        try:
            opts = transport.get_security_options()
            opts.ciphers = (
                "aes128-ctr",
                "aes256-ctr",
                "aes128-cbc",
                "aes256-cbc",
            )
            opts.digests = ("hmac-sha2-256", "hmac-sha1")
        except Exception:
            pass
        transport.set_keepalive(10)
        try:
            transport.start_client(timeout=60)
        except Exception as e:
            raise ConnectionError(f"SSH banner/handshake failed: {e}") from e

        self.emit("[SSH] Banner OK, authenticating...")
        self.transport = transport
        self._authenticate()
        if not self.transport.is_authenticated():
            raise ConnectionError("SSH authentication failed")
        self.emit("[SSH] Authenticated OK")
        self._channel_sem = threading.Semaphore(12)

    def _authenticate(self):
        password = self.password

        def handler(title, instructions, prompt_list):
            return [password for _ in prompt_list]

        last_err = None
        try:
            self.transport.auth_password(self.username, password)
            return
        except Exception as e:
            last_err = e
            self.emit(f"[SSH] password auth failed: {e}")

        try:
            self.transport.auth_interactive(self.username, handler)
            return
        except Exception as e:
            last_err = e
            self.emit(f"[SSH] keyboard-interactive failed: {e}")

        raise ConnectionError(f"SSH auth failed: {last_err}")

    def _ssh_alive(self):
        t = self.transport
        return bool(t and t.is_active() and t.is_authenticated())

    def _reconnect_ssh(self):
        with self._ssh_lock:
            if self._stop.is_set():
                return False
            if self._ssh_alive():
                return True
            self.ready = False
            self.emit("[SSH] الجلسة وقعت — إعادة الاتصال...")
            try:
                if self.transport:
                    self.transport.close()
            except Exception:
                pass
            try:
                self._connect_ssh()
                self.ready = True
                self.emit("[SSH] إعادة الاتصال نجحت")
                return True
            except Exception as e:
                self.emit(f"[SSH] إعادة الاتصال فشلت: {e}")
                return False

    def _watchdog(self):
        while not self._stop.is_set():
            time.sleep(3)
            if self._stop.is_set():
                break
            t = self.transport
            if t is not None and getattr(t, "active", False) is False:
                self.emit("[SSH] Detected dead transport")
                self._reconnect_ssh()
            elif not self._ssh_alive():
                self._reconnect_ssh()
            else:
                # لو حصل Mismatched MAC جوّه thread الباراميكو، الـ transport بيموت
                exc = getattr(t, "get_exception", lambda: None)()
                if exc is not None:
                    self.emit(f"[SSH] Transport error: {exc}")
                    self._reconnect_ssh()

    def _listen(self, port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.listen, port))
        except OSError as e:
            raise ConnectionError(
                f"المنفذ {port} مشغول. اقفل البرامج اللي عليه أو غيّر البورت.\n{e}"
            ) from e
        srv.listen(64)
        srv.settimeout(1.0)
        return srv

    def _accept_loop(self, server, kind):
        while not self._stop.is_set():
            try:
                client, addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            handler = self._handle_socks if kind == "socks" else self._handle_http
            threading.Thread(target=handler, args=(client, addr), daemon=True).start()

    def stop(self):
        self._stop.set()
        self.ready = False
        for s in (self._socks_server, self._http_server):
            try:
                if s:
                    s.close()
            except Exception:
                pass
        try:
            if self.transport:
                self.transport.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass

    def _open_remote(self, host, port, addr):
        if not self._ssh_alive():
            if not self._reconnect_ssh():
                raise ConnectionError("SSH session not active")
        sem = getattr(self, "_channel_sem", None)
        if sem:
            sem.acquire()
        try:
            try:
                chan = self.transport.open_channel(
                    "direct-tcpip", (host, port), addr, timeout=30
                )
            except Exception as e:
                msg = str(e).lower()
                if (
                    not self._ssh_alive()
                    or "not active" in msg
                    or "mismatched mac" in msg
                    or "channel" in msg
                ):
                    if self._reconnect_ssh():
                        chan = self.transport.open_channel(
                            "direct-tcpip", (host, port), addr, timeout=30
                        )
                    else:
                        raise
                else:
                    raise
            # حرّر الـ sem لما القناة تتقفل
            if sem:
                original_close = chan.close

                def _close_and_release(*a, **k):
                    try:
                        return original_close(*a, **k)
                    finally:
                        try:
                            sem.release()
                        except Exception:
                            pass

                chan.close = _close_and_release
            return chan
        except Exception:
            if sem:
                try:
                    sem.release()
                except Exception:
                    pass
            raise

    def _handle_socks(self, client, addr):
        remote = None
        dest = ""
        try:
            client.settimeout(30)
            data = client.recv(262)
            if len(data) < 2 or data[0] != 5:
                client.close()
                return
            client.sendall(b"\x05\x00")

            req = client.recv(4)
            if len(req) < 4 or req[0] != 5 or req[1] != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client.close()
                return

            atyp = req[3]
            if atyp == 1:
                host = socket.inet_ntoa(client.recv(4))
            elif atyp == 3:
                ln = client.recv(1)[0]
                host = client.recv(ln).decode("utf-8", errors="ignore")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, client.recv(16))
            else:
                client.close()
                return

            port = struct.unpack("!H", client.recv(2))[0]
            dest = f"{host}:{port}"
            self.emit(f"[SOCKS] → {dest}", dest=dest)

            remote = self._open_remote(host, port, addr)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self._pipe(client, remote, dest)
        except Exception as e:
            self.emit(f"[SOCKS] fail {dest or addr}: {e}")
            try:
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            except Exception:
                pass
        finally:
            self._close(client, remote)

    def _handle_http(self, client, addr):
        remote = None
        dest = ""
        try:
            client.settimeout(30)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                data += chunk
                if len(data) > 65536:
                    client.close()
                    return

            header, _, rest = data.partition(b"\r\n\r\n")
            first = header.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            parts = first.split()
            if len(parts) < 2:
                client.close()
                return

            method, target = parts[0].upper(), parts[1]

            if method == "CONNECT":
                host, port = parse_host_port(target, 443)
                dest = f"{host}:{port}"
                self.emit(f"[HTTP] CONNECT → {dest}", dest=dest)
                remote = self._open_remote(host, port, addr)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    remote.sendall(rest)
                    self.emit("", bytes_up=len(rest), dest=dest)
                self._pipe(client, remote, dest)
            else:
                if target.startswith("http://"):
                    without = target[7:]
                    hostport, _, path = without.partition("/")
                    path = "/" + path
                else:
                    hostport = ""
                    for line in header.split(b"\r\n")[1:]:
                        if line.lower().startswith(b"host:"):
                            hostport = line.split(b":", 1)[1].strip().decode()
                            break
                    path = target

                if not hostport:
                    client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    client.close()
                    return

                host, port = parse_host_port(hostport, 80)
                dest = f"{host}:{port}"
                self.emit(f"[HTTP] {method} → {dest}{path}", dest=dest)
                remote = self._open_remote(host, port, addr)

                new_first = f"{method} {path} {parts[2] if len(parts) > 2 else 'HTTP/1.1'}\r\n"
                lines = [new_first.encode()]
                for line in header.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"proxy-connection:"):
                        continue
                    lines.append(line + b"\r\n")
                lines.append(b"\r\n")
                payload = b"".join(lines) + rest
                remote.sendall(payload)
                self.emit("", bytes_up=len(payload), dest=dest)
                self._pipe(client, remote, dest)
        except Exception as e:
            self.emit(f"[HTTP] fail {dest or addr}: {e}")
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
        finally:
            self._close(client, remote)

    def _pipe(self, client, remote, dest):
        client.settimeout(0.0)
        remote.settimeout(0.0)
        while not self._stop.is_set():
            r, _, x = select.select([client, remote], [], [client, remote], 60)
            if x or not r:
                break
            if client in r:
                try:
                    data = client.recv(16384)
                except Exception:
                    break
                if not data:
                    break
                remote.sendall(data)
                self.emit("", bytes_up=len(data), dest=dest)
            if remote in r:
                try:
                    data = remote.recv(16384)
                except Exception:
                    break
                if not data:
                    break
                client.sendall(data)
                self.emit("", bytes_down=len(data), dest=dest)
        self.emit(f"[DONE] {dest}", dest=dest)

    @staticmethod
    def _close(client, remote):
        try:
            client.close()
        except Exception:
            pass
        try:
            if remote:
                remote.close()
        except Exception:
            pass
