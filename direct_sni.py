"""
Direct SNI mode (بدون SSH):
  Browser → local HTTP/SOCKS → TLS+SNI → VPS stunnel → tinyproxy → Internet

Exit IP = IP السيرفر.

Limits (honest):
  - Spoofed ClientHello SNI only — not ECH, not modern DPI obfuscation.
  - Peer trust via [ssl] cert_pin_sha256 / verify_hostname (default required).
"""
from __future__ import annotations

import configparser
import select
import socket
import struct
import threading

from conn_pool import ConnectionPool
from http_util import parse_host_port
from tls_util import TlsSettings, wrap_socket_client

HTTP_PORT = 8080
SOCKS_PORT = 1080


class DirectSNIProxy:
    def __init__(
        self,
        host,
        port,
        sni,
        listen="127.0.0.1",
        http_port=HTTP_PORT,
        socks_port=SOCKS_PORT,
        on_event=None,
        tls_settings: TlsSettings | None = None,
        pool_idle: int = 4,
    ):
        self.host = host
        self.port = int(port)
        self.sni = sni
        self.listen = listen
        self.http_port = int(http_port)
        self.socks_port = int(socks_port)
        self.on_event = on_event
        self._stop = threading.Event()
        self._http_server = None
        self._socks_server = None
        self.ready = False

        if tls_settings is not None:
            self._tls = tls_settings
        else:
            cfg = configparser.ConfigParser()
            cfg.read("settings.ini")
            self._tls = TlsSettings.from_config(cfg, sni=sni)

        self._pool = ConnectionPool(
            self._open_ssl,
            max_idle=pool_idle,
            max_age_sec=45.0,
            close_fn=lambda s: s.close(),
        )

    def emit(self, msg, bytes_up=0, bytes_down=0, dest=""):
        if self.on_event:
            try:
                self.on_event(msg, bytes_up, bytes_down, dest)
            except Exception:
                pass

    def start(self):
        self.emit(
            f"[DIRECT] TLS+SNI → {self.host}:{self.port} (SNI={self.sni}) "
            f"verify={self._tls.verify}"
        )
        self.emit(
            "[DIRECT] ملاحظة: حقن SNI ≠ ECH ولا يحمي metadata ضد DPI حديث"
        )
        test = self._open_ssl()
        status = getattr(test, "_sni_injector_verify_status", "")
        self._pool.release(test, reusable=True)
        self.emit(f"[DIRECT] TLS handshake OK | {status}")
        self._warm_pool(extra=1)

        self._http_server = self._listen(self.http_port)
        self._socks_server = self._listen(self.socks_port)
        self.ready = True
        self.emit(f"[SOCKS5] Listening on {self.listen}:{self.socks_port}")
        self.emit(f"[HTTP] Listening on {self.listen}:{self.http_port}  ← ويندوز/كروم")

        threading.Thread(
            target=self._accept_loop, args=(self._socks_server, "socks"), daemon=True
        ).start()
        self._accept_loop(self._http_server, "http")

    def stop(self):
        self._stop.set()
        self.ready = False
        self._pool.close_all()
        for s in (self._http_server, self._socks_server):
            try:
                if s:
                    s.close()
            except Exception:
                pass

    def _listen(self, port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.listen, port))
        except OSError as e:
            raise ConnectionError(f"المنفذ {port} مشغول.\n{e}") from e
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

    def _open_ssl(self):
        raw = socket.create_connection((self.host, self.port), timeout=20)
        return wrap_socket_client(raw, self._tls)

    def _warm_pool(self, extra: int = 1) -> None:
        """Pre-open TLS sessions (pre-CONNECT) into the idle pool."""

        def _one():
            try:
                sock = self._open_ssl()
                self._pool.release(sock, reusable=True)
            except Exception as e:
                self.emit(f"[POOL] warm failed: {e}")

        for _ in range(max(0, extra)):
            threading.Thread(target=_one, daemon=True).start()

    def _remote_connect(self, dest_host, dest_port):
        """TLS (+idle pool) ثم CONNECT عبر tinyproxy. بعد CONNECT القناة مش reusable."""
        remote = self._pool.acquire()
        self._warm_pool(extra=1)
        try:
            req = (
                f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
                f"Host: {dest_host}:{dest_port}\r\n"
                f"Proxy-Connection: Keep-Alive\r\n"
                f"\r\n"
            )
            remote.sendall(req.encode())
            buf = b""
            remote.settimeout(20)
            while b"\r\n\r\n" not in buf:
                chunk = remote.recv(1)
                if not chunk:
                    raise ConnectionError("Remote proxy closed during CONNECT")
                buf += chunk
                if len(buf) > 8192:
                    raise ConnectionError("CONNECT response too large")
            status = buf.split(b"\r\n", 1)[0]
            if b"200" not in status:
                raise ConnectionError(
                    f"Remote CONNECT failed: {status.decode(errors='ignore')}"
                )
            remote.settimeout(None)
            return remote
        except Exception:
            self._pool.release(remote, reusable=False)
            raise

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
                remote = self._remote_connect(host, port)
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
                remote = self._remote_connect(host, port)

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

            remote = self._remote_connect(host, port)
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

    def _pipe(self, client, remote, dest):
        client.settimeout(0.0)
        remote.settimeout(0.0)
        while not self._stop.is_set():
            pending = []
            try:
                if hasattr(remote, "pending") and remote.pending() > 0:
                    pending.append(remote)
            except Exception:
                pass
            if pending:
                r, x = pending, []
            else:
                r, _, x = select.select([client, remote], [], [client, remote], 60)
            if x or (not r and not pending):
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
        st = self._pool.stats
        self.emit(
            f"[POOL] created={st['created']} reused={st['reused']} idle={st['idle']}"
        )

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
