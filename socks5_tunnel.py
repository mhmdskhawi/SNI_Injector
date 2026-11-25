"""
Local HTTP CONNECT → TLS(SNI) → remote stunnel host.

Fixes vs legacy:
  - SSLContext configured *before* wrap_socket
  - CONNECT / host:port via http_util (IPv6-safe)
  - Certificate policy via [ssl] (pin / hostname / none)
"""
from __future__ import annotations

import configparser
import hashlib
import os
import select
import socket
import subprocess
import threading
import time
import warnings

from http_util import parse_connect_request, parse_host_port
from tls_util import TlsSettings, wrap_socket_client

warnings.filterwarnings("ignore", category=DeprecationWarning)


class Tunnel:
    def __init__(self, on_event=None):
        self.config = configparser.ConfigParser()
        with open("settings.ini", encoding="utf-8") as f:
            self.config.read_file(f)
        self.local_ip = self.config["settings"]["local_ip"]
        self.listen_port = int(self.config["settings"]["listen_port"])
        self.on_event = on_event
        self._tls = TlsSettings.from_config(self.config)

    def emit(self, msg):
        print(msg)
        self.logs(msg)
        if self.on_event:
            try:
                self.on_event(msg)
            except Exception:
                pass

    def tunneling(self, client, stunnel_socket):
        connected = True
        self.emit("[*] Connection Established.")
        while connected:
            pending = []
            try:
                if hasattr(stunnel_socket, "pending") and stunnel_socket.pending() > 0:
                    pending.append(stunnel_socket)
            except Exception:
                pass

            if pending:
                r, x = pending, []
            else:
                r, w, x = select.select(
                    [client, stunnel_socket], [], [client, stunnel_socket], 3
                )
            if x:
                break
            if not r and not pending:
                continue
            for i in r:
                try:
                    data = i.recv(16384)
                    if not data:
                        connected = False
                        break
                    if i is stunnel_socket:
                        client.sendall(data)
                    else:
                        stunnel_socket.sendall(data)
                except KeyboardInterrupt:
                    print("Exited")
                    connected = False
                except Exception as e:
                    self.emit(f"[!!!] {e}")
                    connected = False
        try:
            client.close()
        except Exception:
            pass
        try:
            stunnel_socket.close()
        except Exception:
            pass
        self.emit("[*] Client disconnected")

    def destination(self, client, address):
        self.emit(f"[*] New Client connected! {address}")
        stunnel_socket = None
        try:
            raw = b""
            client.settimeout(30)
            while b"\r\n\r\n" not in raw:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                raw += chunk
                if len(raw) > 65536:
                    raise ValueError("CONNECT request too large")

            # Authority from CONNECT; TCP peer is always [ssh] host (stunnel front).
            _req_host, port, _leftover = parse_connect_request(raw)
            host = self.config["ssh"]["host"]
            # Validate port even though we may ignore _req_host for stunnel fronting
            if not (1 <= port <= 65535):
                raise ValueError(f"invalid CONNECT port: {port}")

            raw_sock = socket.create_connection((host, int(port)), timeout=20)
            self.emit(f"[TCP] connected to {host}:{port}")

            tls = TlsSettings.from_config(self.config)
            stunnel_socket = wrap_socket_client(raw_sock, tls)
            status = getattr(stunnel_socket, "_sni_injector_verify_status", "")
            self.emit(f"[TCP] Handshaked SNI={tls.sni} | {status}")
            self.emit(f"[TCP] Protocol: {stunnel_socket.version()}")
            try:
                self.emit(f"[*] Ciphersuite: {stunnel_socket.cipher()[0]}")
            except Exception:
                pass

            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.tunneling(client, stunnel_socket)
        except Exception as e:
            self.emit(f"[Error] {e}")
            try:
                client.close()
            except Exception:
                pass
            if stunnel_socket is not None:
                try:
                    stunnel_socket.close()
                except Exception:
                    pass

    def create_connection(self):
        listen_socket = None
        for res in socket.getaddrinfo(
            self.local_ip,
            self.listen_port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            0,
            socket.AI_PASSIVE,
        ):
            af, socktype, proto, _canonname, sa = res
            try:
                listen_socket = socket.socket(af, socktype, proto)
            except OSError as e:
                self.emit(f"[Error] {e}")
                raise SystemExit(1) from e
            try:
                listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listen_socket.bind((self.local_ip, self.listen_port))
                listen_socket.listen(64)
                break
            except OSError as e:
                self.emit(f"[Error] {e}")
                listen_socket.close()
                listen_socket = None
                continue

        if listen_socket is None:
            self.emit("[Error] bind failed")
            raise SystemExit(1)

        self.emit(f"[*] Waiting on {self.local_ip}:{self.listen_port}")
        self.emit(
            f"[*] TLS policy: verify={self._tls.verify} "
            f"(SNI spoof ≠ ECH / DPI obfuscation)"
        )
        while True:
            try:
                client, address = listen_socket.accept()
                threading.Thread(
                    target=self.destination, args=(client, address), daemon=True
                ).start()
            except KeyboardInterrupt:
                print("\n[*] Exiting...")
                if os.path.exists("logs"):
                    os.remove("logs")
                break

    def logs(self, log):
        logtime = str(time.ctime()).split()[3]
        log_hash = hashlib.sha256(log.encode()).hexdigest()
        with open("logs", "a", encoding="utf-8") as logfile:
            logfile.write(f"[{logtime}] : {log_hash}\n")
        if os.name == "nt":
            subprocess.run(
                ["attrib", "+h", "logs"], shell=True, capture_output=True
            )


if __name__ == "__main__":
    # sanity: ensure parse helpers importable when run as script
    _ = parse_host_port
    Tunnel().create_connection()
