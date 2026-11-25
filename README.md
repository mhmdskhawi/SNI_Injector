# SNI Injector (Python)

TCP-over-TLS helper with a **spoofed ClientHello SNI**, plus local HTTP/SOCKS fronts. Inspired by tools like HTTP Injector — **not** a drop-in security replacement for a real VPN or ECH-aware stack.

## What this is / is not

| Claim | Reality |
| --- | --- |
| Changes SNI in ClientHello | Yes — DPI that only keys off cleartext SNI may treat the session as the bug-host |
| Encrypted Client Hello (ECH) | **No** — SNI remains visible to on-path observers on TLS without ECH |
| Obfuscation vs modern DPI | **No** — no padding, mimicry, or multiplexed cover traffic |
| Certificate security | Configurable: pin / CA+hostname (**required** by default in code). Lab peers may set `verify=none` |

Tunnel confidentiality still depends on the inner protocol (SSH / HTTPS via your VPS). Spoofing SNI does **not** authenticate the peer by itself.

## TLS policy (`[ssl]` in `settings.ini`)

```ini
[ssl]
verify = required          ; required | optional | none
cert_pin_sha256 = <hex>    ; SHA-256 of peer leaf DER (best for self-signed stunnel)
verify_hostname = vpn.example
ca_file =                  ; empty → certifi
```

Pin your stunnel leaf:

```bash
python tools/show_cert_pin.py --pem /etc/stunnel/stunnel.pem
# or live:
python tools/show_cert_pin.py --host YOUR_VPS --port 443 --sni BUG_HOST
```

Then set `verify = required` and paste `cert_pin_sha256`.

OpenTunnel / unknown shared hosts: leave `verify = none` only for lab use (MITM-vulnerable).

## Modes

1. **SSH / OpenTunnel** (`gui.py` or `ssh_socks.py`) — TLS+SNI → HTTP 101 or stunnel → SSH → dynamic SOCKS5 + HTTP proxy on `127.0.0.1:1080` / `:8080`.
2. **Direct SNI** — TLS+SNI → your VPS `stunnel` → `tinyproxy` (see `server/`). Idle TLS pre-CONNECT pool in `conn_pool.py` (not HTTP/2 multiplexing).
3. **Legacy CONNECT front** — `socks5_tunnel.py` listens for HTTP CONNECT and wraps TLS with correct context order + proper CONNECT parsing.

## Quick start

```bash
pip install -r requirements.txt
# edit settings.ini
python gui.py
# or
python socks5_tunnel.py
```

Tests:

```bash
python -m unittest discover -s tests -v
```

## Server (Direct mode)

See `server/install.sh`, `server/stunnel.conf`, `server/tinyproxy.conf`. Open `443` to stunnel → local tinyproxy; clients send spoofed SNI and CONNECT to destinations through the proxy.

## Layout

| File | Role |
| --- | --- |
| `tls_util.py` | SSLContext **before** wrap; pin / hostname verify |
| `http_util.py` | IPv6-safe CONNECT / host:port parsing |
| `conn_pool.py` | Idle pre-CONNECT TLS pool |
| `direct_sni.py` / `ssh_socks.py` / `socks5_tunnel.py` | Frontends |
| `tools/show_cert_pin.py` | Generate pin for `[ssl]` |

## License

See `LICENSE`.
