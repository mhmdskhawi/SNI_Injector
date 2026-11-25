#!/usr/bin/env python3
"""Print SHA-256 pin of a peer leaf cert (for [ssl] cert_pin_sha256)."""
from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import sys


def pin_from_pem(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read()
    # stunnel.pem often has key+cert; extract first CERTIFICATE block
    if b"-----BEGIN CERTIFICATE-----" in data:
        start = data.index(b"-----BEGIN CERTIFICATE-----")
        end = data.index(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
        pem = data[start:end]
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    else:
        der = data
    return hashlib.sha256(der).hexdigest()


def pin_from_host(host: str, port: int, sni: str) -> str:
    raw = socket.create_connection((host, port), timeout=20)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(raw, server_hostname=sni)
    der = sock.getpeercert(binary_form=True)
    sock.close()
    if not der:
        raise SystemExit("no peer certificate")
    return hashlib.sha256(der).hexdigest()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--pem", help="path to PEM/DER leaf (e.g. stunnel.pem)")
    g.add_argument("--host", help="connect and pin live peer")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--sni", default="", help="ClientHello SNI (defaults to --host)")
    args = p.parse_args()
    if args.pem:
        pin = pin_from_pem(args.pem)
    else:
        pin = pin_from_host(args.host, args.port, args.sni or args.host)
    print(pin)
    print("Put in settings.ini:", file=sys.stderr)
    print(f"cert_pin_sha256 = {pin}", file=sys.stderr)
    print("verify = required", file=sys.stderr)


if __name__ == "__main__":
    main()
