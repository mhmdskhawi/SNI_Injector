"""
TLS helpers for SNI-injector paths.

Honest model:
  - ClientHello SNI can differ from the peer you authenticate (classic "bug host").
  - That is NOT ECH, NOT encrypted ClientHello, and NOT DPI obfuscation.
  - Tunnel security = verifying the *actual* peer (cert pin and/or CA+hostname),
    not trusting the advertised SNI string.

verify modes ([ssl] verify=):
  required — must pass pin and/or CA+verify_hostname (default)
  optional — attempt checks; log failure, still continue
  none     — CERT_NONE, lab only (explicitly insecure)
"""
from __future__ import annotations

import hashlib
import os
import ssl
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None


@dataclass(frozen=True)
class TlsSettings:
    """TLS policy. Unset pin/hostname stay None (not confused with empty success)."""

    sni: str
    verify: str = "required"  # required | optional | none
    verify_hostname: Optional[str] = None
    cert_pin_sha256: Optional[str] = None
    ca_file: Optional[str] = None
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    @classmethod
    def from_config(cls, cfg, sni: Optional[str] = None) -> "TlsSettings":
        sni_val = sni if sni is not None else cfg.get("sni", "server_name", fallback="")
        verify = cfg.get("ssl", "verify", fallback="required").strip().lower()
        if verify not in ("required", "optional", "none"):
            verify = "required"
        pin = cfg.get("ssl", "cert_pin_sha256", fallback="").strip() or None
        ca = cfg.get("ssl", "ca_file", fallback="").strip() or None
        vhost = cfg.get("ssl", "verify_hostname", fallback="").strip() or None
        return cls(
            sni=str(sni_val),
            verify=verify,
            verify_hostname=vhost,
            cert_pin_sha256=pin,
            ca_file=ca,
        )


def _default_ca() -> str:
    if certifi is not None:
        return certifi.where()
    paths = ssl.get_default_verify_paths()
    return paths.cafile or ""


def build_client_context(settings: TlsSettings) -> ssl.SSLContext:
    """
    Configure context *before* wrap_socket.
    check_hostname stays False: SNI is spoofable and ≠ peer identity.
    Peer trust is pin and/or manual hostname+CA after handshake.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = settings.minimum_version
    ctx.check_hostname = False

    if settings.verify == "none":
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # Pin is the trust anchor for self-signed stunnel PEMs — chain check would fail.
    if settings.cert_pin_sha256:
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # CA + verify_hostname path
    ctx.verify_mode = ssl.CERT_REQUIRED
    ca = settings.ca_file or _default_ca()
    if not ca or not os.path.isfile(ca):
        raise ssl.SSLError(
            f"CA bundle missing ({ca!r}). Set [ssl] ca_file, or use "
            "cert_pin_sha256 for self-signed peers, or verify=none for lab."
        )
    ctx.load_verify_locations(cafile=ca)
    return ctx


def peer_cert_sha256_hex(ssl_sock: ssl.SSLSocket) -> str:
    der = ssl_sock.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("peer presented no certificate")
    return hashlib.sha256(der).hexdigest()


def _normalize_pin(value: str) -> str:
    return value.lower().replace(":", "").replace(" ", "")


def pin_matches(actual_hex: str, expected: str) -> bool:
    exp = _normalize_pin(expected)
    act = actual_hex.lower()
    if len(exp) < 16:
        return False
    return act.startswith(exp) if len(exp) < 64 else act == exp


def _dns_names_from_cert(cert: Dict[str, Any]) -> Tuple[str, ...]:
    names = []
    for typ, val in cert.get("subjectAltName", ()):
        if typ == "DNS" and val:
            names.append(val)
    if not names:
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                if key == "commonName" and val:
                    names.append(val)
    return tuple(names)


def match_hostname(cert: Optional[Dict[str, Any]], hostname: str) -> None:
    """Minimal RFC 6125-ish DNS match (stdlib match_hostname removed in 3.12+)."""
    if not cert:
        raise ssl.CertificateError("empty peer cert (need CA path for decoded cert)")
    host = hostname.lower().rstrip(".")
    for name in _dns_names_from_cert(cert):
        pattern = name.lower().rstrip(".")
        if pattern.startswith("*."):
            # single-label wildcard
            rest = pattern[2:]
            if "." in host and host.split(".", 1)[1] == rest and not host.startswith("*"):
                return
        elif pattern == host:
            return
    raise ssl.CertificateError(
        f"hostname {hostname!r} not in peer cert names {_dns_names_from_cert(cert)}"
    )


def verify_peer(ssl_sock: ssl.SSLSocket, settings: TlsSettings) -> str:
    """Post-handshake checks. Raises ssl.SSLError when verify=required fails."""
    if settings.verify == "none":
        return "verify=none (INSECURE lab mode)"

    pin = settings.cert_pin_sha256
    vhost = settings.verify_hostname

    if not pin and not vhost:
        msg = (
            "verify=required needs cert_pin_sha256 and/or verify_hostname "
            "(SNI spoof means built-in hostname check cannot use the bug-host name). "
            "Lab only: [ssl] verify = none"
        )
        if settings.verify == "required":
            raise ssl.SSLError(msg)
        return f"verify=optional skipped: {msg}"

    parts = []

    if pin:
        actual = peer_cert_sha256_hex(ssl_sock)
        parts.append(f"pin={actual[:16]}…")
        if not pin_matches(actual, pin):
            err = f"cert pin mismatch: got {actual}, expected {_normalize_pin(pin)}"
            if settings.verify == "required":
                raise ssl.SSLError(err)
            return f"verify=optional FAIL: {err}"
        parts.append("pin_ok")

    if vhost:
        # Decoded cert available only when verify_mode verified the chain
        cert = ssl_sock.getpeercert()
        try:
            if not cert and pin:
                # pin-only path: binary cert only — hostname check not available
                parts.append("hostname_skipped(pin_trust_no_decoded_cert)")
            else:
                match_hostname(cert, vhost)
                parts.append(f"hostname_ok={vhost}")
        except (ssl.CertificateError, ValueError, TypeError) as e:
            err = f"hostname check failed for {vhost!r}: {e}"
            if settings.verify == "required" and not pin:
                raise ssl.SSLError(err) from e
            if settings.verify == "required" and pin:
                parts.append(f"hostname_warn={e}")
            else:
                return f"verify=optional FAIL: {err}"

    return "verify=ok (" + ", ".join(parts) + ")"


def wrap_socket_client(
    raw_sock,
    settings: TlsSettings,
    *,
    context: Optional[ssl.SSLContext] = None,
) -> ssl.SSLSocket:
    """Correct order: configure context → wrap_socket(SNI) → verify_peer."""
    if not settings.sni:
        raise ValueError("SNI (server_name) is empty")
    ctx = context or build_client_context(settings)
    ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=str(settings.sni))
    status = verify_peer(ssl_sock, settings)
    ssl_sock._sni_injector_verify_status = status  # type: ignore[attr-defined]
    return ssl_sock
