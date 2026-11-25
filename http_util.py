"""HTTP CONNECT / Host:port parsing — IPv6-safe, no naive split(':')."""
from __future__ import annotations

from typing import Optional, Tuple


def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    """
    Parse host[:port] or [ipv6]:port.
    Raises ValueError on empty host or non-integer port.
    """
    value = (value or "").strip()
    if not value:
        raise ValueError("empty host:port")

    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError(f"unclosed IPv6 bracket: {value!r}")
        host = value[1:end]
        if not host:
            raise ValueError("empty IPv6 host")
        rest = value[end + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError(f"garbage after IPv6 host: {value!r}")
        return host, _parse_port(rest[1:])

    # hostname or IPv4 with optional :port — only split on last colon when
    # there is exactly one (IPv4/host). Multiple colons without brackets = IPv6 bare.
    if value.count(":") == 1:
        host, port_s = value.rsplit(":", 1)
        if not host:
            raise ValueError("empty host")
        return host, _parse_port(port_s)

    if ":" in value:
        # bare IPv6 without brackets and without port
        return value, default_port

    return value, default_port


def _parse_port(port_s: str) -> int:
    port_s = port_s.strip()
    if not port_s.isdigit():
        raise ValueError(f"invalid port: {port_s!r}")
    port = int(port_s)
    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port}")
    return port


def parse_connect_target(request_text: str) -> Tuple[str, int]:
    """
    Extract authority from an HTTP CONNECT request body (headers included).
    Expected first line: CONNECT host:port HTTP/1.x
    """
    if not request_text:
        raise ValueError("empty CONNECT request")

    first_line = request_text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    parts = first_line.split()
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {first_line!r}")

    method, target = parts[0].upper(), parts[1]
    if method != "CONNECT":
        raise ValueError(f"expected CONNECT, got {method!r}")

    return parse_host_port(target, 443)


def parse_connect_request(raw: bytes) -> Tuple[str, int, bytes]:
    """
    Parse CONNECT from raw bytes. Returns (host, port, leftover_after_headers).
    """
    if b"\r\n\r\n" in raw:
        header, _, rest = raw.partition(b"\r\n\r\n")
    else:
        header, rest = raw, b""
    text = header.decode("utf-8", errors="replace")
    host, port = parse_connect_target(text)
    return host, port, rest
