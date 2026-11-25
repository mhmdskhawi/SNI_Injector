import hashlib
import ssl
import unittest
from unittest import mock

from tls_util import (
    TlsSettings,
    build_client_context,
    match_hostname,
    pin_matches,
    verify_peer,
)


class TestPin(unittest.TestCase):
    def test_full_match(self):
        h = hashlib.sha256(b"x").hexdigest()
        self.assertTrue(pin_matches(h, h))

    def test_prefix(self):
        h = hashlib.sha256(b"x").hexdigest()
        self.assertTrue(pin_matches(h, h[:16]))

    def test_mismatch(self):
        self.assertFalse(pin_matches("ab" * 32, "cd" * 32))

    def test_too_short_prefix(self):
        self.assertFalse(pin_matches("ab" * 32, "abcd"))


class TestMatchHostname(unittest.TestCase):
    def test_san(self):
        cert = {"subjectAltName": (("DNS", "vpn.example"),), "subject": ()}
        match_hostname(cert, "vpn.example")

    def test_wildcard(self):
        cert = {"subjectAltName": (("DNS", "*.example.com"),), "subject": ()}
        match_hostname(cert, "a.example.com")

    def test_fail(self):
        cert = {"subjectAltName": (("DNS", "vpn.example"),), "subject": ()}
        with self.assertRaises(ssl.CertificateError):
            match_hostname(cert, "other.example")


class TestContextOrder(unittest.TestCase):
    def test_none_mode(self):
        ctx = build_client_context(TlsSettings(sni="bug.host", verify="none"))
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)

    def test_pin_mode_skips_chain(self):
        ctx = build_client_context(
            TlsSettings(sni="bug.host", verify="required", cert_pin_sha256="a" * 64)
        )
        # pin is trust anchor — chain verify would fail on self-signed stunnel
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_required_without_anchor_raises(self):
        sock = mock.Mock()
        sock.getpeercert.return_value = None
        with self.assertRaises(ssl.SSLError):
            verify_peer(
                sock,
                TlsSettings(sni="x", verify="required"),
            )


if __name__ == "__main__":
    unittest.main()
