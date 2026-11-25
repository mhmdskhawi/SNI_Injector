import unittest

from http_util import parse_connect_request, parse_connect_target, parse_host_port


class TestParseHostPort(unittest.TestCase):
    def test_host_port(self):
        self.assertEqual(parse_host_port("example.com:8443", 443), ("example.com", 8443))

    def test_host_default(self):
        self.assertEqual(parse_host_port("example.com", 443), ("example.com", 443))

    def test_ipv4(self):
        self.assertEqual(parse_host_port("1.2.3.4:443", 80), ("1.2.3.4", 443))

    def test_ipv6_brackets(self):
        self.assertEqual(
            parse_host_port("[2001:db8::1]:8443", 443), ("2001:db8::1", 8443)
        )

    def test_ipv6_brackets_default(self):
        self.assertEqual(parse_host_port("[2001:db8::1]", 443), ("2001:db8::1", 443))

    def test_bare_ipv6(self):
        self.assertEqual(parse_host_port("2001:db8::1", 443), ("2001:db8::1", 443))

    def test_rejects_naive_split_trap(self):
        # old code used split(':')[-1] which breaks on IPv6 / Host headers
        with self.assertRaises(ValueError):
            parse_host_port("example.com:notaport", 443)

    def test_empty(self):
        with self.assertRaises(ValueError):
            parse_host_port("", 443)


class TestParseConnect(unittest.TestCase):
    def test_basic(self):
        req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.assertEqual(parse_connect_target(req), ("example.com", 443))

    def test_ipv6(self):
        req = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n"
        self.assertEqual(parse_connect_target(req), ("2001:db8::1", 443))

    def test_bytes(self):
        raw = b"CONNECT 10.0.0.1:22 HTTP/1.1\r\n\r\nSSH-leftover"
        host, port, rest = parse_connect_request(raw)
        self.assertEqual((host, port), ("10.0.0.1", 22))
        self.assertEqual(rest, b"SSH-leftover")

    def test_rejects_get(self):
        with self.assertRaises(ValueError):
            parse_connect_target("GET / HTTP/1.1\r\n\r\n")


if __name__ == "__main__":
    unittest.main()
