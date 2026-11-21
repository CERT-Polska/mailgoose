import ipaddress
from unittest import TestCase
from unittest.mock import patch

from libmailgoose.ssl_check import is_private_ip


@patch.dict("os.environ", {}, clear=True)
class UtilsTestCase(TestCase):
    def test_non_global_addresses_blocked(self) -> None:
        for address in (
            "100.64.0.0",
            "100.64.0.1",
            "100.100.100.200",
            "100.127.255.255",
            "0.0.0.0",
            "169.254.169.254",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ):
            with self.subTest(address=address):
                self.assertTrue(is_private_ip(address))

    def test_global_addresses_allowed(self) -> None:
        for address in ("8.8.8.8", "100.63.255.255", "100.128.0.0", "2606:4700:4700::1111"):
            with self.subTest(address=address):
                self.assertFalse(is_private_ip(address))

    def test_bypass_requires_explicit_true(self) -> None:
        for value in ("", "0", "false", "no", "unexpected"):
            with self.subTest(value=value), patch.dict(
                "os.environ", {"MAILGOOSE_SKIP_PRIVATE_IP_ADDRESS_CHECK": value}
            ):
                self.assertTrue(is_private_ip("127.0.0.1"))
                self.assertTrue(is_private_ip("100.64.0.1"))

    def test_explicit_bypass(self) -> None:
        for value in ("true", " TRUE "):
            with self.subTest(value=value), patch.dict(
                "os.environ", {"MAILGOOSE_SKIP_PRIVATE_IP_ADDRESS_CHECK": value}
            ):
                self.assertFalse(is_private_ip("127.0.0.1"))

    def test_is_ip_private(self) -> None:

        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertFalse(is_private_ip("1.2.3.4"))

    def test_exempt_cidrs_blocks_public_ip_in_range(self) -> None:
        """exempt_cidrs should block (treat as private) public IPs that fall within the specified ranges."""
        exempt = [ipaddress.IPv4Network("203.0.113.0/24")]
        # Public IP in exempt range is now blocked
        self.assertTrue(is_private_ip("203.0.113.5", exempt_cidrs=exempt))
        # Public IP outside exempt range remains allowed
        self.assertFalse(is_private_ip("8.8.8.8", exempt_cidrs=exempt))

    def test_exempt_cidrs_private_ip_still_blocked(self) -> None:
        """Private IPs remain blocked regardless of exempt_cidrs."""
        exempt = [ipaddress.IPv4Network("203.0.113.0/24")]
        self.assertTrue(is_private_ip("10.0.0.1", exempt_cidrs=exempt))
        self.assertTrue(is_private_ip("192.168.1.1", exempt_cidrs=exempt))
        self.assertTrue(is_private_ip("127.0.0.1", exempt_cidrs=exempt))

    def test_exempt_cidrs_multiple_ranges(self) -> None:
        """Multiple CIDR ranges can be blocked via exempt_cidrs."""
        exempt = [
            ipaddress.IPv4Network("203.0.113.0/24"),
            ipaddress.IPv4Network("198.51.100.0/24"),
        ]
        self.assertTrue(is_private_ip("203.0.113.10", exempt_cidrs=exempt))
        self.assertTrue(is_private_ip("198.51.100.50", exempt_cidrs=exempt))
        # Public IP not in any exempt range remains allowed
        self.assertFalse(is_private_ip("8.8.8.8", exempt_cidrs=exempt))

    def test_exempt_cidrs_single_host(self) -> None:
        """A /32 CIDR blocks only that single host."""
        exempt = [ipaddress.IPv4Network("8.8.8.8/32")]
        self.assertTrue(is_private_ip("8.8.8.8", exempt_cidrs=exempt))
        self.assertFalse(is_private_ip("8.8.8.9", exempt_cidrs=exempt))

    def test_exempt_cidrs_empty_list(self) -> None:
        """Empty exempt list behaves the same as no exemptions."""
        self.assertTrue(is_private_ip("10.0.0.1", exempt_cidrs=[]))
        self.assertFalse(is_private_ip("1.2.3.4", exempt_cidrs=[]))

    def test_exempt_cidrs_invalid_ip(self) -> None:
        """Invalid IP strings still return True (blocked) even with exemptions."""
        exempt = [ipaddress.IPv4Network("203.0.113.0/24")]
        self.assertTrue(is_private_ip("not-an-ip", exempt_cidrs=exempt))

    def test_exempt_cidrs_wide_internal_range(self) -> None:
        """A wide CIDR can block an entire internal network range to prevent SSRF."""
        # Simulate blocking an organization's internal /16 network
        exempt = [ipaddress.IPv4Network("100.64.0.0/10")]  # CGN range
        self.assertTrue(is_private_ip("100.64.0.1", exempt_cidrs=exempt))
        self.assertTrue(is_private_ip("100.100.100.100", exempt_cidrs=exempt))
        self.assertFalse(is_private_ip("101.0.0.1", exempt_cidrs=exempt))
