import ipaddress
import unittest
from unittest.mock import MagicMock, patch

from libmailgoose.ssl_check import validate_ssl


class ValidateSSLExemptCidrsTestCase(unittest.TestCase):
    """Tests for validate_ssl with exempt_cidrs to verify SSRF protection."""

    @patch("libmailgoose.ssl_check.dns.resolver.Resolver")
    @patch("libmailgoose.ssl_check.retrieve_MX_records")
    @patch("libmailgoose.ssl_check.test_ssl_tls")
    @patch("libmailgoose.ssl_check.is_private_ip")
    def test_public_ip_not_blocked_without_exempt_cidrs(
        self,
        mock_is_private_ip: MagicMock,
        mock_test_ssl_tls: MagicMock,
        mock_retrieve_mx: MagicMock,
        mock_resolver_class: MagicMock,
    ) -> None:
        """Public IP MX records are scanned normally when no exempt_cidrs are set."""
        mock_retrieve_mx.return_value = [(10, "mx.example.com")]

        mock_is_private_ip.return_value = False  # Public IP
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "10.0.0.1"
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_answer]
        mock_resolver_class.return_value = mock_resolver

        mock_test_ssl_tls.return_value = {"port": 25, "error": None, "warning": None}

        result = validate_ssl(
            host="example.com",
            nameservers=None,
            timeout=5.0,
            parked=False,
            fallback_to_hostname=False,
            exempt_cidrs=[],
        )

        assert result is not None
        self.assertTrue(result.valid)
        self.assertTrue(mock_test_ssl_tls.called)

    @patch("libmailgoose.ssl_check.dns.resolver.Resolver")
    @patch("libmailgoose.ssl_check.retrieve_MX_records")
    @patch("libmailgoose.ssl_check.test_ssl_tls")
    def test_public_ip_blocked_by_exempt_cidrs(
        self, mock_test_ssl_tls: MagicMock, mock_retrieve_mx: MagicMock, mock_resolver_class: MagicMock
    ) -> None:
        """A public IP that falls within exempt_cidrs should be blocked (Connection refused)."""
        mock_retrieve_mx.return_value = [(10, "mx.example.com")]

        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "1.1.1.1"
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_answer]
        mock_resolver_class.return_value = mock_resolver

        exempt = [ipaddress.IPv4Network("1.1.1.0/24")]

        result = validate_ssl(
            host="example.com",
            nameservers=None,
            timeout=5.0,
            parked=False,
            fallback_to_hostname=False,
            exempt_cidrs=exempt,
        )

        assert result is not None
        # Should not have called test_ssl_tls because the IP is blocked at the validate_ssl level
        mock_test_ssl_tls.assert_not_called()
        self.assertFalse(result.valid)
        self.assertEqual(len(result.results), 1)
        self.assertEqual(result.results[0].error, "Connection refused")
        self.assertEqual(result.results[0].mx, "mx.example.com")

    @patch("libmailgoose.ssl_check.dns.resolver.Resolver")
    @patch("libmailgoose.ssl_check.retrieve_MX_records")
    @patch("libmailgoose.ssl_check.test_ssl_tls")
    def test_private_ip_blocked_without_exempt_cidrs(
        self, mock_test_ssl_tls: MagicMock, mock_retrieve_mx: MagicMock, mock_resolver_class: MagicMock
    ) -> None:
        """Private IPs are always blocked even without exempt_cidrs (baseline SSRF protection)."""
        mock_retrieve_mx.return_value = [(10, "mx.internal.com")]

        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "10.0.0.1"
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_answer]
        mock_resolver_class.return_value = mock_resolver

        result = validate_ssl(
            host="internal.com",
            nameservers=None,
            timeout=5.0,
            parked=False,
            fallback_to_hostname=False,
            exempt_cidrs=[],
        )

        assert result is not None
        mock_test_ssl_tls.assert_not_called()
        self.assertFalse(result.valid)
        self.assertEqual(result.results[0].error, "Connection refused")

    @patch("libmailgoose.ssl_check.dns.resolver.Resolver")
    @patch("libmailgoose.ssl_check.retrieve_MX_records")
    @patch("libmailgoose.ssl_check.test_ssl_tls")
    @patch("libmailgoose.ssl_check.is_private_ip")
    def test_exempt_cidrs_blocks_only_matching_range(
        self,
        mock_is_private_ip: MagicMock,
        mock_test_ssl_tls: MagicMock,
        mock_retrieve_mx: MagicMock,
        mock_resolver_class: MagicMock,
    ) -> None:
        """exempt_cidrs should only block IPs within the specified range, not others."""
        mock_retrieve_mx.return_value = [
            (10, "mx1.example.com"),
            (20, "mx2.example.com"),
        ]

        mock_is_private_ip.side_effect = [False, True]  # mx1 is public, mx2 is private
        mock_answer_1 = MagicMock()
        mock_answer_1.to_text.return_value = "10.0.0.1"  # In exempt range
        mock_answer_2 = MagicMock()
        mock_answer_2.to_text.return_value = "10.0.0.2"  # Not in exempt range

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = [[mock_answer_1], [mock_answer_2]]
        mock_resolver_class.return_value = mock_resolver

        mock_test_ssl_tls.return_value = {"port": 25, "error": None, "warning": None}

        result = validate_ssl(
            host="example.com",
            nameservers=None,
            timeout=5.0,
            parked=False,
            fallback_to_hostname=False,
            exempt_cidrs=[ipaddress.IPv4Network("10.0.0.2/32")],
        )

        assert result is not None
        blocked_results = [r for r in result.results if r.error == "Connection refused"]
        self.assertEqual(len(blocked_results), 1)
        self.assertEqual(blocked_results[0].mx, "mx2.example.com")

        # test_ssl_tls should have been called for mx1 only
        for call in mock_test_ssl_tls.call_args_list:
            self.assertEqual(call[0][1], "10.0.0.1")  # ip argument

    @patch("libmailgoose.ssl_check.dns.resolver.Resolver")
    @patch("libmailgoose.ssl_check.retrieve_MX_records")
    @patch("libmailgoose.ssl_check.test_ssl_tls")
    def test_exempt_cidrs_wide_range_blocks_all_internal(
        self, mock_test_ssl_tls: MagicMock, mock_retrieve_mx: MagicMock, mock_resolver_class: MagicMock
    ) -> None:
        """A wide exempt CIDR range blocks all IPs in that range."""
        mock_retrieve_mx.return_value = [
            (10, "mx1.corp.com"),
            (20, "mx2.corp.com"),
        ]

        mock_answer_1 = MagicMock()
        mock_answer_1.to_text.return_value = "100.64.1.1"
        mock_answer_2 = MagicMock()
        mock_answer_2.to_text.return_value = "100.100.50.50"

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = [[mock_answer_1], [mock_answer_2]]
        mock_resolver_class.return_value = mock_resolver

        exempt = [ipaddress.IPv4Network("100.64.0.0/10")]

        result = validate_ssl(
            host="corp.com",
            nameservers=None,
            timeout=5.0,
            parked=False,
            fallback_to_hostname=False,
            exempt_cidrs=exempt,
        )

        assert result is not None
        mock_test_ssl_tls.assert_not_called()
        self.assertFalse(result.valid)
        self.assertEqual(len(result.results), 2)
        self.assertTrue(all(r.error == "Connection refused" for r in result.results))
