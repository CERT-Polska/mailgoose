from base import BaseTestCase


class SSLTestCase(BaseTestCase):
    def test_dmarc_starts_with_whitespace(self) -> None:
        result = self.check_domain_api_v1("mailserver.local")
        del result["result"]["timestamp"]
        self.maxDiff = None
        self.assertEqual(result, {})
