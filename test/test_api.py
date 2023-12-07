from base import BaseTestCase
from config import TEST_DOMAIN


class APITestCase(BaseTestCase):
    def test_dmarc_starts_with_whitespace(self) -> None:
        result = self.check_domain_api_v1("starts-with-whitespace.dmarc." + TEST_DOMAIN)
        del result["result"]["timestamp"]
        self.assertEqual(
            result,
            {
                "result": {
                    "domain": {
                        "spf": {
                            "valid": False,
                            "errors": [
                                "Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
                                "to decrease the possibility of successful e-mail message spoofing.",
                            ],
                            "warnings": [],
                            "record_not_found": True,
                            "record_could_not_be_fully_validated": False,
                        },
                        "dmarc": {
                            "record_candidates": [" v=DMARC1; p=none"],
                            "valid": False,
                            "tags": {},
                            "errors": [
                                "Found a DMARC record that starts with whitespace. Please remove the whitespace, as some "
                                "implementations may not process it correctly.",
                            ],
                            "warnings": [],
                            "record_not_found": False,
                        },
                        "spf_not_required_because_of_correct_dmarc": False,
                        "domain": "starts-with-whitespace.dmarc.test.mailgoose.cert.pl",
                        "base_domain": "cert.pl",
                        "warnings": [],
                    },
                },
            },
        )
