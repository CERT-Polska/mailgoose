from base import BaseTestCase


class SSLTestCase(BaseTestCase):
    def base_selfsigned_test_case(self) -> None:
        result = self.check_domain_api_v1("mailserver.local")
        del result["result"]["timestamp"]
        self.assertEqual(
            result,
            {
                "result": {
                    "domain": {
                        "base_domain": "mailserver.local",
                        "dmarc": {"errors": [], "record_not_found": False, "tags": {}, "valid": True, "warnings": []},
                        "domain": "mailserver.local",
                        "domain_does_not_exist": True,
                        "spf": {
                            "errors": [],
                            "record_could_not_be_fully_validated": False,
                            "record_not_found": False,
                            "valid": True,
                            "warnings": [],
                        },
                        "spf_not_required_because_of_correct_dmarc": False,
                        "ssl": {
                            "results": [
                                {
                                    "error": "Connection unexpectedly closed: timed out",
                                    "mx": "mailserver.local",
                                    "port": 25,
                                },
                                {
                                    "error": "Certificate error: unable to get local issuer certificate",
                                    "mx": "mailserver.local",
                                    "port": 465,
                                },
                                {
                                    "error": "Certificate error: unable to get local issuer certificate",
                                    "mx": "mailserver.local",
                                    "port": 587,
                                },
                            ],
                            "valid": False,
                        },
                        "warnings": [],
                    }
                }
            },
        )
