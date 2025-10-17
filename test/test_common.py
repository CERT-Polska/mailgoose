import binascii
import os
import re

from base import BaseTestCase

CONFIG_WITH_WARNINGS_REGEX = r"DMARC:\s*configuration warnings"
INCORRECT_CONFIG_REGEX = r"DMARC:\s*incorrect configuration"
CORRECT_CONFIG_REGEX = r"DMARC:\s*correct configuration"
WARNING_REGEX = "bi bi-exclamation-triangle"


class NonexistentDomainTestCase(BaseTestCase):
    def test_nonexistent_domain(self) -> None:
        result = self.check_domain(binascii.hexlify(os.urandom(16)) + ".com")
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)
        assert "Domain does not exist" in result
