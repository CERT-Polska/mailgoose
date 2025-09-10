import binascii
import os
import re

from base import BaseTestCase
from config import TEST_DOMAIN

CONFIG_WITH_WARNINGS_REGEX = r"DMARC:\s*configuration warnings"
INCORRECT_CONFIG_REGEX = r"DMARC:\s*incorrect configuration"
CORRECT_CONFIG_REGEX = r"DMARC:\s*correct configuration"
WARNING_REGEX = "bi bi-exclamation-triangle"


class DMARCTestCase(BaseTestCase):
    def test_correct(self) -> None:
        result = self.check_domain("correct.dmarc." + TEST_DOMAIN)
        assert re.search(CORRECT_CONFIG_REGEX, result)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)

    def test_nonexistent_dmarc(self) -> None:
        result = self.check_domain(binascii.hexlify(os.urandom(20)).decode("ascii") + ".com")
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert (
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing."
        ) in result

    def test_starts_with_whitespace(self) -> None:
        result = self.check_domain("starts-with-whitespace.dmarc." + TEST_DOMAIN)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert (
            "Found a DMARC record that starts with whitespace. Please remove the whitespace, as some "
            "implementations may not process it correctly."
        ) in result

    def test_none_policy(self) -> None:
        result = self.check_domain("none-policy.dmarc." + TEST_DOMAIN)
        assert re.search(CONFIG_WITH_WARNINGS_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)
        assert ("DMARC policy is &#39;none&#39;, which means that besides reporting no action will be taken.") in result
        assert (
            "The policy describes what action the recipient server should take when noticing a message "
            "that doesn&#39;t pass the verification. &#39;quarantine&#39; policy "
            "suggests the recipient server to flag the message as spam and &#39;reject&#39; policy suggests the recipient "
            "server to reject the message. We recommend using the &#39;quarantine&#39; or &#39;reject&#39; policy."
        ) in result

    def test_unrelated_records(self) -> None:
        result = self.check_domain("contains-unrelated-records.dmarc." + TEST_DOMAIN)
        assert re.search(CONFIG_WITH_WARNINGS_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)
        assert (
            "Unrelated TXT record found in the &#39;_dmarc&#39; subdomain. We recommend removing it, as such unrelated "
            "records may cause problems with some DMARC implementations."
        ) in result

    def test_public_suffix(self) -> None:
        result = self.check_domain("gov.pl")
        assert (
            "Requested to scan a domain that is a public suffix, i.e. a domain such as .com where anybody could "
            "register their subdomain. Such domain don&#39;t have to have properly configured e-mail sender verification "
            "mechanisms. Please make sure you really wanted to check such domain and not its subdomain."
        ) in result

    def test_syntax_error(self) -> None:
        result = self.check_domain("syntax-error.dmarc." + TEST_DOMAIN)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert (
            "Error: Expected end_of_statement or tag_value at position 10 (marked with ➞) in: v=DMARC1; ➞=none"
        ) in result or (
            "Error: Expected tag_value or end_of_statement at position 10 (marked with ➞) in: v=DMARC1; ➞=none"
        ) in result

    def test_syntax_error_policy_location(self) -> None:
        result = self.check_domain("syntax-error-policy-location.dmarc." + TEST_DOMAIN)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert ("the p tag must immediately follow the v tag") in result

    def test_rua_no_mailto(self) -> None:
        result = self.check_domain("rua-no-mailto.dmarc." + TEST_DOMAIN)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert (
            "dmarc@mailgoose.cert.pl is not a valid DMARC report URI - please make sure that the URI begins "
            "with a schema such as mailto:"
        ) in result

    def test_rua_double_mailto(self) -> None:
        result = self.check_domain("rua-double-mailto.dmarc." + TEST_DOMAIN)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert "mailto:mailto:dmarc@mailgoose.cert.pl is not a valid DMARC report URI" in result
        assert "please make sure that the URI begins with a schema:" not in result

    def test_no_redundant_fo_message(self) -> None:
        result = self.check_domain("redundant-fo.dmarc." + TEST_DOMAIN)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)
        assert re.search(CORRECT_CONFIG_REGEX, result)
        assert " fo " not in result

    def test_no_rua_policy_none(self) -> None:
        result = self.check_domain("no-rua-none.dmarc." + TEST_DOMAIN)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert (
            "DMARC policy is &#39;none&#39; and &#39;rua&#39;/&#39;ruf&#39; is not set, which means that the DMARC setting is not effective."
            in result
        )

    def test_no_rua_policy_reject(self) -> None:
        result = self.check_domain("no-rua-reject.dmarc." + TEST_DOMAIN)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(WARNING_REGEX, result)
        assert "rua tag" not in result
        assert re.search(CORRECT_CONFIG_REGEX, result)
