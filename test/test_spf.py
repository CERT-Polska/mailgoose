import re

from base import BaseTestCase
from config import TEST_DOMAIN

RECORD_COULD_NOT_BE_FULLY_VERIFIED_REGEX = r"SPF:\s*record couldn't be fully verified"
INCORRECT_CONFIG_REGEX = r"SPF:\s*incorrect configuration"
CORRECT_CONFIG_REGEX = r"SPF:\s*correct configuration"


class SPFTestCase(BaseTestCase):
    def test_correct(self) -> None:
        result = self.check_domain("correct.spf." + TEST_DOMAIN)
        assert re.search(CORRECT_CONFIG_REGEX, result)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)

    def test_service_domains(self) -> None:
        """Check whether domain names containing underscore are allowed."""
        result = self.check_domain("_spf.cert.pl")
        assert re.search(CORRECT_CONFIG_REGEX, result)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)

    def test_macros(self) -> None:
        result = self.check_domain("macros.spf." + TEST_DOMAIN)
        assert re.search(RECORD_COULD_NOT_BE_FULLY_VERIFIED_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert not re.search(INCORRECT_CONFIG_REGEX, result)
        assert "SPF records containing macros aren&#39;t supported by the system yet." in result

    def test_syntax_error(self) -> None:
        result = self.check_domain("syntax-error.spf." + TEST_DOMAIN)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert (
            "<tt>syntax-error.spf.test.mailgoose.cert.pl:</tt> Expected end_of_statement or "
            "mechanism at position 7 (marked with ➞) in: v=spf1 ➞=bcdefgh"
        ) in result or (
            "<tt>syntax-error.spf.test.mailgoose.cert.pl:</tt> Expected mechanism or "
            "end_of_statement at position 7 (marked with ➞) in: v=spf1 ➞=bcdefgh"
        ) in result

    def test_problematic_include(self) -> None:
        result = self.check_domain("includes-other-domain.spf." + TEST_DOMAIN)
        assert re.search(INCORRECT_CONFIG_REGEX, result)
        assert not re.search(CORRECT_CONFIG_REGEX, result)
        assert (
            "The SPF record&#39;s include chain has a reference to the <tt>includes-yet-another-domain.spf.test.mailgoose.cert.pl</tt> "
            "domain that doesn&#39;t have an SPF record. When using directives such as &#39;include&#39; "
            "or &#39;redirect&#39; remember that the destination domain must have a correct SPF record."
        ) in result
