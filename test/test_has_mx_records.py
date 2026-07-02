import unittest

from libmailgoose.scan import has_mx_records


class HasMXRecordsTestCase(unittest.TestCase):
    def test_has_mx_records(self) -> None:
        # Test with a domain that has MX records
        self.assertTrue(has_mx_records("gmail.com"))

        # Test with a domain that does not have MX records
        self.assertFalse(has_mx_records("nonexistent.com"))
