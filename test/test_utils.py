from time import sleep
from typing import Any, Dict
from unittest import TestCase

from config import APP_URL

from libmailgoose.ssl_check import is_private_ip


class UtilsTestCase(TestCase):
    def test_is_ip_private(self) -> None:

        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertFalse(is_private_ip("1.2.3.4"))