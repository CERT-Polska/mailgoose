from typing import Any, Dict
from unittest import TestCase

import requests
from config import APP_URL


class BaseTestCase(TestCase):
    def check_domain(self, domain: str) -> str:
        response = requests.post(APP_URL + "/check-domain/scan", {"domain": domain})
        return response.text.replace("\n", " ")

    def check_domain_api_v1(self, domain: str) -> Dict[str, Any]:
        response = requests.post(APP_URL + "/api/v1/check-domain?domain=" + domain)
        return response.json()  # type: ignore
