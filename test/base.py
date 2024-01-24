from time import sleep
from typing import Any, Dict
from unittest import TestCase

import requests
from config import APP_URL


class BaseTestCase(TestCase):
    def check_domain(self, domain: str) -> str:
        submission_response = requests.post(APP_URL + "/check-domain/scan", {"domain": domain}, allow_redirects=False)
        submission_response.raise_for_status()

        if not submission_response.next or not submission_response.next.url:
            raise RuntimeError("Did not receive a redirect after submitting domain for scanning")

        results_url = submission_response.next.url

        results_response = requests.get(results_url)
        results_response.raise_for_status()

        while "Domain analysis is running" in results_response.text:
            results_response = requests.get(results_url)
            results_response.raise_for_status()

            sleep(5)

        return results_response.text.replace("\n", " ")

    def check_domain_api_v1(self, domain: str) -> Dict[str, Any]:
        response = requests.post(APP_URL + "/api/v1/check-domain?domain=" + domain)
        return response.json()  # type: ignore
