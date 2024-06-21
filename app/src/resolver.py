from socket import gaierror, gethostbyname
from typing import List

import dns.resolver

from common.config import Config

from .logging import build_logger


class WrappedResolver(dns.resolver.Resolver):
    logger = build_logger(__name__)
    num_retries = 3

    def resolve(self, domain, *args, **kwargs):  # type: ignore
        result = None
        last_exception = None
        num_exceptions = 0

        for _ in range(self.num_retries):
            try:
                self.nameservers = Config.Network.NAMESERVERS

                domain_split = domain.split(".")
                bottommost_nameservers: List[str] = []
                for i in range(len(domain_split)):
                    parent_domain = ".".join(domain_split[i:])
                    dns_response = super().resolve(parent_domain, "NS", raise_on_no_answer=False)
                    if len(dns_response):
                        bottommost_nameservers = []
                        for item in dns_response:
                            try:
                                bottommost_nameservers.append(gethostbyname(str(item)))
                            except gaierror:
                                pass
                        break

                if bottommost_nameservers:
                    self.nameservers = bottommost_nameservers
                else:
                    self.nameservers = Config.Network.NAMESERVERS

                # To save time (as checking SPF+DMARC+DKIM already needs a lot of DNS queries), we don't do a full
                # recursive query, but ask the nameserver for the domain. Therefore any edits made by the user will
                # still be quickly visible in the UI.
                result = super().resolve(domain, *args, **kwargs)
                break
            except Exception as e:
                num_exceptions += 1
                self.logger.exception("problem when resolving: %s, %s", args, kwargs)
                last_exception = e

        self.logger.info(
            "%s DNS query: %s, %s -> %s",
            "flaky" if num_exceptions > 0 and num_exceptions < self.num_retries else "non-flaky",
            args,
            kwargs,
            [str(item) for item in result] if result else last_exception,
        )

        if last_exception and not result:
            raise last_exception

        return result


def setup_resolver() -> None:
    if dns.resolver.Resolver != WrappedResolver:
        dns.resolver.Resolver = WrappedResolver  # type: ignore
