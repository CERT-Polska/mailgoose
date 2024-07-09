import dns.resolver

from common.config import Config

from .logging import build_logger


class WrappedResolver(dns.resolver.Resolver):
    logger = build_logger(__name__)
    num_retries = 3

    def resolve(self, *args, **kwargs):  # type: ignore
        result = None
        last_exception = None
        num_exceptions = 0

        for i in range(self.num_retries):
            try:
                if i < self.num_retries - 1:
                    self.nameservers = Config.Network.NAMESERVERS
                else:
                    self.nameservers = Config.Network.FALLBACK_NAMESERVERS
                result = super().resolve(*args, **kwargs)
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
