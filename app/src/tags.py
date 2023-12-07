from functools import cache

import decouple
from jinja2_simple_tags import StandaloneTag


class BuildIDTag(StandaloneTag):  # type: ignore
    tags = {"build_id"}

    @cache
    def render(self) -> str:
        with open("/app/build_id") as f:
            return f.read().strip()


class LanguageTag(StandaloneTag):  # type: ignore
    tags = {"language"}
    language = decouple.config("LANGUAGE", default="en_US").replace("_", "-")

    @cache
    def render(self) -> str:
        return self.language  # type: ignore
