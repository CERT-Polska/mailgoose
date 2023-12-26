from functools import cache

from jinja2_simple_tags import StandaloneTag

from common.config import Config


class BuildIDTag(StandaloneTag):  # type: ignore
    tags = {"build_id"}

    @cache
    def render(self) -> str:
        with open("/app/build_id") as f:
            return f.read().strip()


class LanguageTag(StandaloneTag):  # type: ignore
    tags = {"language"}
    language = Config.UI.LANGUAGE.replace("_", "-")

    @cache
    def render(self) -> str:
        return self.language
