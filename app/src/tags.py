from functools import cache

from jinja2_simple_tags import StandaloneTag

try:
    from common.config import Config

    LANGUAGE = Config.UI.LANGUAGE
except ImportError:
    # This may happen e.g. when pybabel is processing the templates and loading the tempalate tags
    LANGUAGE = ""


class BuildIDTag(StandaloneTag):  # type: ignore
    tags = {"build_id"}

    @cache
    def render(self) -> str:
        with open("/app/build_id") as f:
            return f.read().strip()


class LanguageTag(StandaloneTag):  # type: ignore
    tags = {"language"}
    language = LANGUAGE.replace("_", "-")

    @cache
    def render(self) -> str:
        return self.language
