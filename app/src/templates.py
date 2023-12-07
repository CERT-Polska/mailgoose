import gettext
import subprocess

from fastapi.templating import Jinja2Templates

from .tags import BuildIDTag, LanguageTag
from .template_utils import mailgoose_urlize


def setup_templates(language: str) -> Jinja2Templates:
    templates = Jinja2Templates(directory="templates", extensions=[BuildIDTag, LanguageTag, "jinja2.ext.i18n"])
    templates.env.filters["mailgoose_urlize"] = mailgoose_urlize
    subprocess.call(
        [
            "pybabel",
            "compile",
            "-f",
            "--input",
            f"/app/translations/{language}/LC_MESSAGES/messages.po",
            "--output",
            f"/app/translations/{language}/LC_MESSAGES/messages.mo",
        ],
        stderr=subprocess.DEVNULL,  # suppress a misleading message where compiled translations will be saved
    )

    templates.env.install_gettext_translations(  # type: ignore
        gettext.translation(domain="messages", localedir="/app/translations", languages=[language]), newstyle=True
    )

    return templates
