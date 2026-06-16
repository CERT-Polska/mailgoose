import gettext
import os
import subprocess
import tempfile

from fastapi.templating import Jinja2Templates

from .tags import BuildIDTag, LanguageTag
from .template_utils import mailgoose_urlize


def setup_templates(language: str) -> Jinja2Templates:
    templates = Jinja2Templates(directory="templates", extensions=[BuildIDTag, LanguageTag, "jinja2.ext.i18n"])
    templates.env.filters["mailgoose_urlize"] = mailgoose_urlize

    with tempfile.TemporaryDirectory() as localedir:
        output_dir = os.path.join(localedir, language, "LC_MESSAGES")
        os.makedirs(output_dir)
        subprocess.call(
            [
                "pybabel",
                "compile",
                "-f",
                "--input",
                f"/app/translations/{language}/LC_MESSAGES/messages.po",
                "--output",
                os.path.join(output_dir, "messages.mo"),
            ],
            stderr=subprocess.DEVNULL,  # suppress a misleading message where compiled translations will be saved
        )

        templates.env.install_gettext_translations(  # type: ignore
            gettext.translation(domain="messages", localedir=localedir, languages=[language]), newstyle=True
        )

    return templates
