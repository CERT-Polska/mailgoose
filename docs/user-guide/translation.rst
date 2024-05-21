Translation
===========
The UI translations reside in ``./app/translations``. If the original messages changed, e.g. because
you changed the UI, update the ``.po`` files by running:

``./scripts/update_translation_files``

and then put the translations in the respective ``.po`` files. The compilation will happen
automatically when starting the system.

The error message translations for DMARC/SPF/DKIM problems reside in the ``TRANSLATIONS`` dict in ``app/src/translate.py``.
The following syntax:

.. code-block:: console

    (
        f"{PLACEHOLDER} is not a valid DMARC report URI",
        f"{PLACEHOLDER} ... translation for your language...",
    ),


means, that the ``{PLACEHOLDER}`` part will be copied verbatim into the translation - this is to
support situations, where the error message contains e.g. a domain, a URI or other part dependent on the configuration.

Adding a new language
---------------------
If you want to support a new language:

- add it in ``scan/libmailgoose/languages.txt``,
- run ``./scripts/update_translation_files`` and fill ``.po`` files for the UI messages for your language in ``./app/translations``
  (**you may skip that part if you want only the library error messages to be translated**),
- add the error message translations for your language in ``scan/libmailgoose/translate.py``.

**You don't have to translate everything - pull requests with partial translations are also welcome!**
