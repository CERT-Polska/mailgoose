from typing import Annotated, Any, List, get_type_hints

import decouple

from libmailgoose.language import Language

DEFAULTS = {}


def get_config(name: str, **kwargs) -> Any:  # type: ignore
    if "default" in kwargs:
        DEFAULTS[name] = kwargs["default"]
    return decouple.config(name, **kwargs)


class Config:
    class Data:
        DB_URL: Annotated[
            str,
            "The URL used to connect to the database (as documented on "
            "https://docs.sqlalchemy.org/en/20/core/engines.html#database-urls). The CERT PL "
            "production instance uses PostgreSQL - this is the database the system has been most "
            "thoroughly tested on.\n\n"
            "If you start the system using the default ``docker-compose.yml`` file in the Github repository, this "
            "variable (and a database) will be set up for you.",
        ] = get_config("DB_URL")
        REDIS_MESSAGE_DATA_EXPIRY_SECONDS: Annotated[
            int,
            "The messages sent to the system and stored in Redis expire in order to decrease the chance that "
            "Redis takes too much memory (the full scan logs are stored in a Postgres database). This variable "
            "controls how long they will be stored before they expire.",
        ] = get_config("REDIS_MESSAGE_DATA_EXPIRY_SECONDS", cast=int, default=10 * 24 * 60 * 60)
        REDIS_URL: Annotated[
            str,
            "The URL used to connect to Redis, eg. `redis://redis:6379/0 <redis://redis:6379/0>`_ (the format is "
            "documented on `https://redis-py.readthedocs.io/en/stable/connections.html#redis.Redis.from_url "
            "<https://redis-py.readthedocs.io/en/stable/connections.html#redis.Redis.from_url>`_).\n\n"
            "If you start the system using the default ``docker-compose.yml`` file in the Github repository, this "
            "variable (and a Redis instance) will be set up for you.",
        ] = get_config("REDIS_URL")

    class Network:
        APP_DOMAIN: Annotated[str, "The domain the site is running on."] = get_config("APP_DOMAIN")
        NAMESERVERS: Annotated[
            List[str],
            "A comma-separated list of nameservers that will be used to resolve domains. If you want "
            "to provide custom ones, remember to modify the ones provided to the Docker containers as well. "
            "At CERT PL we use a separate ``docker-compose.yml`` file with additional configuration specific "
            "to our instance.",
        ] = get_config("NAMESERVERS", default="8.8.8.8", cast=decouple.Csv(str))
        SSL_PRIVATE_KEY_PATH: Annotated[
            str,
            "SSL private key path. Please refer to ``SSL_CERTIFICATE_PATH`` variable documentation to "
            "learn potential caveats.",
        ] = decouple.config("SSL_PRIVATE_KEY_PATH", default=None)
        SSL_CERTIFICATE_PATH: Annotated[
            str,
            "SSL certificate path. Remember:\n\n"
            "1. to mount it into your Docker container,\n"
            "2. to restart the containers if a new one is generated,\n"
            "3. that generated certificates may be symbolic links - their destination must also be mounted.\n\n",
        ] = decouple.config("SSL_CERTIFICATE_PATH", default=None)

    class UI:
        LANGUAGE: Annotated[
            str,
            "The language the site will use (in the form of ``language_COUNTRY``, e.g. ``en_US``). "
            f"Supported options are: {', '.join(sorted('``' + language.value + '``' for language in Language))}.",
        ] = get_config("LANGUAGE", default="en_US")
        OLD_CHECK_RESULTS_AGE_MINUTES: Annotated[
            int,
            "If the user is viewing old check results, they will see a message that the check result "
            "may not describe the current configuration. This is the threshold (in minutes) how old "
            "the check results need to be for that message to be displayed.",
        ] = get_config("OLD_CHECK_RESULTS_AGE_MINUTES", default=60, cast=int)
        SITE_CONTACT_EMAIL: Annotated[
            str,
            "The contact e-mail that will be displayed in the UI (currently in the message that "
            "describes what to do if e-mails to the system aren't received).",
        ] = get_config("SITE_CONTACT_EMAIL", default=None)

    @staticmethod
    def verify_each_variable_is_annotated() -> None:
        def verify_class(cls: type) -> None:
            hints = get_type_hints(cls)

            for variable_name in dir(cls):
                if variable_name.startswith("__"):
                    continue
                member = getattr(cls, variable_name)

                if isinstance(member, type):
                    verify_class(member)
                elif member == Config.verify_each_variable_is_annotated:
                    pass
                else:
                    assert variable_name in hints, f"{variable_name} in {cls} has no type hint"

        verify_class(Config)


Config.verify_each_variable_is_annotated()
