import datetime
import traceback
from typing import Optional

from libmailgoose.language import Language
from libmailgoose.scan import DomainValidationException, ScanningException
from libmailgoose.translate import translate
from redis import Redis

from common.config import Config

from .app_utils import get_from_and_dkim_domain, scan_and_log
from .check_results import save_check_results
from .db import ScanLogEntrySource, ServerErrorLogEntry, Session
from .logging import build_logger
from .resolver import setup_resolver

LOGGER = build_logger(__name__)
REDIS = Redis.from_url(Config.Data.REDIS_URL)

setup_resolver()


def scan_domain_job(
    client_ip: Optional[str],
    client_user_agent: Optional[str],
    domain: str,
    token: str,
) -> None:
    try:
        result = scan_and_log(
            source=ScanLogEntrySource.GUI,
            envelope_domain=domain,
            from_domain=domain,
            dkim_domain=None,
            message=None,
            message_timestamp=None,
            nameservers=Config.Network.NAMESERVERS,
            language=Language(Config.UI.LANGUAGE),
            client_ip=client_ip,
            client_user_agent=client_user_agent,
        )
        error = None
    except (DomainValidationException, ScanningException) as e:
        result = None
        error = translate(e.message, Language(Config.UI.LANGUAGE))
    except Exception:
        session = Session()
        server_error_log_entry = ServerErrorLogEntry(url="worker", error=traceback.format_exc())
        session.add(server_error_log_entry)
        session.commit()

        result = None
        LOGGER.exception("Error during configuration validation")
        error = translate("An unknown error has occured during configuration validation.", Language(Config.UI.LANGUAGE))

    save_check_results(
        envelope_domain=domain,
        from_domain=domain,
        dkim_domain=None,
        result=result,
        error=error,
        rescan_url="/check-domain/",
        message_recipient_username=None,
        token=token,
    )


def scan_message_and_domain_job(
    client_ip: Optional[str],
    client_user_agent: Optional[str],
    envelope_domain: str,
    token: str,
    message_key: bytes,
    recipient_username: str,
) -> None:
    message_data = REDIS.get(message_key)
    message_timestamp_raw = REDIS.get(message_key + b"-timestamp")

    if not message_data or not message_timestamp_raw:
        raise RuntimeError("Worker coudn't access message data")

    message_timestamp = datetime.datetime.fromisoformat(message_timestamp_raw.decode("ascii"))

    from_domain, dkim_domain = get_from_and_dkim_domain(message_data)
    if not from_domain:
        result = None
        error = translate("Invalid or no e-mail domain in the message From header", Language(Config.UI.LANGUAGE))
    else:
        try:
            result = scan_and_log(
                source=ScanLogEntrySource.GUI,
                envelope_domain=envelope_domain,
                from_domain=from_domain,
                dkim_domain=dkim_domain,
                message=message_data,
                message_timestamp=message_timestamp,
                nameservers=Config.Network.NAMESERVERS,
                language=Language(Config.UI.LANGUAGE),
                client_ip=client_ip,
                client_user_agent=client_user_agent,
            )
            error = None
        except (DomainValidationException, ScanningException) as e:
            result = None
            error = translate(e.message, Language(Config.UI.LANGUAGE))

    save_check_results(
        envelope_domain=envelope_domain,
        from_domain=from_domain or envelope_domain,
        dkim_domain=dkim_domain,
        result=result,
        error=error,
        rescan_url="/check-email/",
        message_recipient_username=recipient_username,
        token=token,
    )
