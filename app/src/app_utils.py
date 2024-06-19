import binascii
import dataclasses
import datetime
import io
import traceback
from email import message_from_file
from email.utils import parseaddr
from typing import Optional, Tuple

import dkim.util
from email_validator import EmailNotValidError, validate_email
from libmailgoose.language import Language
from libmailgoose.scan import ScanResult, scan
from libmailgoose.translate import translate_scan_result

from common.config import Config

from .db import (
    DKIMImplementationMismatchLogEntry,
    NonexistentTranslationLogEntry,
    ScanLogEntry,
    ScanLogEntrySource,
    Session,
)
from .logging import build_logger

LOGGER = build_logger(__name__)


def get_from_and_dkim_domain(message: bytes) -> Tuple[Optional[str], Optional[str]]:
    stream = io.StringIO(message.decode("utf-8", errors="ignore"))
    message_parsed = message_from_file(stream)

    if "from" in message_parsed:
        from_address_with_optional_name = message_parsed["from"]
        _, from_address = parseaddr(from_address_with_optional_name)

        try:
            validate_email(from_address, check_deliverability=False)
            _, from_domain = from_address.split("@", 1)
        except EmailNotValidError as e:
            LOGGER.info("E-mail %s is not valid: %s", from_address, e)
            from_domain = None
    else:
        from_domain = None

    dkim_domain = None
    if "dkim-signature" in message_parsed:
        try:
            sig = dkim.util.parse_tag_value(message_parsed["dkim-signature"].encode("ascii"))
            dkim_domain_raw = sig.get(b"d", None)
            if dkim_domain_raw:
                dkim_domain = dkim_domain_raw.decode("ascii")
        except dkim.util.InvalidTagValueList:
            pass

    return from_domain, dkim_domain


def dkim_implementation_mismatch_callback(message: bytes, dkimpy_valid: bool, opendkim_valid: bool) -> None:
    session = Session()
    log_entry = DKIMImplementationMismatchLogEntry(
        message=binascii.hexlify(message),
        dkimpy_valid=dkimpy_valid,
        opendkim_valid=opendkim_valid,
    )
    session.add(log_entry)
    session.commit()


def scan_and_log(
    source: ScanLogEntrySource,
    envelope_domain: str,
    from_domain: str,
    dkim_domain: Optional[str],
    message: Optional[bytes],
    message_timestamp: Optional[datetime.datetime],
    language: Language,
    client_ip: Optional[str],
    client_user_agent: Optional[str],
) -> ScanResult:
    scan_log_entry = ScanLogEntry(
        envelope_domain=envelope_domain,
        from_domain=from_domain,
        dkim_domain=dkim_domain,
        message=message,
        source=source.value,
        client_ip=client_ip,
        client_user_agent=client_user_agent,
        check_options={},
    )
    result = ScanResult(
        domain=None,
        dkim=None,
        timestamp=datetime.datetime.now(),
        message_timestamp=message_timestamp,
    )

    try:
        result = translate_scan_result(
            scan(
                envelope_domain=envelope_domain,
                from_domain=from_domain,
                dkim_domain=dkim_domain,
                message=message,
                message_timestamp=message_timestamp,
                dkim_implementation_mismatch_callback=dkim_implementation_mismatch_callback,
            ),
            language=language,
            nonexistent_translation_handler=_nonexistent_translation_handler,
        )
        return result
    except Exception:
        scan_log_entry.error = traceback.format_exc()
        raise
    finally:
        session = Session()
        scan_log_entry.result = dataclasses.asdict(result)
        scan_log_entry.result["timestamp"] = scan_log_entry.result["timestamp"].isoformat()
        if scan_log_entry.result["message_timestamp"]:
            scan_log_entry.result["message_timestamp"] = scan_log_entry.result["message_timestamp"].isoformat()
        session.add(scan_log_entry)
        session.commit()


def recipient_username_to_address(username: str) -> str:
    # We do not use the request hostname as due to proxy configuration we sometimes got the
    # Host header wrong, thus breaking the check-by-email feature.
    return f"{username}@{Config.Network.APP_DOMAIN}"


def _nonexistent_translation_handler(message: str) -> str:
    """
    By default, translate_scan_result() raises an exception when a translation doesn't exist.
    When users verify their mail configuration from an app, we want to degrade gracefully - instead
    of raising an exception, we log the information about missing translation and display
    English message.
    """
    nonexistent_translation_log_entry = NonexistentTranslationLogEntry(message=message)

    session = Session()
    session.add(nonexistent_translation_log_entry)
    session.commit()

    return message
