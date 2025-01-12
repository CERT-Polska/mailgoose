import binascii
import datetime
import logging
import os
import ssl
import time
from email.message import Message as EmailMessage
from typing import Any, Dict, Optional, Sequence, Union

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message as BaseMessageHandler
from aiosmtpd.smtp import SMTP, Envelope, Session
from redis import Redis

from common.config import Config
from common.mail_receiver_utils import get_key_from_username

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)

LOGGER = logging.getLogger(__name__)
REDIS = Redis.from_url(Config.Data.REDIS_URL)

if Config.Network.SSL_PRIVATE_KEY_PATH and Config.Network.SSL_CERTIFICATE_PATH:
    assert os.path.exists(Config.Network.SSL_PRIVATE_KEY_PATH)
    assert os.path.exists(Config.Network.SSL_CERTIFICATE_PATH)
    LOGGER.info("SSL key and certificate exist, creating context")
    SSL_CONTEXT: Optional[ssl.SSLContext] = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    assert SSL_CONTEXT
    SSL_CONTEXT.load_cert_chain(Config.Network.SSL_CERTIFICATE_PATH, Config.Network.SSL_PRIVATE_KEY_PATH)
else:
    LOGGER.info("SSL key and certificate don't exist, not creating context")
    SSL_CONTEXT = None


class EmailProcessingException(Exception):
    pass


class RedisHandler(BaseMessageHandler):
    def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> Any:
        mail_from = envelope.mail_from
        assert mail_from

        # We use the raw content, not the parsed message from handle_message, so that changes (e.g. headers reordering)
        # don't break DKIM body hash.
        content = envelope.original_content or b""

        LOGGER.info("SSL: %s", session.ssl)
        LOGGER.info(
            "Raw message body bytes (hexlified): %s",
            binascii.hexlify(content),
        )

        for rcpt_to in envelope.rcpt_tos:
            try:
                # We ignore the domain on purpose. Some e-mail providers (e.g. Wirtualna Polska, wp.pl), when
                # tasked with sending an e-mail to a domain, if this domain contains a CNAME record, will
                # actually send the e-mail to the CNAME destination.
                rcpt_to_username, _ = rcpt_to.split("@", 1)

                key = get_key_from_username(rcpt_to_username)

                LOGGER.info(
                    "Saving message: %s -> %s (%s bytes) to Redis under key %s",
                    mail_from,
                    rcpt_to,
                    len(content),
                    key,
                )
                REDIS.setex(key, Config.Data.REDIS_MESSAGE_DATA_EXPIRY_SECONDS, content)
                REDIS.setex(
                    key + b"-sender_ip",
                    Config.Data.REDIS_MESSAGE_DATA_EXPIRY_SECONDS,
                    session.peer[0],
                )
                REDIS.setex(
                    key + b"-timestamp",
                    Config.Data.REDIS_MESSAGE_DATA_EXPIRY_SECONDS,
                    datetime.datetime.now().isoformat(),
                )
                REDIS.setex(
                    key + b"-sender",
                    Config.Data.REDIS_MESSAGE_DATA_EXPIRY_SECONDS,
                    mail_from,
                )
                LOGGER.info("Saved")
            except Exception:
                LOGGER.exception(
                    "Exception while processing message: %s -> %s",
                    mail_from,
                    rcpt_to,
                )

                # The exception details are passed to the recipient server - therefore we raise
                # a generic exception so that we don't leak implementation details.
                raise EmailProcessingException("Internal server error when processing message")

        result = super().handle_DATA(server, session, envelope)
        return result

    def handle_message(self, message: EmailMessage) -> None:
        pass


class MailgooseSMTP(SMTP):
    # This is a hack to support some misconfigured SMTP servers that send AUTH parameter in MAIL FROM even if
    # we don't advertise such capability in EHLO (https://www.rfc-editor.org/rfc/rfc4954.html).
    def _getparams(self, params: Sequence[str]) -> Optional[Dict[str, Union[str, bool]]]:
        result = super()._getparams(params)
        if result and "AUTH" in result:
            del result["AUTH"]
        return result


class ControllerOptionalTLS(Controller):
    def factory(self) -> SMTP:
        if SSL_CONTEXT:
            return MailgooseSMTP(self.handler, tls_context=SSL_CONTEXT)
        else:
            return MailgooseSMTP(self.handler)


# We change the line length as some broken servers don't follow RFC
SMTP.line_length_limit = 102400

controller_25 = ControllerOptionalTLS(RedisHandler(), hostname="0.0.0.0", port=25)
controller_25.start()  # type: ignore
controller_587 = ControllerOptionalTLS(RedisHandler(), hostname="0.0.0.0", port=587)
controller_587.start()  # type: ignore

while True:
    time.sleep(3600)
