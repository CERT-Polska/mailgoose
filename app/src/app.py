import binascii
import dataclasses
import datetime
import os
import time
import traceback
from email.utils import parseaddr
from typing import Any, Callable, Optional

import decouple
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from mail_receiver_utils import get_key_from_username
from redis import Redis
from starlette.responses import Response

from .app_utils import (
    get_from_and_dkim_domain,
    recipient_username_to_address,
    scan_and_log,
)
from .check_results import load_check_results, save_check_results
from .db import ScanLogEntrySource, ServerErrorLogEntry, Session
from .logging import build_logger
from .resolver import setup_resolver
from .scan import DomainValidationException, ScanningException, ScanResult
from .templates import setup_templates
from .translate import Language, translate

app = FastAPI()
LOGGER = build_logger(__name__)

app.mount("/static", StaticFiles(directory="static"), name="static")

setup_resolver()

APP_DOMAIN = decouple.config("APP_DOMAIN")
LANGUAGE = decouple.config("LANGUAGE")
REDIS_MESSAGE_DATA_EXPIRY_SECONDS = decouple.config("REDIS_MESSAGE_DATA_EXPIRY_SECONDS")
NAMESERVERS = decouple.config("NAMESERVERS", default="8.8.8.8", cast=decouple.Csv(str))
REDIS = Redis.from_url(decouple.config("REDIS_CONNECTION_STRING"))
SITE_CONTACT_EMAIL = decouple.config("SITE_CONTACT_EMAIL", default=None)

templates = setup_templates(LANGUAGE)


@dataclasses.dataclass
class ScanAPICallResult:
    system_error: Optional[bool] = None
    result: Optional[ScanResult] = None


@app.exception_handler(404)
async def custom_404_handler(request: Request, exception: HTTPException) -> Response:
    return templates.TemplateResponse("404.html", {"request": request})


@app.middleware("http")
async def catch_exceptions_log_time_middleware(request: Request, call_next: Callable[[Request], Any]) -> Any:
    try:
        time_start = time.time()
        result = await call_next(request)
        LOGGER.info(
            "%s %s took %s seconds",
            request.method,
            request.url.path,
            time.time() - time_start,
        )
        return result
    except Exception:
        LOGGER.exception("An error occured when handling request")

        session = Session()
        server_error_log_entry = ServerErrorLogEntry(url=str(request.url), error=traceback.format_exc())
        session.add(server_error_log_entry)
        session.commit()

        return HTMLResponse(status_code=500, content="Internal Server Error")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root(request: Request) -> Response:
    return templates.TemplateResponse("root.html", {"request": request})


@app.get("/check-email", response_class=HTMLResponse, include_in_schema=False)
async def check_email_form(request: Request) -> Response:
    recipient_username = f"{binascii.hexlify(os.urandom(16)).decode('ascii')}"
    key = get_key_from_username(recipient_username)
    REDIS.setex(b"requested-" + key, REDIS_MESSAGE_DATA_EXPIRY_SECONDS, 1)

    return RedirectResponse("/check-email/" + recipient_username)


@app.get(
    "/check-email/{recipient_username}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
async def check_email_results(request: Request, recipient_username: str) -> Response:
    recipient_address = recipient_username_to_address(recipient_username)
    key = get_key_from_username(recipient_username)

    if not REDIS.get(b"requested-" + key):
        # This is to prevent users providing their own, non-random (e.g. offensive)
        # keys.
        return RedirectResponse("/check-email")

    message_data = REDIS.get(key)
    message_timestamp_raw = REDIS.get(key + b"-timestamp")
    mail_from_raw = REDIS.get(key + b"-sender")

    if not message_data or not message_timestamp_raw or not mail_from_raw:
        return templates.TemplateResponse(
            "check_email.html",
            {
                "request": request,
                "recipient_username": recipient_username,
                "recipient_address": recipient_address,
                "site_contact_email": SITE_CONTACT_EMAIL,
            },
        )

    message_timestamp = datetime.datetime.fromisoformat(message_timestamp_raw.decode("ascii"))

    _, mail_from = parseaddr(mail_from_raw.decode("ascii"))
    _, envelope_domain = tuple(mail_from.split("@", 1))

    from_domain, dkim_domain = get_from_and_dkim_domain(message_data)
    if not from_domain:
        result = None
        error = translate("Invalid or no e-mail domain in the message From header", Language.pl_PL)
    else:
        try:
            result = scan_and_log(
                request=request,
                source=ScanLogEntrySource.GUI,
                envelope_domain=envelope_domain,
                from_domain=from_domain,
                dkim_domain=dkim_domain,
                message=message_data,
                message_timestamp=message_timestamp,
                nameservers=NAMESERVERS,
                language=Language(LANGUAGE),
            )
            error = None
        except (DomainValidationException, ScanningException) as e:
            result = None
            error = translate(e.message, Language.pl_PL)

    token = save_check_results(
        envelope_domain=envelope_domain,
        from_domain=from_domain or envelope_domain,
        dkim_domain=dkim_domain,
        result=result,
        error=error,
        rescan_url="/check-email/",
        message_recipient_username=recipient_username,
    )
    return RedirectResponse(f"/check-results/{token}", status_code=302)


@app.get("/check-domain", response_class=HTMLResponse, include_in_schema=False)
async def check_domain_form(request: Request) -> Response:
    return templates.TemplateResponse("check_domain.html", {"request": request})


@app.get("/check-domain/scan", response_class=HTMLResponse, include_in_schema=False)
async def check_domain_scan_get(request: Request) -> Response:
    return RedirectResponse("/check-domain")


@app.post("/check-domain/scan", response_class=HTMLResponse, include_in_schema=False)
async def check_domain_scan_post(request: Request, domain: str = Form()) -> Response:
    try:
        result = scan_and_log(
            request=request,
            source=ScanLogEntrySource.GUI,
            envelope_domain=domain,
            from_domain=domain,
            dkim_domain=None,
            message=None,
            message_timestamp=None,
            nameservers=NAMESERVERS,
            language=Language(LANGUAGE),
        )
        error = None
    except (DomainValidationException, ScanningException) as e:
        result = None
        error = translate(e.message, Language.pl_PL)

    token = save_check_results(
        envelope_domain=domain,
        from_domain=domain,
        dkim_domain=None,
        result=result,
        error=error,
        rescan_url="/check-domain/",
        message_recipient_username=None,
    )
    return RedirectResponse(f"/check-results/{token}", status_code=302)


@app.get("/check-results/{token}", response_class=HTMLResponse, include_in_schema=False)
async def check_results(request: Request, token: str) -> Response:
    check_results = load_check_results(token)

    if not check_results:
        raise HTTPException(status_code=404)

    return templates.TemplateResponse(
        "check_results.html",
        {"request": request, "url": request.url, **check_results},
    )


@app.get("/api/v1/email-received", include_in_schema=False)
async def email_received(request: Request, recipient_username: str) -> bool:
    key = get_key_from_username(recipient_username)
    message_data = REDIS.get(key)
    return message_data is not None


@app.post("/api/v1/check-domain", response_model_exclude_none=True)
async def check_domain_api(request: Request, domain: str) -> ScanAPICallResult:
    """
    An API to check e-mail sender verification mechanisms of a domain.

    Returns a ScanAPICallResult object, containing information whether the request
    was successful and a ScanResult object. The DKIM field of the ScanResult
    object will be empty, as DKIM can't be checked when given only a domain.
    """
    try:
        result = scan_and_log(
            request=request,
            source=ScanLogEntrySource.API,
            envelope_domain=domain,
            from_domain=domain,
            dkim_domain=None,
            message=None,
            message_timestamp=None,
            nameservers=NAMESERVERS,
            language=Language(LANGUAGE),
        )
        return ScanAPICallResult(result=result)
    except (DomainValidationException, ScanningException):
        LOGGER.exception("An error occured during check of %s", domain)
        return ScanAPICallResult(system_error=True)
