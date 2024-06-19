import binascii
import dataclasses
import os
import time
import traceback
from email.utils import parseaddr
from typing import Any, Callable, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from libmailgoose.language import Language
from libmailgoose.scan import DomainValidationException, ScanningException, ScanResult
from redis import Redis
from rq import Queue
from starlette.responses import Response

from common.config import Config
from common.mail_receiver_utils import get_key_from_username

from .app_utils import recipient_username_to_address, scan_and_log
from .check_results import load_check_results
from .db import ScanLogEntrySource, ServerErrorLogEntry, Session
from .logging import build_logger
from .resolver import setup_resolver
from .templates import setup_templates
from .worker import scan_domain_job, scan_message_and_domain_job

app = FastAPI()
LOGGER = build_logger(__name__)
REDIS = Redis.from_url(Config.Data.REDIS_URL)
job_queue = Queue(connection=REDIS)

app.mount("/static", StaticFiles(directory="static"), name="static")

setup_resolver()

templates = setup_templates(Config.UI.LANGUAGE)


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
    REDIS.setex(b"requested-" + key, Config.Data.REDIS_MESSAGE_DATA_EXPIRY_SECONDS, 1)

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
                "site_contact_email": Config.UI.SITE_CONTACT_EMAIL,
            },
        )

    _, mail_from = parseaddr(mail_from_raw.decode("ascii"))
    _, envelope_domain = tuple(mail_from.split("@", 1))

    client_ip = request.client.host if request.client else None
    client_user_agent = request.headers.get("user-agent", None)

    token = binascii.hexlify(os.urandom(32)).decode("ascii")
    job_queue.enqueue(
        scan_message_and_domain_job,
        client_ip,
        client_user_agent,
        envelope_domain,
        token,
        key,
        recipient_username,
        job_id=token,
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
    client_ip = request.client.host if request.client else None
    client_user_agent = request.headers.get("user-agent", None)

    token = binascii.hexlify(os.urandom(32)).decode("ascii")
    job_queue.enqueue(scan_domain_job, client_ip, client_user_agent, domain, token, job_id=token)

    return RedirectResponse(f"/check-results/{token}", status_code=302)


@app.get("/check-results/{token}", response_class=HTMLResponse, include_in_schema=False)
async def check_results(request: Request, token: str) -> Response:
    if job := job_queue.fetch_job(token):
        if job.get_status(refresh=False) not in ["finished", "canceled", "failed"]:
            return templates.TemplateResponse(
                "check_running.html",
                {"request": request},
            )

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
        client_ip = request.client.host if request.client else None
        client_user_agent = request.headers.get("user-agent", None)

        result = scan_and_log(
            source=ScanLogEntrySource.API,
            envelope_domain=domain,
            from_domain=domain,
            dkim_domain=None,
            message=None,
            message_timestamp=None,
            language=Language(Config.UI.LANGUAGE),
            client_ip=client_ip,
            client_user_agent=client_user_agent,
        )
        return ScanAPICallResult(result=result)
    except (DomainValidationException, ScanningException):
        LOGGER.exception("An error occured during check of %s", domain)
        return ScanAPICallResult(system_error=True)
