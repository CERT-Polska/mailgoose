import dataclasses
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.resolver

from .ssl_check import (
    SSLCertificateError,
    SSLEnum,
    SSLInternalError,
    resolve_to_ip,
    ssl_certificate_description,
    validate_tls_info,
)

# RFC 6186 describes SRV records that allow a mail client to discover the servers it should
# connect to. For now we only look up the IMAP ones - the submission (_submission._tcp,
# _submissions._tcp) and POP3 (_pop3._tcp, _pop3s._tcp) services may be added here later.
MAIL_CLIENT_SERVICES: Dict[str, SSLEnum] = {
    "imap": SSLEnum.STARTTLS,
    "imaps": SSLEnum.IMPLICIT,
}

login_disabled_description = (
    "Until the connection is encrypted, an IMAP server should advertise the LOGINDISABLED capability "
    "and refuse to accept the user's password. Otherwise, a mail client that doesn't require encryption "
    "may send the password over a connection that can be read or modified by anybody who is able to "
    "intercept the traffic."
)


@dataclasses.dataclass(frozen=True)
class SRVRecord:
    priority: int
    weight: int
    port: int
    target: str


@dataclasses.dataclass
class MailClientServerScanResult:
    service: str
    host: str
    port: int
    priority: int
    error: Optional[str] = None
    warning: Optional[str] = None
    additional_info: Optional[str] = None


@dataclasses.dataclass
class MailClientTLSScanResult:
    valid: bool
    warnings: bool
    results: List[MailClientServerScanResult]


def retrieve_SRV_records(
    domain: str, service: str, protocol: str = "tcp", nameservers: Optional[List[str]] = None
) -> List[SRVRecord]:
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    try:
        answers = resolver.resolve(f"_{service}._{protocol}.{domain}", "SRV")
    except Exception:
        return []

    records = []
    for answer in answers:
        target = answer.target.to_text().rstrip(".")

        # RFC 2782: a target of "." means that the service is decidedly not available at this domain.
        if not target:
            continue

        records.append(
            SRVRecord(
                priority=int(answer.priority),
                weight=int(answer.weight),
                port=int(answer.port),
                target=target,
            )
        )

    return sorted(records, key=lambda record: (record.priority, -record.weight, record.target, record.port))


def parse_capabilities(lines: List[str]) -> Set[str]:
    """Extracts IMAP capabilities both from an untagged CAPABILITY response and from a greeting.

    A server may advertise its capabilities in a "* CAPABILITY (...)" response, but is also allowed
    to put them in the response code of the greeting: "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready".
    """
    capabilities: Set[str] = set()
    for line in lines:
        for response_code in re.findall(r"\[CAPABILITY([^\]]*)\]", line, re.IGNORECASE):
            capabilities.update(item.upper() for item in response_code.split())

        untagged_response = re.match(r"^\*\s+CAPABILITY\s+(.*)$", line, re.IGNORECASE)
        if untagged_response:
            capabilities.update(item.upper() for item in untagged_response.group(1).split())
    return capabilities


class IMAPConnection:
    """A minimal IMAP client, sufficient to verify how a server handles TLS."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._buffer = b""
        self._command_counter = 0

    def read_line(self) -> str:
        while b"\r\n" not in self._buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise SSLInternalError("The IMAP server closed the connection unexpectedly")
            self._buffer += chunk

        line, self._buffer = self._buffer.split(b"\r\n", 1)
        return line.decode("utf-8", errors="replace")

    def read_greeting(self) -> Set[str]:
        greeting = self.read_line()
        if not greeting.startswith("* OK") and not greeting.startswith("* PREAUTH"):
            raise SSLInternalError(f"Unexpected greeting received from the IMAP server: {greeting}")
        return parse_capabilities([greeting])

    def command(self, command: str) -> Tuple[str, List[str]]:
        self._command_counter += 1
        tag = f"a{self._command_counter}"
        self.sock.sendall(f"{tag} {command}\r\n".encode("ascii"))

        untagged_responses: List[str] = []
        while True:
            line = self.read_line()
            if line.startswith(f"{tag} "):
                status = line[len(tag) + 1 :].split(" ", 1)[0].upper()
                return status, untagged_responses
            untagged_responses.append(line)

    def capabilities(self) -> Set[str]:
        status, untagged_responses = self.command("CAPABILITY")
        if status != "OK":
            raise SSLInternalError("The IMAP server refused the CAPABILITY command")
        return parse_capabilities(untagged_responses)

    def start_tls(self, context: ssl.SSLContext, hostname: str) -> ssl.SSLSocket:
        status, _ = self.command("STARTTLS")
        if status != "OK":
            raise SSLInternalError("The IMAP server refused the STARTTLS command")

        # RFC 3501: the client must discard any data received before the handshake, as it may have
        # been injected by an attacker. A correctly behaving server doesn't send such data at all.
        if self._buffer:
            raise SSLInternalError(
                "The IMAP server sent data between the STARTTLS command and the TLS handshake - such data "
                "must be discarded, as it may have been injected by an attacker"
            )

        tls_sock = context.wrap_socket(self.sock, server_hostname=hostname)
        self.sock = tls_sock
        return tls_sock

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def test_mail_client_tls(hostname: str, ip: str, port: int, ssl_type: SSLEnum, timeout: float) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "port": port,
        "error": None,
        "warning": None,
        "additional_info": None,
    }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED

    connection = None
    try:
        connection = IMAPConnection(socket.create_connection((ip, port), timeout=timeout))

        if ssl_type == SSLEnum.IMPLICIT:
            tls_sock = context.wrap_socket(connection.sock, server_hostname=hostname)
            connection.sock = tls_sock
            validate_tls_info(tls_sock)

            capabilities = connection.read_greeting() | connection.capabilities()
            if "STARTTLS" in capabilities:
                result["warning"] = (
                    f"The {hostname} server advertises the STARTTLS capability on a port that already uses "
                    "implicit TLS - on an already encrypted connection this capability shouldn't be advertised."
                )
        else:
            capabilities = connection.read_greeting() | connection.capabilities()

            if "STARTTLS" not in capabilities:
                raise SSLInternalError(f"STARTTLS not supported on {hostname} IMAP server")

            if "LOGINDISABLED" not in capabilities:
                result["warning"] = (
                    f"The {hostname} server doesn't advertise the LOGINDISABLED capability, therefore mail "
                    "clients may send the user's password over an unencrypted connection."
                )
                result["additional_info"] = login_disabled_description

            tls_sock = connection.start_tls(context, hostname)
            validate_tls_info(tls_sock)

            # Make sure the server still speaks IMAP after the handshake
            connection.capabilities()

    except ssl.SSLCertVerificationError as e:
        verify_message = e.verify_message
        if "unable to get local issuer certificate" in verify_message:
            # this error needs to be more descriptive, as it doesn't tell the user what is wrong with the certificate
            verify_message = "unable to get local issuer certificate, possibly due to missing intermediate certificates or untrusted root CA in the certificate chain"
        result["warning"] = f"Certificate error: {verify_message}"
        result["additional_info"] = ssl_certificate_description
    except SSLCertificateError as e:
        result["warning"] = str(e)
        result["additional_info"] = ssl_certificate_description
    except ConnectionRefusedError:
        # Contrary to the MX check, we don't skip this error for parked domains - the domain
        # explicitly advertises the service in a SRV record, so it should be reachable.
        result["error"] = "Connection refused"
    except SSLInternalError as e:
        result["error"] = str(e)
    except TimeoutError:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = str(e)
    finally:
        if connection:
            connection.close()

    return result


def validate_mail_client_tls(
    host: str, nameservers: Optional[List[str]], timeout: float
) -> Optional[MailClientTLSScanResult]:
    """Checks the TLS configuration of the servers a mail client would connect to.

    The servers are discovered using the SRV records described in RFC 6186. If the domain doesn't
    publish them, None is returned - these records are optional, so their absence is not an error.
    """
    servers: List[Tuple[str, SSLEnum, SRVRecord]] = []
    for service, ssl_type in MAIL_CLIENT_SERVICES.items():
        for record in retrieve_SRV_records(host, service, nameservers=nameservers):
            servers.append((service, ssl_type, record))

    if not servers:
        return None

    results: List[MailClientServerScanResult] = []

    def scan_server(service: str, ssl_type: SSLEnum, record: SRVRecord, ip: str) -> MailClientServerScanResult:
        result = test_mail_client_tls(
            record.target,
            ip,
            record.port,
            ssl_type,
            timeout=timeout,
        )
        return MailClientServerScanResult(
            service=service,
            host=record.target,
            port=result["port"],
            priority=record.priority,
            error=result["error"],
            warning=result["warning"],
            additional_info=result["additional_info"],
        )

    with ThreadPoolExecutor(max_workers=len(servers)) as executor:
        futures = []
        for service, ssl_type, record in servers:
            ip = resolve_to_ip(record.target, nameservers=nameservers)
            if not ip:
                results.append(
                    MailClientServerScanResult(
                        service=service,
                        host=record.target,
                        port=record.port,
                        priority=record.priority,
                        error="DNS resolution error",
                    )
                )
                continue

            futures.append(executor.submit(scan_server, service, ssl_type, record, ip))

        results.extend(item.result() for item in as_completed(futures))

    results = sorted(results, key=lambda item: (item.service, item.priority, item.host, item.port))

    return MailClientTLSScanResult(
        valid=all(item.error is None for item in results),
        warnings=not all(item.warning is None for item in results),
        results=results,
    )
