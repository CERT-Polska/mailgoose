import dataclasses
import datetime
import enum
import smtplib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver


class SSLEnum(enum.Enum):
    IMPLICIT = "Implicit TLS"
    STARTTLS = "STARTTLS"


@dataclasses.dataclass
class SSLMXScanResult:
    preference: Optional[int]
    mx: str
    port: Optional[int]
    error: Optional[str] = None
    warning: Optional[str] = None
    additional_info: Optional[str] = None


@dataclasses.dataclass
class SSLScanResult:
    valid: bool
    warnings: bool
    results: List[SSLMXScanResult]


class SSLInternalError(Exception):
    pass


class SSLCertificateError(Exception):
    pass


ssl_certificate_description = (
    "An SSL/TLS certificate encrypts communication between servers while verifying the server's identity. "
    "A website loading successfully in a browser does not guarantee that the mail server certificate is valid,  "
    "as web and mail services typically use separate certificates that are configured independently. "
    "Although a valid SSL/TLS certificate is not necessarily required for email delivery, "
    "it is considered a best practice for ensuring secure email communication."
)


def retrieve_MX_records(domain: str, nameservers: Optional[List[str]] = None) -> List[Tuple[Optional[int], str]]:
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted([(int(r.preference), r.exchange.to_text()) for r in answers])
        return [(r[0], r[1].rstrip(".")) for r in mx_records]
    except Exception:
        return []


def check_cert_name(cn: str, hostname: str) -> bool:
    if cn.startswith("*."):
        return hostname.endswith(cn[1:])
    return cn.lower() == hostname.lower()


def check_cert_hostnames(cert: Dict[str, Any], hostname: str) -> bool:
    main_CN = dict(x[0] for x in cert["subject"]).get("commonName", "")
    if check_cert_name(main_CN, hostname):
        return True

    alt_names = [x[1] for x in cert.get("subjectAltName", [])]
    for alt_name in alt_names:
        if check_cert_name(alt_name, hostname):
            return True
    raise SSLCertificateError(
        f"Certificate hostname mismatch: {hostname} doesn't match certificate names: {', '.join(sorted(set([main_CN] + alt_names)))}"
    )


def validate_tls_info(tls_sock: ssl.SSLSocket) -> None:
    cert = tls_sock.getpeercert()
    if cert and tls_sock.server_hostname:
        check_cert_hostnames(cert, tls_sock.server_hostname)
        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")  # type: ignore
        if expiry < datetime.datetime.now():
            raise SSLCertificateError("SSL certificate expired")


def test_ssl_tls(
    hostname: str, ip: str, port: int, ssl_type: SSLEnum, nameservers: Optional[List[str]], timeout: float, parked: bool
) -> Dict[str, Any]:
    # important - some servers rejects EHLO if reverse hostname is invalid (eg. poczta.onet.pl)
    result: Dict[str, Any] = {
        "port": port,
        "error": None,
        "warning": None,
    }

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        if ssl_type == SSLEnum.IMPLICIT:
            # Implicit TLS — wrap socket immediately
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    result["connected"] = True
                    result["tls"] = True
                    validate_tls_info(tls_sock)
                    tls_sock.send(b"EHLO %s\r\n" % "127.0.0.1".encode())
                    welcome_banner = tls_sock.recv(1024).decode()
                    if "220" not in welcome_banner:
                        raise SSLInternalError("No welcome banner received on implicit TLS connection")
                    ehlo_response = tls_sock.recv(1024).decode()
                    if "250" not in ehlo_response:
                        raise SSLInternalError("No EHLO response received on implicit TLS connection")

                    tls_sock.send(b"STARTTLS\r\n")
                    starttls_response = tls_sock.recv(1024).decode()
                    # should trigger an error since STARTTLS is not expected on implicit TLS ports
                    if "220" in starttls_response:
                        raise SSLInternalError(
                            "Unexpected response to STARTTLS on implicit TLS connection (on implicit TLS connection, "
                            "the STARTTLS command should fail, as the connection is already encrypted, so the server "
                            "should respond with an error message)"
                        )
        else:
            # STARTTLS — connect plain, then upgrade
            with smtplib.SMTP(hostname, port, timeout=timeout) as smtp:
                result["connected"] = True
                smtp.ehlo()
                ehlo_response = smtp.ehlo_resp.decode() if smtp.ehlo_resp else None  # type: ignore
                if not ehlo_response:
                    raise SSLInternalError("No EHLO response received before STARTTLS")

                if smtp.has_extn("STARTTLS"):
                    smtp.starttls(context=context)

                    smtp.ehlo()
                    ehlo_response = smtp.ehlo_resp.decode() if smtp.ehlo_resp else None  # type: ignore
                    if not ehlo_response:
                        raise SSLInternalError("No EHLO response received after STARTTLS")

                    result["tls"] = True
                    tls_sock = smtp.sock  # type: ignore
                    validate_tls_info(tls_sock)
                else:
                    raise SSLInternalError(f"STARTTLS not supported on {hostname} MX server")

    except ssl.SSLCertVerificationError as e:
        result["connected"] = True
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
        if not parked:
            # ECONNREFUSED is OK for parked domains
            result["error"] = "Connection refused"
    except SSLInternalError as e:
        result["error"] = str(e)
    except TimeoutError:
        result["error"] = "Connection timed out"
    except smtplib.SMTPConnectError as e:
        # we ignore these as they are usually caused by the server not supporting SMTP or blocking scanner's IP address
        pass
    except Exception as e:
        result["error"] = str(e)

    return result


def validate_ssl(
    host: str, nameservers: Optional[List[str]], timeout: float, parked: bool, fallback_to_hostname: bool
) -> SSLScanResult:
    ports = {
        25: SSLEnum.STARTTLS,
        465: SSLEnum.IMPLICIT,
        587: SSLEnum.STARTTLS,
    }

    mx_records: List[Tuple[Optional[int], str]] = retrieve_MX_records(host, nameservers=nameservers)
    if not mx_records and fallback_to_hostname:
        mx_records = [(None, host)]

    if not mx_records:
        return SSLScanResult(
            valid=True,
            warnings=False,
            results=[],
        )

    results: List[SSLMXScanResult] = []

    def scan_mx(preference: Optional[int], port: int, ssl_type: SSLEnum, mx: str, ip: str) -> SSLMXScanResult:
        result_mx = test_ssl_tls(
            mx,
            ip,
            port,
            ssl_type,
            nameservers=nameservers,
            timeout=timeout,
            parked=parked,
        )
        return SSLMXScanResult(
            preference=preference,
            mx=mx,
            port=result_mx["port"],
            error=result_mx["error"],
            warning=result_mx["warning"],
            additional_info=result_mx.get("additional_info"),
        )

    results = []

    with ThreadPoolExecutor(max_workers=len(mx_records) * len(ports)) as executor:
        futures = []
        for preference, mx in mx_records:
            ip = None
            resolver = dns.resolver.Resolver()
            if nameservers:
                resolver.nameservers = nameservers
            try:
                answers = resolver.resolve(mx, "A")
                ip = answers[0].to_text()
            except Exception:
                try:
                    ip = socket.gethostbyname(mx)  # fallback
                except socket.gaierror:
                    results.append(
                        SSLMXScanResult(preference=preference, mx=mx, port=None, error="DNS resolution error")
                    )
                    continue

            for port, ssl_type in ports.items():
                future = executor.submit(scan_mx, preference, port, ssl_type, mx, ip)
                futures.append(future)

        mx_has_working_port: set[str] = set()
        for result in sorted(
            [item.result() for item in as_completed(futures)],
            key=lambda item: (item.preference, item.mx, item.port),
        ):
            if result.mx in mx_has_working_port:
                # Most important port has SSL/TLS accepted
                # Issue happens with google/outlook - Port 25 is working normally, but for 465, 587 raises network unreachable OSError
                continue

            if result.error is None:
                mx_has_working_port.add(result.mx)

            results.append(result)

    return SSLScanResult(
        valid=all(item.error is None for item in results),
        warnings=not all(item.warning is None for item in results),
        results=results,
    )
