import dataclasses
import datetime
import enum
import smtplib
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import dns.resolver


class SSLEnum(enum.Enum):
    IMPLICIT = "Implicit TLS"
    STARTTLS = "STARTTLS"


@dataclasses.dataclass
class SSLMXScanResult:
    mx: str
    port: Optional[int]
    error: Optional[str] = None


@dataclasses.dataclass
class SSLScanResult:
    valid: bool
    results: List[SSLMXScanResult]


class SSLInternalError(Exception):
    pass


def retrieve_MX_records(domain: str, nameservers: Optional[List[str]] = None) -> List[str]:
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers

    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted([(int(r.preference), r.exchange.to_text()) for r in answers])
        return [r[1].rstrip(".") for r in mx_records]
    except Exception:
        return []


def check_cert_name(cn: str, hostname: str) -> bool:
    if cn.startswith("*."):
        return hostname.endswith(cn[1:])
    return cn == hostname


def check_cert_hostnames(cert: Dict[str, Any], hostname: str) -> bool:
    main_CN = dict(x[0] for x in cert["subject"]).get("commonName", "")
    if check_cert_name(main_CN, hostname):
        return True

    alt_names = [x[1] for x in cert.get("subjectAltName", [])]
    for alt_name in alt_names:
        if check_cert_name(alt_name, hostname):
            return True
    raise SSLInternalError(f"Certificate hostname mismatch: {hostname} not found in CN or SANs")


def validate_tls_info(tls_sock: ssl.SSLSocket) -> None:
    cert = tls_sock.getpeercert()
    if cert and tls_sock.server_hostname:
        check_cert_hostnames(cert, tls_sock.server_hostname)
        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")  # type: ignore
        if expiry < datetime.datetime.now():
            raise SSLInternalError("SSL certificate expired")


def test_ssl_tls(hostname: str, nameservers: Optional[List[str]] = None, timeout: float = 5.0) -> List[Dict[str, Any]]:
    # important - some servers rejects EHLO if reverse hostname is invalid (eg. poczta.onet.pl)
    ports = {
        25: SSLEnum.STARTTLS,
        465: SSLEnum.IMPLICIT,
        587: SSLEnum.STARTTLS,
    }

    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    try:
        answers = resolver.resolve(hostname, "A")
        ip = answers[0].to_text()
    except Exception:
        try:
            ip = socket.gethostbyname(hostname)  # fallback
        except socket.gaierror:
            return [{"port": None, "error": "DNS resolution error"}]

    results = []

    for port, ssl_type in ports.items():
        result: Dict[str, Any] = {
            "port": port,
            "error": None,
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
                            raise SSLInternalError("Unexpected response to STARTTLS on implicit TLS connection")
            else:
                # STARTTLS — connect plain, then upgrade
                with smtplib.SMTP(hostname, port, timeout=5) as smtp:
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
            result["error"] = f"Certificate error: {e.verify_message}"
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
        except SSLInternalError as e:
            result["error"] = str(e)
        except TimeoutError:
            result["error"] = "Connection timed out"
        except Exception as e:
            result["error"] = str(e)

        results.append(result)
        # Most important port has SSL/TLS accepted
        # Issue happens with google/outlook - Port 25 is working normally, but for 465, 587 raises network unreachable OSError
        if result["error"] is None:
            break

    return results


def validate_ssl(host: str, nameservers: Optional[List[str]], timeout: float = 5.0) -> SSLScanResult:
    mx_records = retrieve_MX_records(host, nameservers=nameservers)
    if not mx_records:
        mx_records = [host]

    results: List[SSLMXScanResult] = []

    def scan_mx(mx: str) -> List[SSLMXScanResult]:
        results_mx = test_ssl_tls(
            mx,
            nameservers=nameservers,
            timeout=timeout,
        )

        return [SSLMXScanResult(mx=mx, port=result_mx["port"], error=result_mx["error"]) for result_mx in results_mx]

    with ThreadPoolExecutor(max_workers=len(mx_records)) as executor:
        futures = {executor.submit(scan_mx, mx): mx for mx in mx_records}

        for future in as_completed(futures):
            results.extend(future.result())

    return SSLScanResult(
        valid=all(item.error is None for item in results),
        results=results,
    )
