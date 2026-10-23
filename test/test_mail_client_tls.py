import socket
import threading
from typing import List, Optional, Tuple
from unittest import TestCase
from unittest.mock import patch

from libmailgoose.mail_client_tls_check import (
    SRVRecord,
    parse_capabilities,
    retrieve_SRV_records,
    test_mail_client_tls,
)
from libmailgoose.ssl_check import SSLEnum


class FakeSRVAnswer:
    def __init__(self, priority: int, weight: int, port: int, target: str) -> None:
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = FakeName(target)


class FakeName:
    def __init__(self, name: str) -> None:
        self.name = name

    def to_text(self) -> str:
        return self.name


class FakeIMAPServer:
    """An IMAP server that speaks just enough of the protocol to be checked."""

    def __init__(self, capabilities: str) -> None:
        self.capabilities = capabilities
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return int(self.socket.getsockname()[1])

    def __enter__(self) -> "FakeIMAPServer":
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()
        self.thread.join(timeout=5)

    def _serve(self) -> None:
        try:
            connection, _ = self.socket.accept()
        except OSError:
            return

        with connection:
            connection.sendall(b"* OK IMAP4rev1 ready\r\n")
            buffer = b""
            while True:
                try:
                    chunk = connection.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return

                buffer += chunk
                while b"\r\n" in buffer:
                    line, buffer = buffer.split(b"\r\n", 1)
                    tag, command = line.decode("ascii").split(" ", 1)
                    if command.upper() == "CAPABILITY":
                        connection.sendall(f"* CAPABILITY {self.capabilities}\r\n".encode("ascii"))
                        connection.sendall(f"{tag} OK CAPABILITY completed\r\n".encode("ascii"))
                    else:
                        connection.sendall(f"{tag} BAD unsupported\r\n".encode("ascii"))


class RetrieveSRVRecordsTestCase(TestCase):
    def _retrieve(self, answers: List[FakeSRVAnswer]) -> List[SRVRecord]:
        with patch("dns.resolver.Resolver.resolve", return_value=answers):
            records: List[SRVRecord] = retrieve_SRV_records("example.com", "imaps")
        return records

    def test_records_are_sorted_by_priority_and_weight(self) -> None:
        self.assertEqual(
            self._retrieve(
                [
                    FakeSRVAnswer(20, 0, 993, "backup.example.com."),
                    FakeSRVAnswer(10, 1, 993, "second.example.com."),
                    FakeSRVAnswer(10, 5, 993, "first.example.com."),
                ]
            ),
            [
                SRVRecord(priority=10, weight=5, port=993, target="first.example.com"),
                SRVRecord(priority=10, weight=1, port=993, target="second.example.com"),
                SRVRecord(priority=20, weight=0, port=993, target="backup.example.com"),
            ],
        )

    def test_service_explicitly_not_available(self) -> None:
        # RFC 2782: a target of "." means the service is not available at this domain
        self.assertEqual(self._retrieve([FakeSRVAnswer(0, 0, 0, ".")]), [])

    def test_no_records(self) -> None:
        with patch("dns.resolver.Resolver.resolve", side_effect=Exception("NXDOMAIN")):
            self.assertEqual(retrieve_SRV_records("example.com", "imaps"), [])


class ParseCapabilitiesTestCase(TestCase):
    def test_capabilities_from_greeting(self) -> None:
        self.assertEqual(
            parse_capabilities(["* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] ready"]),
            {"IMAP4REV1", "STARTTLS", "LOGINDISABLED"},
        )

    def test_capabilities_from_response(self) -> None:
        self.assertEqual(
            parse_capabilities(["* CAPABILITY IMAP4rev1 STARTTLS", "* OK unrelated"]),
            {"IMAP4REV1", "STARTTLS"},
        )


class MailClientTLSTestCase(TestCase):
    def _check(self, capabilities: str) -> Tuple[Optional[str], Optional[str]]:
        with FakeIMAPServer(capabilities) as server:
            result = test_mail_client_tls("imap.example.com", "127.0.0.1", server.port, SSLEnum.STARTTLS, timeout=5.0)
        return result["error"], result["warning"]

    def test_starttls_not_supported(self) -> None:
        error, _ = self._check("IMAP4rev1")
        self.assertEqual(error, "STARTTLS not supported on imap.example.com IMAP server")

    def test_login_allowed_before_starttls(self) -> None:
        # The server does support STARTTLS, but allows logging in without it. The TLS handshake
        # itself will fail, as the fake server doesn't implement STARTTLS - we only check the warning.
        _, warning = self._check("IMAP4rev1 STARTTLS")
        self.assertEqual(
            warning,
            "The imap.example.com server doesn't advertise the LOGINDISABLED capability, therefore mail "
            "clients may send the user's password over an unencrypted connection.",
        )

    def test_connection_refused(self) -> None:
        # A port that has been bound but never listened on, so nothing can accept a connection
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])

        result = test_mail_client_tls("imap.example.com", "127.0.0.1", port, SSLEnum.STARTTLS, timeout=5.0)
        self.assertEqual(result["error"], "Connection refused")
