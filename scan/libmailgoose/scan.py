import datetime
import io
import string
import subprocess
from dataclasses import dataclass, field
from email import message_from_file
from email.message import Message as EmailMessage
from typing import Any, Callable, Dict, List, Optional

import checkdmarc.dmarc
import checkdmarc.smtp
import checkdmarc.utils
import dkim
import dkim.dnsplug
import dkim.util
import dns.exception
import dns.resolver
import publicsuffixlist
import spf
import validators

from . import lax_record_query
from .logging import build_logger

checkdmarc.utils.DNS_CACHE.max_age = 1
checkdmarc.smtp.TLS_CACHE.max_age = 1
checkdmarc.smtp.STARTTLS_CACHE.max_age = 1

psl = publicsuffixlist.PublicSuffixList()

LOGGER = build_logger(__name__)


@dataclass
class SPFScanResult:
    record: Optional[str]
    record_candidates: Optional[List[str]]
    valid: bool
    errors: List[str]
    warnings: List[str]
    # As these errors are interpreted in a special way by downstream tools,
    # let's have flags (not only string messages) whether they happened.
    record_not_found: bool
    record_could_not_be_fully_validated: bool = False


@dataclass
class DMARCScanResult:
    location: Optional[str]
    record: Optional[str]
    record_candidates: Optional[List[str]]
    valid: bool
    errors: List[str]
    warnings: List[str]
    # As this error is interpreted in a special way by downstream tools,
    # let's have a flag (not only string message) whether it happened.
    record_not_found: bool = False
    tags: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainScanResult:
    spf: SPFScanResult
    dmarc: DMARCScanResult
    domain: str
    base_domain: str
    warnings: List[str]
    spf_not_required_because_of_correct_dmarc: bool = False


@dataclass
class DKIMScanResult:
    valid: bool
    errors: List[str]
    warnings: List[str]


@dataclass
class ScanResult:
    domain: Optional[DomainScanResult]
    dkim: Optional[DKIMScanResult]
    timestamp: Optional[datetime.datetime]
    message_timestamp: Optional[datetime.datetime]

    @property
    def num_checked_mechanisms(self) -> int:
        result = 0
        if self.domain:
            result += 2
        if self.dkim:
            result += 1
        return result

    @property
    def num_correct_mechanisms(self) -> int:
        result = 0
        for mechanism in self.mechanisms:
            if mechanism.valid and not mechanism.warnings:
                result += 1
        return result

    @property
    def has_not_valid_mechanisms(self) -> int:
        for mechanism in self.mechanisms:
            if not mechanism.valid:
                return True
        return False

    @property
    def mechanisms(self) -> List[Any]:
        mechanisms: List[Any] = []
        if self.domain:
            mechanisms.append(self.domain.spf)
            mechanisms.append(self.domain.dmarc)

        if self.dkim:
            mechanisms.append(self.dkim)
        return mechanisms


class ScanningException(Exception):
    def __init__(self, message: str) -> None:
        self.message = message


class DomainValidationException(Exception):
    def __init__(self, message: str):
        self.message = message


def validate_and_sanitize_domain(domain: str) -> str:
    domain = domain.lower().strip(" .")

    for space in string.whitespace:
        if space in domain:
            raise DomainValidationException("Whitespace in domain name detected. Please provide a correct domain name.")
    for forbidden_character in set(string.punctuation) - {".", "-", "_"}:
        if forbidden_character in domain:
            raise DomainValidationException(
                f"Unexpected character in domain detected: {forbidden_character}. Please provide a correct domain name."
            )

    result = validators.domain(domain, rfc_2782=True)
    if isinstance(result, validators.ValidationError):
        raise DomainValidationException("Please provide a correct domain name.")

    return domain


def check_alignment(
    parsed_dmarc_record: Dict[str, Any],
    tag_name: str,
    other_domain: str,
    from_domain: str,
) -> bool:
    from_domain = from_domain.encode("idna").decode("ascii")
    other_domain = other_domain.encode("idna").decode("ascii")

    if tag_name not in parsed_dmarc_record["tags"]:
        # The default value, if no aspf/adkim tag is provided, is for the alignment to be relaxed
        relaxed = True
    else:
        tag_value = parsed_dmarc_record["tags"][tag_name]["value"]

        if tag_value not in ["r", "s"]:
            raise checkdmarc.dmarc.DMARCSyntaxError(f"Unknown {tag_name} value: {tag_value}.")
        relaxed = tag_value == "r"

    if relaxed:
        return psl.privatesuffix(from_domain) == psl.privatesuffix(other_domain)  # type: ignore
    else:
        return from_domain == other_domain


def check_spf_alignment(parsed_dmarc_record: Dict[str, Any], spf_domain: str, from_domain: str) -> bool:
    return check_alignment(parsed_dmarc_record, "aspf", spf_domain, from_domain)


def check_dkim_alignment(parsed_dmarc_record: Dict[str, Any], dkim_domain: str, from_domain: str) -> bool:
    return check_alignment(parsed_dmarc_record, "adkim", dkim_domain, from_domain)


def contains_spf_all_fail(parsed: Dict[str, Any]) -> bool:
    if parsed["all"] in ["softfail", "fail"]:
        return True
    if "redirect" in parsed and parsed["redirect"]:
        return contains_spf_all_fail(parsed["redirect"]["parsed"])
    return False


def scan_domain(
    envelope_domain: str,
    from_domain: str,
    dkim_domain: Optional[str],
    message_sender_ip: Optional[bytes] = None,
    parked: bool = False,
    nameservers: Optional[List[str]] = None,
    include_dmarc_tag_descriptions: bool = False,
    timeout: float = 5.0,
    ignore_void_dns_lookups: bool = False,
) -> DomainScanResult:
    envelope_domain = validate_and_sanitize_domain(envelope_domain)
    from_domain = validate_and_sanitize_domain(from_domain)

    if dkim_domain:
        dkim_domain = validate_and_sanitize_domain(dkim_domain)

    warnings = []

    domains_to_check = [envelope_domain, from_domain]
    if dkim_domain:
        domains_to_check.append(dkim_domain)

    for domain in domains_to_check:
        # We glue example-subdomain. to the domain due to the behavior of the publicsuffixlist library - if
        # accept_unknown is False, the publicsuffix() of a *known* TLD would be None.
        if psl.publicsuffix("example-subdomain." + domain, accept_unknown=False) == domain:
            warnings.append(
                "Requested to scan a domain that is a public suffix, i.e. a domain such as .com where anybody could "
                "register their subdomain. Such domain don't have to have properly configured e-mail sender verification "
                "mechanisms. Please make sure you really wanted to check such domain and not its subdomain.",
            )
        elif psl.publicsuffix("example-subdomain." + domain) == domain:
            warnings.append(
                "Requested to scan a top-level domain. Top-level domains don't have to have properly configured e-mail sender "
                "verification mechanisms. Please make sure you really wanted to check such domain and not its subdomain."
                "Besides, the domain is not known to the Public Suffix List (https://publicsuffix.org/) - please verify whether "
                "it is correct.",
            )

    warnings = sorted(set(warnings))

    domain_result = DomainScanResult(
        spf=SPFScanResult(
            record=None,
            record_candidates=None,
            valid=True,
            record_not_found=False,
            record_could_not_be_fully_validated=False,
            errors=[],
            warnings=[],
        ),
        dmarc=DMARCScanResult(
            record=None,
            record_not_found=False,
            record_candidates=None,
            valid=True,
            location=None,
            errors=[],
            warnings=[],
        ),
        domain=domain,
        base_domain=checkdmarc.get_base_domain(domain),
        warnings=warnings,
    )

    try:
        spf_query = checkdmarc.spf.query_spf_record(envelope_domain, nameservers=nameservers, timeout=timeout)

        domain_result.spf.record = spf_query["record"]
        if domain_result.spf.record and "%" in domain_result.spf.record:
            domain_result.spf.warnings = ["SPF records containing macros aren't supported by the system yet."]
            domain_result.spf.record_could_not_be_fully_validated = True
        elif not domain_result.spf.record:
            raise checkdmarc.spf.SPFRecordNotFound(None)
        else:
            domain_result.spf.warnings = spf_query["warnings"]

            try:
                parsed_spf = checkdmarc.spf.parse_spf_record(
                    domain_result.spf.record,
                    domain_result.domain,
                    parked=parked,
                    nameservers=nameservers,
                    timeout=timeout,
                )
                domain_result.spf.warnings = list(set(domain_result.spf.warnings) | set(parsed_spf["warnings"]))

                if not contains_spf_all_fail(parsed_spf["parsed"]):
                    domain_result.spf.errors = [
                        "SPF '~all' or '-all' directive not found. We recommend adding it, as it describes "
                        "what should happen with messages that fail SPF verification. For example, "
                        "'-all' will tell the recipient server to drop such messages."
                    ]
            except checkdmarc.spf.SPFRecordNotFound as e:
                # This is a different type from standard SPFRecordNotFound - it occurs
                # during *parsing*, so it is not caused by lack of SPF record, but
                # a malformed one (e.g. including a domain that doesn't have an SPF record).
                domain_result.spf.errors = [
                    f"The SPF record's include chain has a reference to the {e.domain} domain that doesn't "
                    "have an SPF record. When using directives such as 'include' or 'redirect' remember "
                    "that the destination domain must have a correct SPF record.",
                ]

        if message_sender_ip:
            message_sender_ip_s = message_sender_ip.decode("ascii")
            spf_check_result = spf.query(message_sender_ip_s, envelope_domain, None).check()
            if spf_check_result[0] in ("softfail", "fail"):
                domain_result.spf.errors.append(
                    f"The IP address {message_sender_ip_s} from which the message was received "
                    f"is not authorized by the domain's SPF policy to send messages."
                )
    except checkdmarc.spf.SPFRecordNotFound as e:
        # https://github.com/domainaware/checkdmarc/issues/90
        if isinstance(e.args[0], dns.exception.DNSException):
            raise ScanningException(e.args[0].msg if e.args[0].msg else repr(e.args[0]))

        if isinstance(e.args[0], checkdmarc.spf.MultipleSPFRTXTRecords):
            domain_result.spf.errors = [
                "Multiple SPF records found. We recommend leaving only one, as multiple SPF records "
                "can cause problems with some SPF implementations.",
            ]
        else:
            # Sometimes an entry pretending to be an SPF record exists (e.g. something
            # beginning with [space]v=spf1) so to avoid communication problems
            # with the user we tell them that we didn't find a valid one.
            domain_result.spf.errors = [
                "Valid SPF record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
                "to decrease the possibility of successful e-mail message spoofing.",
            ]
            domain_result.spf.record_not_found = True
    except checkdmarc.spf.SPFTooManyVoidDNSLookups:
        if not ignore_void_dns_lookups:
            domain_result.spf.errors = [
                "SPF record causes too many void DNS lookups. Some implementations may require the number of "
                "failed DNS lookups (e.g. ones that reference a nonexistent domain) to be low. The DNS lookups "
                "are caused by directives such as 'mx' or 'include'.",
            ]
    except checkdmarc.spf.SPFIncludeLoop:
        domain_result.spf.errors = [
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain."
        ]
    except checkdmarc.spf.SPFRedirectLoop:
        domain_result.spf.errors = [
            "SPF record includes an endless loop. Please check whether 'include' or 'redirect' directives don't "
            "create a loop where a domain redirects back to itself or earlier domain."
        ]
    except checkdmarc.spf.SPFSyntaxError as e:
        # We put here the original exception message from checkdmarc (e.g. "example.com: Expected mechanism
        # at position 42 (marked with ➞) in: (...)") as it contains information that is helpful to debug the syntax error.
        domain_result.spf.errors = [e.args[0]]
    except checkdmarc.spf.SPFTooManyDNSLookups:
        domain_result.spf.errors = [
            "SPF record causes too many DNS lookups. The DNS lookups are caused by directives such as 'mx' or 'include'. "
            "The specification requires the number of DNS lookups to be lower or equal to 10 to decrease load on DNS servers.",
        ]

    domain_result.spf.valid = len(domain_result.spf.errors) == 0

    # DMARC
    try:
        dmarc_warnings = []
        # According to Section 6.6.1 of RFC7489 (https://datatracker.ietf.org/doc/html/rfc7489):
        # If the domain is encoded with UTF-8, the domain name must be converted to an A-label, as described
        # in Section 2.3 of [IDNA], for further processing.
        from_domain = from_domain.encode("idna").decode("ascii")

        try:
            dmarc_query = checkdmarc.dmarc.query_dmarc_record(from_domain, nameservers=nameservers, timeout=timeout)
        except checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC:
            dmarc_warnings.append(
                "Unrelated TXT record found in the '_dmarc' subdomain. We recommend removing it, as such unrelated "
                "records may cause problems with some DMARC implementations.",
            )
            dmarc_query = checkdmarc.dmarc.query_dmarc_record(
                domain,
                nameservers=nameservers,
                timeout=timeout,
                ignore_unrelated_records=True,
            )

        except Exception as e:
            raise e
        domain_result.dmarc.record = dmarc_query["record"]
        if not domain_result.dmarc.record:
            raise checkdmarc.dmarc.DMARCRecordNotFound(None)

        domain_result.dmarc.location = dmarc_query["location"]

        try:
            parsed_dmarc_record = checkdmarc.dmarc.parse_dmarc_record(
                dmarc_query["record"],
                dmarc_query["location"],
                parked=parked,
                include_tag_descriptions=include_dmarc_tag_descriptions,
                nameservers=nameservers,
                timeout=timeout,
            )
        except checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC as e:
            dmarc_warnings.append(
                f"Unrelated TXT record found in a domain the record refers to: {e.data['target']}. "
                "We recommend removing it, as such unrelated records may cause problems with some DMARC "
                "implementations.",
            )
            parsed_dmarc_record = checkdmarc.dmarc.parse_dmarc_record(
                dmarc_query["record"],
                dmarc_query["location"],
                parked=parked,
                include_tag_descriptions=include_dmarc_tag_descriptions,
                ignore_unrelated_records=True,
                nameservers=nameservers,
                timeout=timeout,
            )

        if not check_spf_alignment(parsed_dmarc_record, envelope_domain, from_domain):
            domain_result.dmarc.errors.append(
                f"Domain checked by the SPF mechanism (from the RFC5321.MailFrom header: {envelope_domain}) is not "
                f"aligned with the DMARC record domain (from the RFC5322.From header: {from_domain}). Read more "
                "about various e-mail From headers on https://dmarc.org/2016/07/how-many-from-addresses-are-there/"
            )
        if dkim_domain:
            if not check_dkim_alignment(parsed_dmarc_record, dkim_domain, from_domain):
                domain_result.dmarc.errors.append(
                    f"Domain from the DKIM signature ({dkim_domain}) is not aligned with the DMARC record domain "
                    f"(from the From header: {from_domain})."
                )

        if parsed_dmarc_record["tags"]["p"]["value"] == "none":
            if "rua" not in parsed_dmarc_record["tags"] and "ruf" not in parsed_dmarc_record["tags"]:
                domain_result.dmarc.errors.append(
                    "DMARC policy is 'none' and 'rua'/'ruf' is not set, which means that the DMARC setting is not effective. "
                    "The 'rua'/'ruf' settings don't influence the blocking behavior, but allows you to receive reports "
                    "that will allow you to learn whether the DMARC mechanism works properly and whether it's possible "
                    "to change the policy to 'quarantine' or 'reject'."
                )
            else:
                dmarc_warnings.append(
                    "DMARC policy is 'none', which means that besides reporting no action will be taken. \n\n"
                    "The policy describes what action the recipient server should take when noticing a message "
                    "that doesn't pass the verification. 'quarantine' policy suggests the recipient server to "
                    "flag the message as spam and 'reject' policy suggests the recipient server to reject the "
                    "message. We recommend using the 'quarantine' or 'reject' policy.\n\n"
                    "When testing the DMARC mechanism, to minimize the risk of correct messages not being delivered, "
                    "the 'none' policy may be used. Such tests are recommended especially when the domain is used to "
                    "send a large number of e-mails using various tools and not delivering a correct message is "
                    "unacceptable. In such cases the reports should be closely monitored, and the target setting should "
                    "be 'quarantine' or 'reject'."
                )
        elif (
            parsed_dmarc_record["tags"]["sp"]["value"] == "none"
        ):  # "elif" because we don't want to report the same problem for subdomains if p=none
            if "rua" not in parsed_dmarc_record["tags"]:
                domain_result.dmarc.errors.append(
                    "DMARC subdomain policy is 'none' and 'rua' is not set, which means that the DMARC setting is not effective for subdomains."
                )
            else:
                dmarc_warnings.append(
                    "DMARC subdomain policy is 'none', which means that besides reporting no action will be taken for e-mails coming from subdomains.\n\n"
                    "The policy describes what action the recipient server should take when noticing a message "
                    "that doesn't pass the verification. 'quarantine' policy suggests the recipient server to "
                    "flag the message as spam and 'reject' policy suggests the recipient server to reject the "
                    "message. We recommend using the 'quarantine' or 'reject' policy.\n\n"
                    "When testing the DMARC mechanism, to minimize the risk of correct messages not being delivered, "
                    "the 'none' policy may be used. Such tests are recommended especially when the domain is used to "
                    "send a large number of e-mails using various tools and not delivering a correct message is "
                    "unacceptable. In such cases the reports should be closely monitored, and the target setting should "
                    "be 'quarantine' or 'reject'."
                )

        domain_result.dmarc.tags = parsed_dmarc_record["tags"]
        domain_result.dmarc.warnings = list(
            set(dmarc_query["warnings"]) | set(parsed_dmarc_record["warnings"]) | set(dmarc_warnings)
        )
    except checkdmarc.dmarc.DMARCRecordNotFound as e:
        # https://github.com/domainaware/checkdmarc/issues/90
        if isinstance(e.args[0], dns.exception.DNSException):
            raise ScanningException(e.args[0].msg if e.args[0].msg else repr(e.args[0]))

        # Sometimes an entry pretending to be a DMARC record exists so to avoid
        # communication problems with the user we tell them that we
        # didn't find a valid one.
        domain_result.dmarc.errors = [
            "Valid DMARC record not found. We recommend using all three mechanisms: SPF, DKIM and DMARC "
            "to decrease the possibility of successful e-mail message spoofing.",
        ]
        domain_result.dmarc.record_not_found = True
    except checkdmarc.dmarc.DMARCRecordInWrongLocation as e:
        # We put here the original exception message from checkdmarc ("The DMARC record must be located at {0},
        # not {1}") as it contains the domain names describing the expected and actual location.
        domain_result.dmarc.errors = [e.args[0]]
    except checkdmarc.dmarc.MultipleDMARCRecords:
        domain_result.dmarc.errors = [
            "There are multiple DMARC records. We recommend leaving only one, as multiple "
            "DMARC records can cause problems with some DMARC implementations.",
        ]
    except checkdmarc.dmarc.SPFRecordFoundWhereDMARCRecordShouldBe:
        domain_result.dmarc.errors = [
            "There is an SPF record instead of DMARC one on the '_dmarc' subdomain.",
        ]
    except checkdmarc.dmarc.DMARCRecordStartsWithWhitespace:
        domain_result.dmarc.errors = [
            "Found a DMARC record that starts with whitespace. "
            "Please remove the whitespace, as some implementations may not "
            "process it correctly."
        ]
    except checkdmarc.dmarc.DMARCSyntaxError as e:
        # We put here the original exception message from checkdmarc (e.g. "the p tag must immediately follow
        # the v tag") as it contains information that is helpful to debug the syntax error.
        domain_result.dmarc.errors = [e.args[0]]
    except checkdmarc.dmarc.InvalidDMARCTag:
        domain_result.dmarc.errors = [
            "DMARC record uses an invalid tag. Please refer to https://datatracker.ietf.org/doc/html/rfc7489#section-6.3 "
            "for the list of available tags."
        ]
    except checkdmarc.dmarc.InvalidDMARCReportURI:
        domain_result.dmarc.errors = [
            "DMARC report URI is invalid. The report URI should be an e-mail address prefixed with mailto:.",
        ]
    except checkdmarc.dmarc.UnverifiedDMARCURIDestination:
        domain_result.dmarc.errors = [
            "The destination of a DMARC report URI does not indicate that it accepts reports for the domain."
        ]
    except checkdmarc.dmarc.DMARCReportEmailAddressMissingMXRecords:
        domain_result.dmarc.errors = [
            "The domain of the email address in a DMARC report URI is missing MX records. That means, that this domain "
            "may not receive DMARC reports."
        ]

    # If policy is none, it will be saved as a separate error. If policy is quarantine or reject, this is
    # optional as the messages that don't pass dmarc are blocked or quarantined.
    #
    # We can match on string equality as we have unittests for that so if something changes in the library
    # we'll detect it.
    domain_result.dmarc.warnings = [
        warning
        for warning in domain_result.dmarc.warnings
        if warning != "rua/ruf tag (destination for aggregate/failure reports) not found"
    ]

    domain_result.dmarc.valid = len(domain_result.dmarc.errors) == 0

    if not domain_result.spf.record:
        try:
            domain_result.spf.record_candidates = lax_record_query.lax_query_spf_record(envelope_domain)
        # If we are unable to retrieve the candidates, let's keep them empty, as the check result is more important.
        except Exception:
            pass

    if not domain_result.dmarc.record:
        try:
            domain_result.dmarc.record_candidates = lax_record_query.lax_query_dmarc_record(from_domain)
        # If we are unable to retrieve the candidates, let's keep them empty, as the check result is more important.
        except Exception:
            pass

    domain_result.spf_not_required_because_of_correct_dmarc = (
        domain_result.spf is not None
        and domain_result.spf.record_not_found
        and domain_result.dmarc is not None
        and bool(domain_result.dmarc.record)
        and domain_result.dmarc.valid
        and len(domain_result.dmarc.warnings) == 0
        and domain_result.dmarc.tags is not None
        and "p" in domain_result.dmarc.tags
        and domain_result.dmarc.tags["p"]["value"] in ["quarantine", "reject"]
    )
    if domain_result.spf_not_required_because_of_correct_dmarc:
        domain_result.spf.valid = True

    return domain_result


def scan_dkim(
    message: bytes,
    message_parsed: EmailMessage,
    dkim_implementation_mismatch_callback: Optional[Callable[[bytes, bool, bool], None]] = None,
) -> DKIMScanResult:
    if "dkim-signature" not in message_parsed:
        return DKIMScanResult(
            valid=False,
            errors=["No DKIM signature found"],
            warnings=[],
        )

    opendkim_valid = subprocess.run(["opendkim-testmsg"], input=message).returncode == 0

    try:
        # We don't call dkim.verify() directly because it would catch dkim.DKIMException
        # for us, thus not allowing to translate the message.
        d = dkim.DKIM(message)
        signature_tags, _, _ = d.verify_headerprep()

        LOGGER.info("DKIM signature tags: %s", repr(signature_tags))
        if b"l" in signature_tags or "l" in signature_tags:
            # https://www.zone.eu/blog/2024/05/17/bimi-and-dmarc-cant-save-you/
            warnings = [
                "Using the DKIM body length tag (l=) is not recommended, as it may allow an attacker to add own content to "
                "the e-mail, and, in some cases, completely override it."
            ]
        else:
            warnings = []

        selector_full_name = signature_tags[b"s"] + b"._domainkey." + signature_tags[b"d"] + b"."
        if dkim_record_raw := dkim.dnsplug.get_txt(selector_full_name):
            try:
                dkim_record_tags = dkim.util.parse_tag_value(dkim_record_raw)
            except dkim.util.InvalidTagSpec as e:
                raise dkim.DKIMException(
                    "The DKIM DNS record contains an invalid tag: " + e.args[0].decode("ascii", errors="replace")
                )
            except dkim.util.DuplicateTag as e:
                raise dkim.DKIMException(
                    "The DKIM DNS record contains an duplicate tag: " + e.args[0].decode("ascii", errors="replace")
                )
            if acceptable_hash_algorithms_raw := dkim_record_tags.get(b"h"):
                acceptable_hash_algorithms: List[bytes] = acceptable_hash_algorithms_raw.split(b",")
                for acceptable_hash_algorithm in acceptable_hash_algorithms:
                    if acceptable_hash_algorithm not in (b"sha1", b"sha256"):
                        warnings.append(
                            "The DKIM acceptable hash algorithms tag (h=) in the DNS record contains an unsupported hash "
                            "algorithm: " + acceptable_hash_algorithm.decode()
                        )

        dkimpy_valid = d.verify()

        LOGGER.info(
            "DKIM libraries opinion: dkimpy=%s, opendkim=%s",
            dkimpy_valid,
            opendkim_valid,
        )
        if dkimpy_valid != opendkim_valid and dkim_implementation_mismatch_callback:
            dkim_implementation_mismatch_callback(message, dkimpy_valid, opendkim_valid)

        if dkimpy_valid:
            return DKIMScanResult(
                valid=True,
                errors=[],
                warnings=warnings,
            )
        else:
            return DKIMScanResult(
                valid=False,
                errors=["Found an invalid DKIM signature"],
                warnings=warnings,
            )
    except (dkim.DKIMException, dns.exception.DNSException) as e:
        LOGGER.info(
            "DKIM libraries opinion: dkimpy=False, opendkim=%s",
            opendkim_valid,
        )
        if opendkim_valid and dkim_implementation_mismatch_callback:
            dkim_implementation_mismatch_callback(message, False, opendkim_valid)

        if e.args[0]:
            return DKIMScanResult(
                valid=False,
                errors=[e.args[0]],
                warnings=[],
            )
        else:
            LOGGER.exception("Error during DKIM signature validation")

            return DKIMScanResult(
                valid=False,
                errors=["An unknown error occured during DKIM signature validation."],
                warnings=[],
            )


def scan(
    envelope_domain: str,
    from_domain: str,
    dkim_domain: Optional[str],
    message: Optional[bytes],
    message_sender_ip: Optional[bytes],
    message_timestamp: Optional[datetime.datetime],
    nameservers: Optional[List[str]] = None,
    dkim_implementation_mismatch_callback: Optional[Callable[[bytes, bool, bool], None]] = None,
) -> ScanResult:
    if message:
        stream = io.StringIO(message.decode("utf-8", errors="ignore"))
        message_parsed = message_from_file(stream)
    else:
        message_parsed = None

    return ScanResult(
        domain=scan_domain(
            envelope_domain=envelope_domain,
            from_domain=from_domain,
            dkim_domain=dkim_domain,
            message_sender_ip=message_sender_ip,
            nameservers=nameservers,
        ),
        dkim=(
            scan_dkim(
                message=message,
                message_parsed=message_parsed,
                dkim_implementation_mismatch_callback=dkim_implementation_mismatch_callback,
            )
            if message and message_parsed
            else None
        ),
        timestamp=datetime.datetime.now(),
        message_timestamp=message_timestamp,
    )
