"""Domain ownership verification.

Before a public domain can be scanned its owner must prove control of it, by publishing a
random per-domain token either as a DNS TXT record or as a file under /.well-known/.
A verification is valid for a limited time and must then be repeated.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

RECORD_PREFIX = "scanner-verify="
WELL_KNOWN_PATH = "/.well-known/scanner-verify.txt"
DNS_SUBDOMAIN = "_scanner-verify"
METHODS = ("dns", "file")
LOOPBACK_METHOD = "loopback-exempt"
MAX_FILE_BYTES = 4096

TxtLookup = Callable[[str], list[str]]  # name -> TXT strings; raises LookupFailed
FileFetch = Callable[[str], tuple[int, str]]  # url -> (status, body); raises LookupFailed


class LookupFailed(Exception):  # noqa: N818
    """The DNS query or file request could not be completed. The message is safe to show."""


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    method: str
    detail: str


def new_token() -> str:
    """A unique, unguessable token for one domain."""
    return secrets.token_urlsafe(24)


def record_value(token: str) -> str:
    return f"{RECORD_PREFIX}{token}"


def instructions(host: str, token: str) -> dict[str, dict[str, str]]:
    return {
        "dns": {"type": "TXT", "name": host, "alt_name": f"{DNS_SUBDOMAIN}.{host}", "value": record_value(token)},
        "file": {"url": f"https://{host}{WELL_KNOWN_PATH}", "content": token},
    }


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "replace"), b.encode("utf-8", "replace"))


def check_dns(host: str, token: str, lookup: TxtLookup) -> VerificationResult:
    """Look for the TXT record on the domain itself or on _scanner-verify.<domain>."""
    expected = record_value(token)
    errors: list[str] = []
    for name in (host, f"{DNS_SUBDOMAIN}.{host}"):
        try:
            records = lookup(name)
        except LookupFailed as exc:
            errors.append(str(exc))
            continue
        if any(_same(record.strip().strip('"'), expected) for record in records):
            return VerificationResult(True, "dns", f"Found the TXT record on {name}.")
    if len(errors) == 2:
        return VerificationResult(False, "dns", f"The DNS lookup failed: {errors[0]}")
    return VerificationResult(
        False, "dns",
        "No matching TXT record was found. DNS changes can take a few minutes (sometimes hours) to appear. "
        "Check that the value matches exactly and try again.",
    )


def check_file(host: str, token: str, fetch: FileFetch) -> VerificationResult:
    """Fetch https://<host>/.well-known/scanner-verify.txt and compare its content with the token."""
    url = f"https://{host}{WELL_KNOWN_PATH}"
    try:
        status, body = fetch(url)
    except LookupFailed as exc:
        return VerificationResult(False, "file", str(exc))
    if 300 <= status < 400:
        return VerificationResult(
            False, "file", "The verification file address redirects elsewhere. It must be served directly, without a redirect."
        )
    if status != 200:
        return VerificationResult(False, "file", f"The verification file was not found (HTTP {status}).")
    content = body[:MAX_FILE_BYTES].strip()
    if _same(content, token) or _same(content, record_value(token)):
        return VerificationResult(True, "file", "Found the verification file with the correct token.")
    return VerificationResult(False, "file", "The verification file exists but does not contain the expected token.")


def expiry(verified_at: datetime, ttl_days: int) -> datetime:
    return verified_at + timedelta(days=ttl_days)


def status(verified_at: str | None, ttl_days: int, now: datetime | None = None) -> str:
    """"verified", "expired", or "unverified" for a stored ISO timestamp."""
    if not verified_at:
        return "unverified"
    try:
        when = datetime.fromisoformat(verified_at)
    except ValueError:
        return "unverified"
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return "verified" if (now or datetime.now(UTC)) < expiry(when, ttl_days) else "expired"


# --------------------------------------------------------------------------- live lookups


def live_txt_lookup(name: str) -> list[str]:
    """TXT records for ``name`` from the system resolver. A missing record is an empty list."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError as exc:
        raise LookupFailed("DNS verification needs the dnspython package.") from exc
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=10)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise LookupFailed("the DNS server did not answer in time. Try again in a moment.") from exc
    return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]


def make_file_fetch(limiters, resolver=None, timeout: float = 10.0) -> FileFetch:
    """A fetcher for the verification file: SSRF-checked, pinned, rate limited, and never follows redirects."""
    import http.client
    import ssl
    from urllib.parse import urlsplit

    from webscan.web.fetcher import pinned_get
    from webscan.web.netguard import BlockedAddressError, ResolutionError, resolve_public

    def fetch(url: str) -> tuple[int, str]:
        host = urlsplit(url).hostname or ""
        try:
            ip = (resolve_public(host, resolver) if resolver else resolve_public(host))[0]
        except ResolutionError as exc:
            raise LookupFailed(f"{host} could not be found in DNS. Check the spelling.") from exc
        except BlockedAddressError as exc:
            raise LookupFailed(str(exc)) from exc
        limiters.get(host).acquire()
        try:
            response = pinned_get(url, ip, timeout, max_bytes=MAX_FILE_BYTES)
        except ssl.SSLCertVerificationError as exc:
            raise LookupFailed(f"{host} has an invalid HTTPS certificate, so the file could not be checked. "
                               "Use the DNS method instead.") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise LookupFailed(f"{host} could not be reached over HTTPS. Check that the site is online.") from exc
        return response.status, response.body

    return fetch
