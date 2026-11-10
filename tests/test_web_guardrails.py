"""Web UI guardrails: ownership verification, private-address blocking, and rate limiting."""

from __future__ import annotations

import socket
import threading
from datetime import UTC, datetime, timedelta

import pytest

from webscan.web import verification
from webscan.web.netguard import (
    BlockedAddressError,
    ResolutionError,
    TargetError,
    is_blocked_ip,
    parse_scan_target,
    resolve_public,
    resolve_target,
)
from webscan.web.ratelimit import RateLimiter, ScanBusyError, ScanGate
from webscan.web.settings import WebConfigError, WebSettings

# ------------------------------------------------------------------ verification


def test_tokens_are_unique_and_long():
    tokens = {verification.new_token() for _ in range(200)}
    assert len(tokens) == 200 and all(len(t) >= 32 for t in tokens)


def test_instructions_name_both_methods():
    info = verification.instructions("example.org", "tok123")
    assert info["dns"] == {
        "type": "TXT", "name": "example.org", "alt_name": "_scanner-verify.example.org",
        "value": "scanner-verify=tok123",
    }
    assert info["file"] == {"url": "https://example.org/.well-known/scanner-verify.txt", "content": "tok123"}


def test_dns_verification_accepts_exact_record_on_either_name():
    records = {"example.org": ["v=spf1 -all", "scanner-verify=tok123"], "_scanner-verify.example.org": []}
    assert verification.check_dns("example.org", "tok123", lambda name: records[name]).ok
    records = {"example.org": [], "_scanner-verify.example.org": ['"scanner-verify=tok123"']}
    assert verification.check_dns("example.org", "tok123", lambda name: records[name]).ok


@pytest.mark.parametrize("record", ["scanner-verify=other", "scanner-verify=tok1234", "tok123", "xscanner-verify=tok123", ""])
def test_dns_verification_rejects_wrong_records(record):
    result = verification.check_dns("example.org", "tok123", lambda _name: [record])
    assert not result.ok and "No matching TXT record" in result.detail


def test_dns_verification_reports_lookup_failure():
    def broken(_name):
        raise verification.LookupFailed("the DNS server did not answer in time.")

    result = verification.check_dns("example.org", "tok123", broken)
    assert not result.ok and "DNS lookup failed" in result.detail


def test_file_verification_requires_the_token_served_directly():
    seen = []

    def fetch(url, status=200, body="tok123\n"):
        seen.append(url)
        return status, body

    assert verification.check_file("example.org", "tok123", fetch).ok
    assert seen == ["https://example.org/.well-known/scanner-verify.txt"]
    assert verification.check_file("example.org", "tok123", lambda u: (200, "scanner-verify=tok123")).ok
    assert not verification.check_file("example.org", "tok123", lambda u: (200, "<html>tok123</html>")).ok
    assert "not found" in verification.check_file("example.org", "tok123", lambda u: (404, "tok123")).detail
    assert "redirect" in verification.check_file("example.org", "tok123", lambda u: (301, "tok123")).detail


def test_file_verification_reports_unreachable_site():
    def fetch(_url):
        raise verification.LookupFailed("example.org could not be reached over HTTPS.")

    result = verification.check_file("example.org", "tok123", fetch)
    assert not result.ok and "could not be reached" in result.detail


def test_verification_expires_after_ttl():
    now = datetime(2026, 6, 1, tzinfo=UTC)
    fresh = (now - timedelta(days=29, hours=23)).isoformat()
    stale = (now - timedelta(days=30, seconds=1)).isoformat()
    assert verification.status(fresh, 30, now) == "verified"
    assert verification.status(stale, 30, now) == "expired"
    assert verification.status(None, 30, now) == "unverified"
    assert verification.status("not-a-date", 30, now) == "unverified"


# ------------------------------------------------------------------ private-IP blocking


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.1.1", "169.254.169.254",
        "127.0.0.1", "127.8.8.8", "0.0.0.0", "100.64.0.1", "224.0.0.1", "255.255.255.255", "192.0.2.10",
        "::1", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1",
        "not-an-ip",
    ],
)
def test_private_and_internal_addresses_are_blocked(address):
    assert is_blocked_ip(address)


@pytest.mark.parametrize("address", ["93.184.216.34", "1.1.1.1", "172.32.0.1", "172.15.255.255", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address):
    assert not is_blocked_ip(address)


def _resolver(*addresses):
    def resolve(host, port, type=0):  # noqa: A002 - mirrors socket.getaddrinfo
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, type, 6, "", (a, 0)) for a in addresses]

    return resolve


def test_resolution_rejects_hostnames_pointing_at_private_space():
    assert resolve_public("example.org", _resolver("2606:4700::1", "93.184.216.34")) == ["93.184.216.34", "2606:4700::1"]
    for bad in ("10.0.0.5", "169.254.169.254", "127.0.0.1", "::1"):
        with pytest.raises(BlockedAddressError):
            resolve_public("evil.example.org", _resolver(bad))
    # One private answer among public ones is enough to block (DNS rebinding style setups).
    with pytest.raises(BlockedAddressError):
        resolve_public("mixed.example.org", _resolver("93.184.216.34", "192.168.0.10"))


def test_resolution_failure_is_reported():
    def failing(host, port, type=0):  # noqa: A002
        raise socket.gaierror("no such host")

    with pytest.raises(ResolutionError):
        resolve_public("missing.example.org", failing)
    with pytest.raises(ResolutionError):
        resolve_public("empty.example.org", _resolver())


def test_loopback_is_the_only_exception_and_never_uses_dns():
    target = parse_scan_target("LOCALHOST:3000")
    assert (target.host, target.kind, target.port, target.name) == ("localhost", "loopback", 3000, "localhost:3000")
    assert parse_scan_target("127.0.0.1").name == "localhost"

    def must_not_resolve(*_args, **_kwargs):
        raise AssertionError("loopback targets must not be resolved")

    assert resolve_target(target, must_not_resolve) == "127.0.0.1"


@pytest.mark.parametrize(
    "raw",
    [
        "10.0.0.1", "192.168.1.10", "169.254.169.254", "172.16.5.4", "8.8.8.8", "127.0.0.2", "[::1]", "::1",
        "10.0.0.0/8", "http://example.org", "example.org/path", "example.org:8443", "user@example.org",
        "exa mple.org", "*.example.org", "example.org;ls", "files.corp.internal", "printer.local", "localhost:99999",
        "localhost:0", "", "   ", "a" * 300 + ".org", None, 42,
    ],
)
def test_target_validation_rejects_everything_but_hostnames_and_loopback(raw):
    with pytest.raises(TargetError):
        parse_scan_target(raw)


def test_target_validation_normalizes_hostnames():
    target = parse_scan_target("  WWW.Example.ORG. ")
    assert (target.host, target.kind, target.port, target.scope_name) == ("www.example.org", "public", None, "www.example.org")


# ------------------------------------------------------------------ rate limiting


class FakeClock:
    def __init__(self):
        self.now = 100.0
        self.waits = []

    def __call__(self):
        return self.now

    def wait(self, seconds, _cancel):
        self.waits.append(round(seconds, 6))
        self.now += seconds
        return False


def test_rate_limiter_spaces_requests():
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock, wait=clock.wait)
    assert all(limiter.acquire() for _ in range(5))
    assert clock.waits == [0.5, 0.5, 0.5, 0.5]  # first call is immediate, then 2 per second
    assert clock.now == pytest.approx(102.0)
    clock.now += 10  # idle time is not banked into a burst
    assert limiter.acquire() and limiter.acquire()
    assert clock.waits[-1] == 0.5 and len(clock.waits) == 5


def test_rate_limiter_stops_waiting_when_cancelled():
    cancel = threading.Event()
    limiter = RateLimiter(0.001)  # a 1000 second gap between calls
    assert limiter.acquire(cancel)
    threading.Timer(0.05, cancel.set).start()
    assert limiter.acquire(cancel) is False  # returns promptly instead of sleeping 1000 s
    assert limiter.acquire(cancel) is False


def test_rate_limiter_rejects_nonsense():
    with pytest.raises(ValueError):
        RateLimiter(0)


def test_scan_gate_limits_concurrency_and_enforces_cooldown():
    clock = FakeClock()
    gate = ScanGate(max_concurrent=2, cooldown_seconds=60, clock=clock)
    gate.enter("a.example.org")
    with pytest.raises(ScanBusyError, match="already running"):
        gate.enter("a.example.org")
    gate.enter("b.example.org")
    with pytest.raises(ScanBusyError, match="2 scans are already running"):
        gate.enter("c.example.org")
    gate.leave("a.example.org")
    gate.enter("c.example.org")  # a slot is free again
    gate.leave("b.example.org")
    with pytest.raises(ScanBusyError, match="Wait 61 seconds") as info:
        gate.enter("a.example.org")  # a slot is free, but a.example.org is cooling down
    assert info.value.retry_after == 61
    clock.now += 60
    gate.enter("a.example.org")


# ------------------------------------------------------------------ settings


def test_web_settings_default_to_loopback_and_refuse_other_hosts():
    web = WebSettings.from_env({})
    assert (web.ui_origin, web.api_origin) == ("http://127.0.0.1:5500", "http://127.0.0.1:8000")
    for host in ("0.0.0.0", "192.168.1.20", "example.org", "::"):
        with pytest.raises(WebConfigError):
            WebSettings.from_env({"WEBSCAN_UI_HOST": host})
        with pytest.raises(WebConfigError):
            WebSettings.from_env({"WEBSCAN_API_HOST": host})
    with pytest.raises(WebConfigError):
        WebSettings.from_env({"WEBSCAN_MAX_REQUESTS_PER_SECOND": "50"})
