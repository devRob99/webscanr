"""HackerTarget client: gating, rate limiting, quota, retries, and text-error detection.

HTTP and time are fully mocked; nothing here touches the network or sleeps for real.
"""

import threading

import pytest
import requests

from tests.conftest import read_audit
from webscan.providers.guard import LiveModeError
from webscan.providers.hackertarget.client import (
    HackerTargetClient,
    HackerTargetError,
    QuotaExceededError,
    QuotaTracker,
    RateLimiter,
    RetriesExhaustedError,
    detect_text_error,
)
from webscan.providers.hackertarget.endpoints import ENDPOINTS, endpoints_for
from webscan.providers.hackertarget.provider import HackerTargetProvider
from webscan.scope.enforcer import ScopeError

NMAP = ENDPOINTS["nmap"]
SECRET = "test-key-do-not-log-123456"


class FakeResponse:
    def __init__(self, status=200, text="PORT STATE SERVICE\n80/tcp open http\n", headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


class FakeSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}

    def get(self, url, params=None, timeout=None):
        self.calls.append({"url": url, "params": dict(params or {}), "timeout": timeout})
        item = self.responses.pop(0) if self.responses else FakeResponse()
        if isinstance(item, Exception):
            raise item
        return item


class FakeTime:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def live_ctx(make_ctx):
    ctx = make_ctx(demo=False, use_examples=True, live=True, env={"WEBSCAN_LIVE_MODE": "true"})
    ctx.providers_cfg["approved_providers"] = ["hackertarget"]
    return ctx


def make_client(ctx, tmp_path, *responses, **overrides):
    cfg = {**ctx.providers_cfg["hackertarget"], **overrides.pop("cfg", {})}
    fake_time = FakeTime()
    session = FakeSession(*responses)
    client = HackerTargetClient(
        cfg, ctx.guard, ctx.audit, quota_path=tmp_path / "quota.json", api_key=SECRET, session=session,
        sleep=fake_time.sleep, clock=fake_time.clock, rng=overrides.pop("rng", lambda: 1.0),
        today=overrides.pop("today", lambda: "2026-10-05"),
    )
    return client, session, fake_time


# ------------------------------------------------------------------ happy path and logging


def test_success_sends_https_request_with_key_and_never_logs_it(live_ctx, tmp_path):
    client, session, _ = make_client(live_ctx, tmp_path)
    text = client.get(NMAP, "donate.example.org")
    assert "80/tcp" in text
    call = session.calls[0]
    assert call["url"] == "https://api.hackertarget.com/nmap/"
    assert call["params"] == {"q": "donate.example.org", "apikey": SECRET}
    assert call["timeout"] == 30.0
    calls = [r for r in read_audit(live_ctx) if r["event"] == "api_call"]
    assert len(calls) == 1 and calls[0]["status"] == "ok" and calls[0]["mode"] == "live"
    assert calls[0]["targets"] == ["donor-portal"] and calls[0]["endpoint"] == "nmap"
    raw_log = live_ctx.audit.path.read_text()
    assert SECRET not in raw_log and "example.org" not in raw_log


def test_base_url_must_be_https(live_ctx, tmp_path):
    with pytest.raises(HackerTargetError):
        make_client(live_ctx, tmp_path, cfg={"base_url": "http://api.hackertarget.com"})


# ------------------------------------------------------------------ gating: no call without all three checks


def test_no_request_without_live_flag(make_ctx, tmp_path):
    ctx = make_ctx(demo=False, use_examples=True, live=False, env={"WEBSCAN_LIVE_MODE": "true"})
    ctx.providers_cfg["approved_providers"] = ["hackertarget"]
    client, session, _ = make_client(ctx, tmp_path)
    with pytest.raises(LiveModeError):
        client.get(NMAP, "donate.example.org")
    assert session.calls == []


def test_no_request_without_env_live_mode(make_ctx, tmp_path):
    ctx = make_ctx(demo=False, use_examples=True, live=True, env={})
    ctx.providers_cfg["approved_providers"] = ["hackertarget"]
    client, session, _ = make_client(ctx, tmp_path)
    with pytest.raises(LiveModeError, match="WEBSCAN_LIVE_MODE"):
        client.get(NMAP, "donate.example.org")
    assert session.calls == []


def test_no_request_without_provider_approval(make_ctx, tmp_path):
    ctx = make_ctx(demo=False, use_examples=True, live=True, env={"WEBSCAN_LIVE_MODE": "true"})
    assert ctx.providers_cfg["approved_providers"] == []
    client, session, _ = make_client(ctx, tmp_path)
    with pytest.raises(LiveModeError, match="approved_providers"):
        client.get(NMAP, "donate.example.org")
    assert session.calls == []
    assert read_audit(ctx)[-1]["event"] == "live_call_blocked"


def test_demo_mode_never_goes_live_even_if_everything_else_is_on(make_ctx, tmp_path):
    ctx = make_ctx(demo=True, live=True, env={"WEBSCAN_LIVE_MODE": "true"})
    ctx.providers_cfg["approved_providers"] = ["hackertarget"]
    client, session, _ = make_client(ctx, tmp_path)
    with pytest.raises(LiveModeError, match="demo"):
        client.get(NMAP, "donate.example.org")
    assert session.calls == []


@pytest.mark.parametrize("target", ["10.0.0.5", "files.target.local", "evil.example.com", "198.51.100.1", "a;b"])
def test_private_and_out_of_scope_targets_never_reach_the_api(live_ctx, tmp_path, target):
    client, session, _ = make_client(live_ctx, tmp_path)
    with pytest.raises(ScopeError):
        client.get(NMAP, target)
    assert session.calls == []
    assert read_audit(live_ctx)[-1]["event"] == "scope_rejection"
    assert client.quota.used == 0


def test_wip_endpoints_cannot_be_called_live(live_ctx, tmp_path):
    client, session, _ = make_client(live_ctx, tmp_path)
    for key in ("nikto", "openvas"):
        assert ENDPOINTS[key].wip
        with pytest.raises(HackerTargetError, match="WIP"):
            client.get(ENDPOINTS[key], "donate.example.org")
    assert session.calls == []


# ------------------------------------------------------------------ retry / backoff


def test_429_is_retried_with_exponential_backoff(live_ctx, tmp_path):
    client, session, fake_time = make_client(
        live_ctx, tmp_path, FakeResponse(429), FakeResponse(429), FakeResponse(200, "ok result"),
        cfg={"min_delay_seconds": 0},
    )
    assert client.get(NMAP, "donate.example.org") == "ok result"
    assert len(session.calls) == 3
    assert fake_time.sleeps == [2.0, 4.0]  # base 2s, doubling; rng=1.0 -> full step
    statuses = [r["status"] for r in read_audit(live_ctx) if r["event"] == "api_call"]
    assert statuses == ["retry", "retry", "ok"]


def test_backoff_has_jitter_and_a_ceiling(live_ctx, tmp_path):
    low, _, _ = make_client(live_ctx, tmp_path, rng=lambda: 0.0)
    high, _, _ = make_client(live_ctx, tmp_path, rng=lambda: 1.0)
    assert low.backoff_delay(0) == 1.0 and high.backoff_delay(0) == 2.0  # 50-100% of the step
    assert low.backoff_delay(2) == 4.0 and high.backoff_delay(2) == 8.0
    assert high.backoff_delay(20) == 60.0  # capped at backoff_max_seconds
    assert high.backoff_delay(0, retry_after="30") == 30.0
    assert high.backoff_delay(0, retry_after="9999") == 60.0
    assert high.backoff_delay(0, retry_after="soon") == 2.0


def test_retry_after_header_is_honored(live_ctx, tmp_path):
    client, _, fake_time = make_client(
        live_ctx, tmp_path, FakeResponse(429, headers={"Retry-After": "17"}), FakeResponse(200, "fine"),
        cfg={"min_delay_seconds": 0},
    )
    assert client.get(NMAP, "donate.example.org") == "fine"
    assert fake_time.sleeps == [17.0]


def test_5xx_and_timeouts_are_retried_until_exhausted(live_ctx, tmp_path):
    client, session, fake_time = make_client(
        live_ctx, tmp_path, FakeResponse(503), requests.Timeout("slow"), requests.ConnectionError("down"),
        FakeResponse(500), FakeResponse(502), cfg={"min_delay_seconds": 0},
    )
    with pytest.raises(RetriesExhaustedError, match="5 attempts"):
        client.get(NMAP, "donate.example.org")
    assert len(session.calls) == 5  # max_retries=4 -> 5 attempts
    assert len(fake_time.sleeps) == 4
    assert client.quota.used == 5  # every attempt counts against the quota


def test_other_http_errors_are_not_retried(live_ctx, tmp_path):
    client, session, fake_time = make_client(live_ctx, tmp_path, FakeResponse(403, "Forbidden"))
    with pytest.raises(HackerTargetError, match="HTTP 403"):
        client.get(NMAP, "donate.example.org")
    assert len(session.calls) == 1 and fake_time.sleeps == []


# ------------------------------------------------------------------ plain-text errors with HTTP 200


@pytest.mark.parametrize(
    "body,kind",
    [
        ("API count exceeded - Increase Quota with Membership", "quota"),
        ("error check your search parameter", "error"),
        ("error invalid host", "error"),
        ("Error input invalid - enter IP or Hostname", "error"),
        ("invalid api key", "error"),
        ("Too many requests, slow down", "rate"),
        ("No DNS A records found", "empty"),
        ("", "empty"),
    ],
)
def test_text_errors_are_classified(body, kind):
    assert detect_text_error(body)[0] == kind


def test_real_results_are_not_mistaken_for_errors():
    assert detect_text_error("Starting Nmap 7.80\n80/tcp open http\n") is None
    assert detect_text_error("example.org,203.0.113.11\n") is None
    assert detect_text_error("HTTP/1.1 500 Internal Server Error\nServer: nginx\n") is None


def test_quota_message_in_200_body_stops_everything(live_ctx, tmp_path):
    client, session, _ = make_client(live_ctx, tmp_path, FakeResponse(200, "API count exceeded - Increase Quota"))
    with pytest.raises(QuotaExceededError):
        client.get(NMAP, "donate.example.org")
    assert client.quota.remaining == 0
    with pytest.raises(QuotaExceededError):
        client.get(NMAP, "donate.example.org")
    assert len(session.calls) == 1  # the second call never left the machine


def test_plain_text_error_is_not_retried_or_parsed(live_ctx, tmp_path):
    client, session, fake_time = make_client(live_ctx, tmp_path, FakeResponse(200, "error check your search parameter"))
    with pytest.raises(HackerTargetError, match="check your search"):
        client.get(NMAP, "donate.example.org")
    assert len(session.calls) == 1 and fake_time.sleeps == []


def test_rate_limit_text_is_retried_and_empty_result_is_empty(live_ctx, tmp_path):
    client, session, _ = make_client(
        live_ctx, tmp_path, FakeResponse(200, "Too many requests"), FakeResponse(200, "No DNS A records found"),
        cfg={"min_delay_seconds": 0},
    )
    assert client.get(ENDPOINTS["dnslookup"], "example.org") == ""
    assert len(session.calls) == 2


# ------------------------------------------------------------------ quota and pacing


def test_daily_quota_persists_across_restarts_and_resets_next_day(tmp_path):
    day = ["2026-10-05"]
    path = tmp_path / "state" / "quota.json"
    first = QuotaTracker(path, 3, today=lambda: day[0])
    assert [first.consume(), first.consume()] == [1, 2]
    restarted = QuotaTracker(path, 3, today=lambda: day[0])
    assert restarted.used == 2 and restarted.remaining == 1
    restarted.consume()
    with pytest.raises(QuotaExceededError):
        restarted.consume()
    day[0] = "2026-10-06"
    assert restarted.remaining == 3 and restarted.consume() == 1


def test_quota_file_corruption_is_tolerated(tmp_path):
    path = tmp_path / "quota.json"
    path.write_text("{broken")
    assert QuotaTracker(path, 5, today=lambda: "d").consume() == 1


def test_client_refuses_requests_once_quota_is_spent(live_ctx, tmp_path):
    client, session, _ = make_client(live_ctx, tmp_path, cfg={"daily_quota": 2, "min_delay_seconds": 0})
    client.get(NMAP, "donate.example.org")
    client.get(NMAP, "www.example.org")
    with pytest.raises(QuotaExceededError):
        client.get(NMAP, "archive.example.org")
    assert len(session.calls) == 2


def test_rate_limiter_enforces_minimum_delay():
    fake_time = FakeTime()
    limiter = RateLimiter(2.0, fake_time.clock, fake_time.sleep)
    assert limiter.wait() == 0.0
    fake_time.now += 0.5
    assert limiter.wait() == pytest.approx(1.5)
    fake_time.now += 5
    assert limiter.wait() == 0.0
    assert fake_time.sleeps == [pytest.approx(1.5)]


def test_client_paces_consecutive_requests(live_ctx, tmp_path):
    client, _, fake_time = make_client(live_ctx, tmp_path)
    client.get(NMAP, "donate.example.org")
    client.get(NMAP, "www.example.org")
    assert fake_time.sleeps == [2.0]  # min_delay_seconds between the two requests


def test_queue_keeps_order_continues_after_failures_and_caps_concurrency(live_ctx, tmp_path):
    active, peak, lock = [0], [0], threading.Lock()

    class SlowSession(FakeSession):
        def get(self, url, params=None, timeout=None):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            try:
                if params["q"] == "www.example.org":
                    return FakeResponse(403)
                threading.Event().wait(0.01)
                return FakeResponse(200, f"result for {params['q']}")
            finally:
                with lock:
                    active[0] -= 1

    cfg = {**live_ctx.providers_cfg["hackertarget"], "max_concurrent": 2, "min_delay_seconds": 0}
    client = HackerTargetClient(cfg, live_ctx.guard, live_ctx.audit, tmp_path / "q.json", session=SlowSession(),
                                sleep=lambda s: None)
    hosts = ["donate.example.org", "www.example.org", "archive.example.org", "staging.example.org", "10.0.0.5"]
    results = client.get_many([(NMAP, h) for h in hosts])
    assert [target for _, target, _ in results] == hosts
    assert results[0][2] == "result for donate.example.org"
    assert isinstance(results[1][2], HackerTargetError)
    assert isinstance(results[4][2], ScopeError)  # private address rejected inside the queue too
    assert results[3][2] == "result for staging.example.org"
    assert 1 <= peak[0] <= 2


# ------------------------------------------------------------------ endpoints and provider


def test_endpoint_selection_by_target_kind():
    enabled = ["nmap", "httpheaders", "dnslookup", "hostsearch", "reverseiplookup", "subnetcalc", "nikto"]
    assert [e.key for e in endpoints_for("domain", enabled)] == ["nmap", "httpheaders", "dnslookup", "hostsearch", "nikto"]
    assert [e.key for e in endpoints_for("ip", enabled)] == ["nmap", "httpheaders", "reverseiplookup", "nikto"]
    assert [e.key for e in endpoints_for("ip", enabled, asset_has_hostnames=True)] == ["reverseiplookup"]
    assert [e.key for e in endpoints_for("cidr", enabled)] == ["subnetcalc"]
    assert endpoints_for("domain", ["made-up"]) == []
    assert all(e.path.startswith("/") and e.path.endswith("/") for e in ENDPOINTS.values())


def test_provider_uses_mock_data_by_default_and_marks_it(ctx):
    provider = HackerTargetProvider(ctx)
    assert provider.is_external and not provider.is_live()
    findings = provider.run("archive.example.org")
    assert findings and all(f.data_source == "mock" and f.sources == ["hackertarget"] for f in findings)
    assert any(f.cve_id == "CVE-2021-41773" for f in findings)
    assert all(f.asset_name == "archived-brochure-site" for f in findings)
    events = [r["event"] for r in read_audit(ctx)]
    assert "mock_response" in events and "provider_run" in events and "api_call" not in events


def test_provider_goes_live_only_with_everything_enabled_and_skips_wip(live_ctx, tmp_path):
    headers = "HTTP/1.1 200 OK\nServer: Apache/2.4.49 (Unix)\n"
    client, session, _ = make_client(
        live_ctx, tmp_path, FakeResponse(200, "PORT STATE SERVICE\n23/tcp open telnet\n"), FakeResponse(200, headers),
        FakeResponse(200, "error check your search parameter"), FakeResponse(200, "staging.example.org,203.0.113.20\n"),
        cfg={"min_delay_seconds": 0},
    )
    provider = HackerTargetProvider(live_ctx, client=client)
    assert provider.is_live()
    findings = provider.run("staging.example.org")
    called = [c["url"].rsplit("/", 2)[-2] for c in session.calls]
    assert called == ["nmap", "httpheaders", "dnslookup", "hostsearch"]  # no nikto/openvas live
    assert all(f.data_source == "live" for f in findings)
    assert any(f.knowledge_id == "open-telnet" for f in findings)
    assert any("dnslookup" in w for w in live_ctx.warnings)  # one failing endpoint did not stop the rest


def test_provider_without_api_key_stays_on_mock(live_ctx):
    provider = HackerTargetProvider(live_ctx)
    assert not provider.is_live()
    assert all(f.data_source == "mock" for f in provider.run("donate.example.org"))
