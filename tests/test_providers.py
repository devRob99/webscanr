"""Provider base class enforcement, local passive checks, and platform detection."""

import pytest

from tests.conftest import read_audit
from webscan.config import DEFAULT_PROVIDERS
from webscan.enrichment.platform import detect_platform
from webscan.models import Finding
from webscan.pipeline import collect
from webscan.providers.base import Provider
from webscan.providers.guard import LiveModeError
from webscan.providers.local import checks
from webscan.providers.local.fetch import FixtureFetcher, HttpResponse, LiveFetcher, TlsInfo
from webscan.providers.local.provider import LocalChecksProvider
from webscan.providers.registry import all_provider_names, target_providers
from webscan.scope.enforcer import ScopeError

CFG = DEFAULT_PROVIDERS["local"]


class Recorder(Provider):
    name = "recorder"
    is_external = True

    def __init__(self, ctx, fail=False):
        super().__init__(ctx)
        self.seen, self.fail = [], fail

    def _collect(self, target, decision, live):
        self.seen.append((target, live))
        if self.fail:
            raise RuntimeError("provider exploded at donate.example.org")
        return [
            Finding(vulnerability_name="x", cve_id=None, base_severity=1.0, asset_name="donor-portal",
                    exposure_tier="public", asset_criticality=3, has_known_exploit=False)
        ]


class LocalRecorder(Recorder):
    name = "local-recorder"
    is_external = False


# ------------------------------------------------------------------ base class enforcement


def test_providers_cannot_override_run():
    with pytest.raises(TypeError, match="must not override"):

        class Sneaky(Provider):
            name = "sneaky"

            def run(self, target):  # tries to skip the scope check
                return []

            def _collect(self, target, decision, live):
                return []


@pytest.mark.parametrize("target", ["evil.example.com", "198.51.100.9", "donate.example.org; id", "203.0.113.0/24"])
def test_out_of_scope_targets_never_reach_collect_and_are_audited(ctx, target):
    provider = Recorder(ctx)
    with pytest.raises(ScopeError):
        provider.run(target)
    assert provider.seen == []
    last = read_audit(ctx)[-1]
    assert last["event"] == "scope_rejection" and last["status"] == "rejected" and last["provider"] == "recorder"
    assert "example" not in str(last["targets"]) and "198.51" not in str(last["targets"])


@pytest.mark.parametrize("target", ["10.0.0.5", "files.target.local"])
def test_internal_targets_blocked_for_external_but_allowed_for_local_providers(ctx, target):
    external = Recorder(ctx)
    with pytest.raises(ScopeError, match="external provider"):
        external.run(target)
    assert external.seen == []
    local = LocalRecorder(ctx)
    assert len(local.run(target)) == 1 and len(local.seen) == 1


def test_provider_failure_is_contained_logged_and_redacted(ctx):
    provider = Recorder(ctx, fail=True)
    assert provider.run("donate.example.org") == []
    record = read_audit(ctx)[-1]
    assert record["event"] == "provider_run" and record["status"] == "error" and "RuntimeError" in record["detail"]
    assert "example.org" not in record["detail"]
    assert any("failed and was skipped" in w and "example.org" not in w for w in ctx.warnings)


def test_successful_run_is_audited_with_alias_mode_and_duration(ctx):
    Recorder(ctx).run("DONATE.example.org")
    record = read_audit(ctx)[-1]
    assert record["event"] == "provider_run" and record["status"] == "ok" and record["mode"] == "mock"
    assert record["targets"] == ["donor-portal"] and record["duration_ms"] >= 0 and record["findings"] == 1


def test_collect_halts_whole_scan_if_any_asset_target_is_out_of_scope(ctx):
    from webscan.config import Asset

    provider = LocalRecorder(ctx)
    rogue = Asset(alias="rogue", hostnames=["donate.example.org", "evil.example.com"], exposure_tier="public",
                  asset_criticality=1)
    with pytest.raises(ScopeError, match="Nothing was scanned"):
        collect(ctx, [ctx.assets.get("donor-portal"), rogue], [provider])
    assert provider.seen == []


def test_collect_skips_external_providers_for_internal_assets(ctx):
    external, local = Recorder(ctx), LocalRecorder(ctx)
    collect(ctx, [ctx.assets.get("file-server")], [external, local])
    assert external.seen == [] and len(local.seen) == 2
    skipped = [r for r in read_audit(ctx) if r["event"] == "provider_skipped"]
    assert len(skipped) == 2 and skipped[0]["targets"] == ["file-server"]


def test_registry_lists_providers_and_keeps_wip_stubs_off_by_default(ctx):
    names = all_provider_names()
    assert {"hackertarget", "quantro", "local"} <= set(names)
    default = [p.name for p in target_providers(ctx)]
    assert default == ["hackertarget", "local"]
    with_wip = target_providers(ctx, include_wip=True)
    assert len(with_wip) > len(default)
    assert all(p.wip for p in with_wip if p.name not in default)


# ------------------------------------------------------------------ local checks against fixtures


@pytest.fixture
def fetcher(ctx):
    return FixtureFetcher(ctx.settings.data_dir / "mock" / "local")


def ids(issues):
    return sorted(i.knowledge_id or i.name for i in issues)


def test_header_audit(ctx, fetcher):
    donate = ids(checks.check_headers(fetcher, "donate.example.org", None, CFG))
    assert donate == ["missing-csp", "missing-hsts", "missing-permissions-policy", "missing-referrer-policy",
                      "missing-x-frame-options", "server-version-disclosure"]
    wix = ids(checks.check_headers(fetcher, "www.example.org", None, CFG))
    assert "missing-hsts" not in wix and "missing-csp" in wix
    archive = ids(checks.check_headers(fetcher, "archive.example.org", None, CFG))
    assert "missing-hsts" not in archive  # HTTP-only site: reported by the TLS check instead


def test_tls_checks(fetcher):
    donate = checks.check_tls(fetcher, "donate.example.org", None, CFG)
    assert ids(donate) == ["tls-cert-expiring", "tls-legacy-protocols"]
    assert "12 day" in donate[0].name and "TLS 1.0" in donate[1].evidence
    assert checks.check_tls(fetcher, "www.example.org", None, CFG) == []
    assert ids(checks.check_tls(fetcher, "archive.example.org", None, CFG)) == ["no-https-redirect"]


class StubFetcher:
    def __init__(self, pages=None, tls=None, dns=None):
        self.pages, self._tls, self.dns, self.requested = pages or {}, tls, dns or {}, []

    def get(self, url):
        self.requested.append(url)
        return self.pages.get(url)

    def tls(self, host):
        return self._tls

    def txt(self, name, scope_domain):
        return self.dns.get(name)


def test_tls_invalid_expired_and_urgent_certificates():
    assert ids(checks.check_tls(StubFetcher(tls=TlsInfo(False, error="self-signed")), "h.example.org", None, CFG)) == [
        "tls-cert-invalid"]
    assert ids(checks.check_tls(StubFetcher(tls=TlsInfo(True, days_remaining=-3)), "h.example.org", None, CFG)) == [
        "tls-cert-invalid"]
    urgent = checks.check_tls(StubFetcher(tls=TlsInfo(True, days_remaining=3)), "h.example.org", None, CFG)
    assert urgent[0].knowledge_id == "tls-cert-expiring" and urgent[0].severity == 7.0
    assert checks.check_tls(StubFetcher(tls=TlsInfo(True, days_remaining=200)), "h.example.org", None, CFG) == []


def test_cookie_flags_report_names_but_never_values(fetcher):
    issues = checks.check_cookies(fetcher, "donate.example.org", None, CFG)
    assert len(issues) == 1 and issues[0].knowledge_id == "insecure-cookies"
    assert "wp_donor_session (missing Secure, HttpOnly, SameSite)" in issues[0].evidence
    assert "wp_lang (missing HttpOnly)" in issues[0].evidence
    assert "placeholder" not in issues[0].evidence
    assert checks.check_cookies(fetcher, "www.example.org", None, CFG) == []


def test_email_spoofing_checks(ctx, fetcher):
    main = ctx.assets.get("main-website")
    issues = checks.check_email(fetcher, "example.org", main, CFG)
    assert ids(issues) == ["missing-dmarc"]  # SPF present, DKIM found under selector1
    assert "anyone can send email" in issues[0].name
    assert checks.check_email(fetcher, "www.example.org", main, CFG) == []  # runs once, on the email domain


def test_email_checks_cover_weak_and_missing_records(ctx):
    main = ctx.assets.get("main-website")
    selectors = {f"{s}._domainkey.example.org": [] for s in CFG["dkim_selectors"]}
    weak = StubFetcher(dns={"example.org": ["v=spf1 +all"], "_dmarc.example.org": ["v=DMARC1; p=none; rua=mailto:x"],
                            **selectors})
    assert ids(checks.check_email(weak, "example.org", main, CFG)) == ["missing-dkim", "missing-spf", "weak-dmarc-policy"]
    good = StubFetcher(dns={"example.org": ["v=spf1 -all"], "_dmarc.example.org": ["v=DMARC1; p=reject"],
                            **selectors, "google._domainkey.example.org": ["v=DKIM1; p=abc"]})
    assert checks.check_email(good, "example.org", main, CFG) == []
    unknown = StubFetcher(dns={})  # DNS lookups failed: report nothing rather than guess
    assert checks.check_email(unknown, "example.org", main, CFG) == []


def test_donation_page_checks(ctx, fetcher):
    donor = ctx.assets.get("donor-portal")
    issues = checks.check_donation(fetcher, "donate.example.org", donor, CFG)
    assert ids(issues) == ["third-party-scripts-donation"]
    assert "Stripe" in issues[0].evidence and "connect.facebook.net" in issues[0].evidence
    assert "js.stripe.com" not in issues[0].evidence.split("Other script sources:")[1]
    assert issues[0].name.startswith("3 ")


def test_donation_form_over_http_is_flagged(ctx):
    donor = ctx.assets.get("donor-portal")
    page = HttpResponse("http://donate.example.org/donate/", 200, {"content-type": "text/html"},
                        '<form action="http://pay.example.net/submit"></form>')
    issues = checks.check_donation(StubFetcher({page.url: page}), "donate.example.org", donor, CFG)
    assert ids(issues) == ["donation-form-insecure"]
    assert "served over http://" in issues[0].evidence and "submits to an http:// address" in issues[0].evidence


def test_privacy_checks(fetcher):
    www = checks.check_privacy(fetcher, "www.example.org", None, CFG)
    assert ids(www) == ["third-party-trackers"] and "Hotjar" in www[0].evidence
    assert ids(checks.check_privacy(fetcher, "archive.example.org", None, CFG)) == ["missing-privacy-policy"]
    assert checks.check_privacy(fetcher, "donate.example.org", None, CFG) == []


def test_exposed_files_use_a_few_single_requests_and_store_no_contents(fetcher):
    staging = checks.check_exposed_files(fetcher, "staging.example.org", None, CFG)
    assert ids(staging) == ["exposed-env", "exposed-git"]
    assert all("placeholder" not in i.evidence and "refs/heads" not in i.evidence for i in staging)
    assert ids(checks.check_exposed_files(fetcher, "archive.example.org", None, CFG)) == ["exposed-backup"]
    assert checks.check_exposed_files(fetcher, "donate.example.org", None, CFG) == []


def test_exposed_files_ignore_soft_404_pages_and_html_lookalikes():
    html = {"content-type": "text/html"}
    soft = "<html>Welcome! Everything returns this page.</html>"
    pages = {"https://h.example.org/": HttpResponse("https://h.example.org/", 200, html, "home")}
    for path in ["/webscan-baseline-check-that-should-not-exist", *CFG["exposed_paths"]]:
        pages[f"https://h.example.org{path}"] = HttpResponse(f"https://h.example.org{path}", 200, html, soft)
    stub = StubFetcher(pages)
    assert checks.check_exposed_files(stub, "h.example.org", None, CFG) == []
    assert len(stub.requested) == len(CFG["exposed_paths"]) + 2  # home + baseline + one GET per path
    # A different HTML page at /.git/HEAD is still not a git file.
    pages["https://h.example.org/.git/HEAD"] = HttpResponse("u", 200, html, "<html>custom error</html>")
    assert checks.check_exposed_files(StubFetcher(pages), "h.example.org", None, CFG) == []


def test_local_provider_runs_all_checks_on_fixtures_and_tags_them_mock(ctx):
    provider = LocalChecksProvider(ctx)
    assert not provider.is_external and not provider.is_live()
    findings = provider.run("staging.example.org")
    found = {f.knowledge_id for f in findings}
    assert {"exposed-git", "exposed-env", "no-https-redirect", "missing-csp"} <= found
    assert all(f.data_source == "mock" and f.sources == ["local"] and f.asset_name == "staging-site" for f in findings)
    assert provider.run("203.0.113.20") == []  # hostname-based checks only
    assert provider.run("files.target.local") == []  # no fixture -> nothing, and no network


def test_one_failing_check_does_not_stop_the_others(ctx, monkeypatch):
    def boom(*_args):
        raise ValueError("bad page at staging.example.org")

    monkeypatch.setitem(checks.CHECKS, "headers", boom)
    findings = LocalChecksProvider(ctx).run("staging.example.org")
    assert any(f.knowledge_id == "exposed-git" for f in findings)
    assert any("Local check 'headers' failed" in w and "example.org" not in w for w in ctx.warnings)


def test_live_fetcher_is_blocked_unless_live_mode_is_fully_enabled(ctx, make_ctx):
    with pytest.raises(LiveModeError):
        LiveFetcher(ctx).get("https://donate.example.org/")
    with pytest.raises(LiveModeError):
        LiveFetcher(ctx).tls("donate.example.org")
    with pytest.raises(LiveModeError):
        LiveFetcher(ctx).txt("_dmarc.example.org", "example.org")
    live = make_ctx(demo=False, use_examples=True, live=True, env={"WEBSCAN_LIVE_MODE": "true"})
    with pytest.raises(ScopeError):  # live mode on, but the host is not in the approved inventory
        LiveFetcher(live).get("https://evil.example.com/")


# ------------------------------------------------------------------ platform detection


@pytest.mark.parametrize(
    "headers,body,expected",
    [
        ({"X-Wix-Request-Id": "1"}, "", "wix"),
        ({"Server": "Pepyaka"}, "", "wix"),
        ({"Server": "Squarespace"}, "", "squarespace"),
        ({"Link": '<https://x/wp-json/>; rel="https://api.w.org/"'}, "", "wordpress"),
        ({}, '<link href="/wp-content/themes/a/style.css">', "wordpress"),
        ({}, '<img src="https://static1.squarespace.com/a.png">', "squarespace"),
        ({}, '<meta itemprop="x" content="Google Sites">', "google_sites"),
        ({"Server": "nginx"}, "<html></html>", None),
        (None, "", None),
    ],
)
def test_platform_detection(headers, body, expected):
    assert detect_platform(headers, body) == expected


def test_local_provider_fills_in_missing_platform_from_signals(ctx):
    asset = ctx.assets.get("donor-portal")
    asset.platform = None
    findings = LocalChecksProvider(ctx).run("donate.example.org")
    assert asset.platform == "wordpress"
    assert all(f.platform == "wordpress" for f in findings)
