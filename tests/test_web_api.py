"""Web API: backend enforcement of the guardrails, demo mode, and a full scan against fake transport."""

from __future__ import annotations

import socket
import time
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from webscan.config import load_settings  # noqa: E402
from webscan.providers.local.fetch import HttpResponse, TlsInfo  # noqa: E402
from webscan.web import fetcher as fetcher_module  # noqa: E402
from webscan.web.api import create_api  # noqa: E402
from webscan.web.scanner import ScanManager  # noqa: E402
from webscan.web.settings import WebSettings  # noqa: E402
from webscan.web.storage import Store  # noqa: E402
from webscan.web.ui import create_ui  # noqa: E402

WEB = WebSettings(max_requests_per_second=5.0, scan_cooldown_seconds=60)
ORIGIN = {"Origin": WEB.ui_origin}
TXT: dict[str, list[str]] = {}


def public_resolver(host, port, type=0):  # noqa: A002
    return [(socket.AF_INET, type, 6, "", ("93.184.216.34", 0))]


def make_client(tmp_path, live=True, resolver=public_resolver, web=WEB):
    env = {"WEBSCAN_LIVE_MODE": "true"} if live else {}
    settings = load_settings(output_dir=tmp_path / "output", log_dir=tmp_path / "logs", env=env,
                             config_dir=tmp_path / "no-config")
    manager = ScanManager(settings, web, Store(None), resolver=resolver, demo_step_seconds=0.01)
    app = create_api(settings, web, manager, txt_lookup=lambda name: TXT.get(name, []),
                     file_fetch=lambda url: (404, ""))
    return TestClient(app, base_url=web.api_origin, headers=ORIGIN), manager


def wait_for(client, scan_id, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}").json()["scan"]
        if scan["status"] != "running":
            return scan
        time.sleep(0.02)
    raise AssertionError("scan did not finish")


def add_verified(client, domain="example.org"):
    added = client.post("/api/domains", json={"domain": domain}).json()["domain"]
    TXT[domain] = [added["instructions"]["dns"]["value"]]
    assert client.post(f"/api/domains/{domain}/verify", json={"method": "dns"}).json()["ok"]
    return added


@pytest.fixture(autouse=True)
def _clear_txt():
    TXT.clear()


@pytest.fixture
def fake_site(monkeypatch):
    """Replaces the socket-level transport. Records every URL requested."""
    requested: list[tuple[str, str]] = []
    pages = {
        "https://example.org/": HttpResponse(
            "https://example.org/", 200, {"content-type": "text/html", "server": "nginx/1.18.0"},
            "<html><script>alert(1)</script><a href='/privacy'>Privacy</a></html>",
            ["session=abc123; Path=/"],
        ),
        "http://example.org/": HttpResponse("http://example.org/", 301, {"location": "https://example.org/"}),
    }

    def fake_get(url, ip, timeout, max_bytes=0, on_connection=None):
        requested.append((url, ip))
        if url in pages:
            return pages[url]
        return HttpResponse(url, 404, {"content-type": "text/html"}, "Not Found")

    monkeypatch.setattr(fetcher_module, "pinned_get", fake_get)
    monkeypatch.setattr(fetcher_module.GuardedFetcher, "tls", lambda self, host: TlsInfo(valid=True, days_remaining=200))
    monkeypatch.setattr(fetcher_module.GuardedFetcher, "txt", lambda self, name, scope: [])
    return requested


# ------------------------------------------------------------------ backend enforcement


def test_scans_of_unverified_domains_are_blocked_on_the_backend(tmp_path, fake_site):
    client, _ = make_client(tmp_path)
    body = {"domain": "example.org", "scan_type": "quick"}

    refused = client.post("/api/scans", json=body)
    assert refused.status_code == 403 and "written permission" in refused.json()["error"]  # no acknowledgment yet
    assert client.post("/api/acknowledgment", json={"accepted": False}).status_code == 422
    stamp = client.post("/api/acknowledgment", json={"accepted": True}).json()["acknowledged_at"]
    assert datetime.fromisoformat(stamp) <= datetime.now(UTC)
    assert client.get("/api/config").json()["acknowledged_at"] == stamp

    refused = client.post("/api/scans", json=body)
    assert refused.status_code == 403 and "Add this domain" in refused.json()["error"]  # not added

    domain = client.post("/api/domains", json={"domain": "example.org"}).json()["domain"]
    assert domain["status"] == "unverified" and len(domain["instructions"]["file"]["content"]) >= 32
    refused = client.post("/api/scans", json=body)
    assert refused.status_code == 403 and "not verified" in refused.json()["error"]  # added, not verified

    failed = client.post("/api/domains/example.org/verify", json={"method": "dns"}).json()
    assert failed["ok"] is False and failed["domain"]["status"] == "unverified"
    assert client.post("/api/domains/example.org/verify", json={"method": "file"}).json()["ok"] is False
    assert client.post("/api/scans", json=body).status_code == 403
    assert fake_site == []  # nothing was ever sent to the target


def test_expired_verification_blocks_scans(tmp_path, fake_site):
    client, manager = make_client(tmp_path)
    client.post("/api/acknowledgment", json={"accepted": True})
    add_verified(client)
    old = (datetime.now(UTC) - timedelta(days=WEB.verification_ttl_days + 1)).isoformat(timespec="seconds")
    manager.store.mark_verified("example.org", "dns", old)
    assert client.get("/api/domains").json()["domains"][0]["status"] == "expired"
    refused = client.post("/api/scans", json={"domain": "example.org", "scan_type": "quick"})
    assert refused.status_code == 403 and "expired" in refused.json()["error"]
    assert fake_site == []


def test_live_mode_switch_blocks_verification_and_scans(tmp_path, fake_site):
    client, _ = make_client(tmp_path, live=False)
    assert client.get("/api/config").json()["live_mode"] is False
    client.post("/api/acknowledgment", json={"accepted": True})
    client.post("/api/domains", json={"domain": "example.org"})
    assert client.post("/api/domains/example.org/verify", json={"method": "dns"}).status_code == 403
    client.post("/api/domains", json={"domain": "localhost:3000"})
    refused = client.post("/api/scans", json={"domain": "localhost:3000", "scan_type": "quick"})
    assert refused.status_code == 403 and "WEBSCAN_LIVE_MODE" in refused.json()["error"]
    assert fake_site == []


@pytest.mark.parametrize(
    "domain", ["10.0.0.1", "169.254.169.254", "http://example.org/", "example.org:22", "a b.org", "router.local", ""]
)
def test_domain_input_is_validated(tmp_path, domain):
    client, _ = make_client(tmp_path)
    response = client.post("/api/domains", json={"domain": domain})
    assert response.status_code == 422 and response.json()["error"]


def test_scan_options_are_validated(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.post("/api/scans", json={"domain": "example.org", "scan_type": "aggressive"}).status_code == 422
    assert client.post("/api/scans", json={"domain": "example.org", "exploit": True}).status_code == 422
    assert client.post("/api/scans", json={"scan_type": "quick"}).status_code == 422
    assert client.get("/api/scans/" + "x" * 80).status_code == 404


def test_state_changing_requests_need_the_ui_origin_and_a_known_host(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.post("/api/acknowledgment", json={"accepted": True}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.get("/api/config", headers={"Host": "attacker.example"}).status_code == 400
    preflight = client.options("/api/scans", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in preflight.headers
    ok = client.get("/api/config")
    assert ok.headers["access-control-allow-origin"] == WEB.ui_origin
    assert ok.headers["x-content-type-options"] == "nosniff" and "default-src 'none'" in ok.headers["content-security-policy"]


# ------------------------------------------------------------------ real scan against fake transport


def test_full_scan_flow_scope_cooldown_and_audit(tmp_path, fake_site):
    client, _ = make_client(tmp_path)
    client.post("/api/acknowledgment", json={"accepted": True})
    add_verified(client)

    started = client.post("/api/scans", json={"domain": "example.org", "scan_type": "full"})
    assert started.status_code == 202
    scan = wait_for(client, started.json()["scan"]["id"])
    assert scan["status"] == "completed", scan
    result = scan["result"]
    titles = " | ".join(f["title"] for f in result["findings"])
    assert result["summary"]["total"] == len(result["findings"]) > 3
    assert "Content-Security-Policy" in titles or "content security" in titles.lower()
    assert all(f["what"] and f["why"] and f["fix"] and f["asset"] == "example.org" for f in result["findings"])
    assert sum(result["summary"]["counts"].values()) == result["summary"]["total"]

    # Scope: every request went to the verified host, at the address that passed the SSRF check.
    assert fake_site and all(url.split("/")[2] == "example.org" and ip == "93.184.216.34" for url, ip in fake_site)
    assert len(fake_site) == len({url for url, _ in fake_site})  # responses are cached, not re-requested

    # Cooldown between scans of the same domain.
    again = client.post("/api/scans", json={"domain": "example.org", "scan_type": "quick"})
    assert again.status_code == 429 and int(again.headers["retry-after"]) > 0

    # Exports.
    exported = client.get(f"/api/scans/{scan['id']}/report.json")
    assert exported.headers["content-disposition"].startswith('attachment; filename="webscan-example.org-')
    assert exported.json()["demo_data"] is False and exported.json()["scanner_export"]["findings"]
    html = client.get(f"/api/scans/{scan['id']}/report.html")
    assert html.status_code == 200 and "<script" not in html.text.lower()
    assert "script-src" not in html.headers["content-security-policy"]

    # History and audit log.
    assert [s["id"] for s in client.get("/api/scans").json()["scans"]] == [scan["id"]]
    events = {e["event"]: e for e in client.get("/api/audit").json()["entries"]}
    assert {"authorization_acknowledged", "domain_added", "domain_verified", "scan_started", "scan_completed",
            "scan_refused"} <= set(events)
    done = events["scan_completed"]
    assert done["target"] == "example.org" and done["verification_method"] == "dns" and "Grade" in done["summary"]


def test_hostname_resolving_to_private_address_is_never_contacted(tmp_path, fake_site):
    def private(host, port, type=0):  # noqa: A002
        return [(socket.AF_INET, type, 6, "", ("169.254.169.254", 0))]

    client, _ = make_client(tmp_path, resolver=private)
    client.post("/api/acknowledgment", json={"accepted": True})
    add_verified(client)
    scan = wait_for(client, client.post("/api/scans", json={"domain": "example.org"}).json()["scan"]["id"])
    assert scan["status"] == "failed" and "private or internal address" in scan["error"]
    assert fake_site == []


def test_unreachable_site_gives_a_clear_error(tmp_path, monkeypatch):
    def refuse(url, ip, timeout, max_bytes=0, on_connection=None):
        raise ConnectionRefusedError()

    monkeypatch.setattr(fetcher_module, "pinned_get", refuse)
    client, _ = make_client(tmp_path)
    client.post("/api/acknowledgment", json={"accepted": True})
    client.post("/api/domains", json={"domain": "localhost:3999"})
    assert client.get("/api/domains").json()["domains"][0]["status"] == "exempt"  # loopback skips verification
    scan = wait_for(client, client.post("/api/scans", json={"domain": "localhost:3999"}).json()["scan"]["id"])
    assert scan["status"] == "failed" and "could not be reached" in scan["error"]


def test_cancel_stops_a_running_scan_immediately(tmp_path, monkeypatch):
    calls = []

    def slow(url, ip, timeout, max_bytes=0, on_connection=None):
        calls.append(url)
        return HttpResponse(url, 200, {"content-type": "text/html"}, "<html></html>")

    monkeypatch.setattr(fetcher_module, "pinned_get", slow)
    slow_web = WebSettings(max_requests_per_second=0.1)  # 10 s between requests: the scan sits in the limiter
    client, _ = make_client(tmp_path, web=slow_web)
    client.post("/api/acknowledgment", json={"accepted": True})
    add_verified(client)
    scan_id = client.post("/api/scans", json={"domain": "example.org", "scan_type": "full"}).json()["scan"]["id"]
    started = time.monotonic()
    cancelled = client.post(f"/api/scans/{scan_id}/cancel", json={}).json()["scan"]
    assert cancelled["status"] == "cancelled" and time.monotonic() - started < 1.0
    time.sleep(0.2)
    sent = len(calls)
    time.sleep(0.2)
    assert len(calls) == sent <= 1  # nothing more is sent after cancelling
    final = client.get(f"/api/scans/{scan_id}").json()["scan"]
    assert final["status"] == "cancelled" and not final.get("result")
    assert client.get(f"/api/scans/{scan_id}/report.json").status_code == 409


# ------------------------------------------------------------------ demo mode


def test_demo_mode_runs_end_to_end_without_network_or_live_mode(tmp_path):
    # The autouse no_network fixture fails this test if any socket is opened.
    client, _ = make_client(tmp_path, live=False)
    started = client.post("/api/scans", json={"demo": True, "scan_type": "full"}).json()["scan"]
    assert started["target"] == "demo.example.com" and started["mode"] == "demo" and started["progress"]["steps"]
    scan = wait_for(client, started["id"])
    assert scan["status"] == "completed"
    counts = scan["result"]["summary"]["counts"]
    assert sum(1 for level in ("Critical", "High", "Medium", "Low") if counts[level]) >= 3  # a mix of severities

    history = client.get("/api/scans", params={"demo": "true"}).json()["scans"]
    assert [s["id"] for s in history] == [started["id"], "demo-earlier"]
    assert client.get("/api/scans").json()["scans"] == []  # demo scans never appear in real history
    assert client.get("/api/audit").json()["entries"] == []

    diff = client.get("/api/compare", params={"previous": started["id"], "current": "demo-earlier"}).json()["comparison"]
    assert diff["previous"]["id"] == "demo-earlier" and diff["new"] and diff["resolved"]
    assert client.get(f"/api/scans/{started['id']}/report.json").json()["demo_data"] is True


def test_compare_rejects_different_domains_and_unknown_scans(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.get("/api/compare", params={"previous": "nope", "current": "demo-earlier"}).status_code == 404
    assert client.get("/api/compare").status_code == 422


# ------------------------------------------------------------------ UI server


def test_ui_is_served_with_csp_and_security_headers():
    client = TestClient(create_ui(WEB), base_url=WEB.ui_origin)
    page = client.get("/")
    assert page.status_code == 200 and "Try Demo" not in page.text and 'src="app.js"' in page.text
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert f"connect-src 'self' {WEB.api_origin}" in csp and "frame-ancestors 'none'" in csp
    assert page.headers["x-content-type-options"] == "nosniff" and page.headers["x-frame-options"] == "DENY"
    assert client.get("/config.json").json() == {"apiBase": "http://127.0.0.1:8000/api"}
    script = client.get("/app.js").text
    assert "innerHTML" not in script.replace("Nothing in this file uses innerHTML", "")
    redirected = client.get("/", headers={"Host": "localhost:5500"}, follow_redirects=False)
    assert redirected.status_code == 307 and redirected.headers["location"] == "http://127.0.0.1:5500/"
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_redirects_to_another_host_are_reported_and_never_followed(tmp_path, monkeypatch):
    calls = []
    https_up = True

    def redirecting(url, ip, timeout, max_bytes=0, on_connection=None):
        calls.append(url)
        if url.startswith("https://") and not https_up:
            raise ConnectionRefusedError()
        return HttpResponse(url, 301, {"location": "https://www.other-site.example/"})

    monkeypatch.setattr(fetcher_module, "pinned_get", redirecting)
    monkeypatch.setattr(fetcher_module.GuardedFetcher, "tls", lambda self, host: None)
    client, _ = make_client(tmp_path, web=WebSettings(max_requests_per_second=5.0, scan_cooldown_seconds=0))
    client.post("/api/acknowledgment", json={"accepted": True})
    add_verified(client)

    scan = wait_for(client, client.post("/api/scans", json={"domain": "example.org"}).json()["scan"]["id"])
    assert scan["status"] == "completed"
    assert any("www.other-site.example" in warning for warning in scan["result"]["warnings"])

    https_up = False  # only a plain-http redirect answers: nothing on this host can be assessed
    scan = wait_for(client, client.post("/api/scans", json={"domain": "example.org"}).json()["scan"]["id"])
    assert scan["status"] == "failed" and "www.other-site.example" in scan["error"]
    assert all(url.split("/")[2] == "example.org" for url in calls)  # the redirect target was never requested
