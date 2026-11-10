"""Optional dashboard (skipped when the 'dashboard' extra is not installed)."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from webscan import store  # noqa: E402
from webscan.dashboard.app import create_app, parse_tokens  # noqa: E402
from webscan.history import record_run  # noqa: E402
from webscan.pipeline import prioritize, run_demo_collection  # noqa: E402


def seeded(ctx):
    raw = run_demo_collection(ctx)
    store.save_raw(ctx, raw)
    record_run(ctx, prioritize(ctx, raw))
    return TestClient(create_app(ctx))


def test_overview_and_report_are_redacted_and_bilingual(ctx):
    client = seeded(ctx)
    home = client.get("/")
    assert home.status_code == 200 and "donor-portal" in home.text and "Grade trend" in home.text
    assert "example.org" not in home.text and "203.0.113" not in home.text
    spanish = client.get("/report", params={"lang": "es"})
    assert spanish.status_code == 200 and "Informe de evaluación de seguridad" in spanish.text
    assert "/report?lang=en" in spanish.text and "example.org" not in spanish.text
    assert "Security Assessment Report" in client.get("/report", params={"lang": "xx"}).text


def test_tokens_gate_access_when_configured(make_ctx):
    ctx = make_ctx(env={"WEBSCAN_DASHBOARD_TOKENS": "s3cret-viewer:viewer, adm1n-token:admin, bad:root"})
    client = seeded(ctx)
    assert client.get("/").status_code == 401
    assert client.get("/", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = client.get("/", headers={"Authorization": "Bearer adm1n-token"})
    assert ok.status_code == 200 and "admin" in ok.text
    assert client.get("/", headers={"Authorization": "Bearer bad"}).status_code == 401
    assert parse_tokens("a:viewer,b:nope,,c:analyst") == {"a": "viewer", "c": "analyst"}
