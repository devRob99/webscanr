"""Read-only local dashboard: asset list, scan history, grade trend, report viewer.

STATUS: 🟡 Partial (optional later phase).
  Done: overview page, history with grade trend, report viewer with language toggle,
        token-based roles when WEBSCAN_DASHBOARD_TOKENS is set.
  Not done: starting scans or editing config from the browser, user accounts, scheduled
        rescans, multi-organization "clinic mode".

It binds to 127.0.0.1 by default and serves only redacted data (asset aliases). If
WEBSCAN_DASHBOARD_TOKENS is unset, the dashboard is open to anyone who can reach the port,
which is acceptable only on localhost.
"""

from __future__ import annotations

import hmac
from html import escape

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from webscan import store
from webscan.context import RunContext
from webscan.history import list_runs
from webscan.pipeline import prioritize
from webscan.reporting.html_report import GRADE_COLORS, render_html

ROLES = ("admin", "analyst", "viewer")
STYLE = (
    "<style>body{font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:900px;margin:2em auto;padding:0 1em;"
    "color:#1f2933}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 10px;"
    "border-bottom:1px solid #d9dee4}th{background:#f4f6f8}.g{display:inline-block;width:1.8em;height:1.8em;"
    "line-height:1.8em;text-align:center;border-radius:50%;color:#fff;font-weight:700}nav a{margin-right:1em}</style>"
)


def parse_tokens(raw: str | None) -> dict[str, str]:
    """"token:role,token:role" -> {token: role}; entries with unknown roles are ignored."""
    tokens: dict[str, str] = {}
    for pair in (raw or "").split(","):
        token, _, role = pair.strip().partition(":")
        if token and role in ROLES:
            tokens[token] = role
    return tokens


def create_app(ctx: RunContext) -> FastAPI:
    app = FastAPI(title="WebScan dashboard", docs_url=None, redoc_url=None, openapi_url=None)
    tokens = parse_tokens(ctx.settings.get_env("WEBSCAN_DASHBOARD_TOKENS"))

    def role(request: Request) -> str:
        if not tokens:
            return "viewer"  # no tokens configured: local, read-only use
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        for token, token_role in tokens.items():
            if supplied and hmac.compare_digest(supplied, token):
                return token_role
        ctx.audit.log("dashboard_denied", status="rejected", detail=request.url.path)
        raise HTTPException(status_code=401, detail="A valid dashboard token is required")

    def page(title: str, body: str) -> HTMLResponse:
        nav = '<nav><a href="/">Overview</a><a href="/report?lang=en">Report (EN)</a><a href="/report?lang=es">Informe (ES)</a></nav>'
        return HTMLResponse(f"<!doctype html><meta charset='utf-8'><title>{escape(title)}</title>{STYLE}{nav}<h1>{escape(title)}</h1>{body}")

    def badge(grade: str) -> str:
        return f"<span class='g' style='background:{GRADE_COLORS.get(grade, '#666')}'>{escape(grade)}</span>"

    @app.get("/", response_class=HTMLResponse)
    def overview(current: str = Depends(role)) -> HTMLResponse:
        runs = list_runs(ctx, limit=20)
        r = ctx.redactor.redact  # the dashboard is always redacted, whatever the CLI flags
        assets = "".join(
            f"<tr><td>{escape(a.alias)}</td><td>{escape(r(a.description))}</td><td>{escape(a.exposure_tier)}</td>"
            f"<td>{a.asset_criticality}</td><td>{escape(a.platform or '')}</td></tr>"
            for a in ctx.assets.assets
        )
        trend = " &rarr; ".join(badge(run["grade"]) for run in reversed(runs)) or "No runs recorded yet."
        history = "".join(
            f"<tr><td>{run['id']}</td><td>{escape(run['created_at'])}</td><td>{badge(run['grade'])}</td>"
            f"<td>{run['total']}</td><td>{run['counts'].get('Critical', 0)}</td><td>{run['counts'].get('High', 0)}</td>"
            f"<td>{escape(run['data_mode'])}</td></tr>"
            for run in runs
        )
        body = (
            f"<p>Signed in as: <strong>{escape(current)}</strong> (read-only)</p><h2>Grade trend</h2><p>{trend}</p>"
            "<h2>Assets</h2><table><tr><th>Alias</th><th>Description</th><th>Exposure</th><th>Criticality</th>"
            f"<th>Platform</th></tr>{assets}</table>"
            "<h2>Scan history</h2><table><tr><th>#</th><th>When (UTC)</th><th>Grade</th><th>Findings</th>"
            f"<th>Critical</th><th>High</th><th>Data</th></tr>{history}</table>"
        )
        return page(f"WebScan - {r(ctx.assets.organization_alias)}", body)

    @app.get("/report", response_class=HTMLResponse)
    def report(lang: str = "en", current: str = Depends(role)) -> HTMLResponse:
        raw = store.load_raw(ctx)
        if not raw:
            return page("No findings yet", "<p>Run <code>webscan demo</code> or <code>webscan scan --all</code> first.</p>")
        lang = lang if lang in ("en", "es") else "en"
        other = "es" if lang == "en" else "en"
        was_enabled, ctx.redactor.enabled = ctx.redactor.enabled, True
        try:
            html = render_html(prioritize(ctx, raw), ctx, lang, alt_href=f"/report?lang={other}")
        finally:
            ctx.redactor.enabled = was_enabled
        ctx.audit.log("dashboard_report", status="ok", detail=f"role={current} lang={lang}")
        return HTMLResponse(html)

    return app
