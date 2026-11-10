"""JSON API for the web UI. Every route lives under /api.

Bound to loopback, CORS-restricted to the UI origin, and every state-changing request must
carry that Origin. All input is validated here; the browser is never trusted.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from webscan import __version__
from webscan.config import Settings
from webscan.providers.local.fetch import USER_AGENT
from webscan.reporting.html_report import write_pdf
from webscan.web import verification
from webscan.web.demo import DEMO_TARGET
from webscan.web.netguard import Target, TargetError, parse_scan_target
from webscan.web.scanner import CHECK_LABELS, LIVE_MODE_MESSAGE, SCAN_TYPES, ScanManager, ScanRefused
from webscan.web.settings import WebSettings
from webscan.web.storage import Store

API_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-site",
}
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DomainIn(_Body):
    domain: str = Field(min_length=1, max_length=260)


class VerifyIn(_Body):
    method: Literal["dns", "file"]


class AcknowledgeIn(_Body):
    accepted: Literal[True]


class ScanIn(_Body):
    domain: str | None = Field(default=None, max_length=260)
    scan_type: Literal["quick", "full"] = "quick"
    demo: bool = False


def create_api(
    settings: Settings,
    web: WebSettings,
    manager: ScanManager | None = None,
    txt_lookup: verification.TxtLookup | None = None,
    file_fetch: verification.FileFetch | None = None,
) -> FastAPI:
    app = FastAPI(title="WebScan API", docs_url=None, redoc_url=None, openapi_url=None)
    manager = manager or ScanManager(settings, web, Store(settings.output_dir / "web" / "webscan_ui.sqlite"))
    store = manager.store
    txt_lookup = txt_lookup or verification.live_txt_lookup
    file_fetch = file_fetch or verification.make_file_fetch(manager.limiters, manager.resolver)
    allowed_hosts = {f"{web.api_host}:{web.api_port}", f"127.0.0.1:{web.api_port}", f"localhost:{web.api_port}"}

    def error(status_code: int, message: str, **headers: str) -> JSONResponse:
        return JSONResponse({"error": message}, status_code=status_code, headers=headers)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host", "") not in allowed_hosts:  # blocks DNS-rebinding requests
            response: Response = error(400, "Unknown host.")
        elif request.method not in SAFE_METHODS and request.headers.get("origin") != web.ui_origin:
            response = error(403, "Requests that change data are accepted only from the WebScan UI.")
        else:
            response = await call_next(request)
        for name, value in API_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    app.add_middleware(
        CORSMiddleware, allow_origins=[web.ui_origin], allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"], expose_headers=["Content-Disposition", "Retry-After"],
    )

    @app.exception_handler(ScanRefused)
    async def _refused(_request: Request, exc: ScanRefused):
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else {}
        return error(exc.status_code, exc.message, **headers)

    @app.exception_handler(TargetError)
    async def _bad_target(_request: Request, exc: TargetError):
        return error(422, str(exc))

    @app.exception_handler(RequestValidationError)
    async def _invalid(_request: Request, _exc: RequestValidationError):
        return error(422, "The request was not valid. Check the values and try again.")

    @app.exception_handler(StarletteHTTPException)
    async def _http(_request: Request, exc: StarletteHTTPException):
        return error(exc.status_code, str(exc.detail))

    # ------------------------------------------------------------------ helpers

    def domain_view(record: dict[str, Any]) -> dict[str, Any]:
        status = manager.domain_status(record)
        view: dict[str, Any] = {
            "name": record["name"], "host": record["host"], "kind": record["kind"], "status": status,
            "method": verification.LOOPBACK_METHOD if status == "exempt" else record.get("method"),
            "created_at": record["created_at"], "verified_at": record.get("verified_at"), "expires_at": None,
        }
        if record["kind"] == "public":
            view["instructions"] = verification.instructions(record["host"], record["token"])
            if record.get("verified_at"):
                from datetime import datetime

                view["expires_at"] = verification.expiry(
                    datetime.fromisoformat(record["verified_at"]), web.verification_ttl_days
                ).isoformat(timespec="seconds")
        return view

    def known_domain(name: str) -> tuple[Target, dict[str, Any]]:
        target = parse_scan_target(name)
        record = store.get_domain(target.name)
        if record is None:
            raise ScanRefused(404, "That domain has not been added.")
        return target, record

    def finished_scan(scan_id: str) -> dict[str, Any]:
        scan = manager.get(scan_id) if len(scan_id) <= 40 else None
        if scan is None:
            raise ScanRefused(404, "Scan not found.")
        if scan["status"] != "completed" or not scan.get("result"):
            raise ScanRefused(409, "This scan has no report because it did not complete.")
        return scan

    def filename(scan: dict[str, Any], extension: str) -> str:
        safe = "".join(c if c.isalnum() or c in ".-" else "-" for c in scan["target"])
        return f"webscan-{safe}-{scan['started_at'][:10]}.{extension}"

    # ------------------------------------------------------------------ routes

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return {
            "version": __version__,
            "live_mode": manager.live_mode,
            "live_mode_message": None if manager.live_mode else LIVE_MODE_MESSAGE,
            "acknowledged_at": store.acknowledged_at(),
            "verification_ttl_days": web.verification_ttl_days,
            "user_agent": USER_AGENT,
            "demo_target": DEMO_TARGET,
            "limits": {
                "max_requests_per_second": web.max_requests_per_second,
                "max_concurrent_scans": web.max_concurrent_scans,
                "scan_cooldown_seconds": web.scan_cooldown_seconds,
                "scan_timeout_seconds": web.scan_timeout_seconds,
            },
            "scan_types": [
                {"id": key, "label": value["label"], "description": value["description"],
                 "checks": [CHECK_LABELS[c] for c in value["checks"]]}
                for key, value in SCAN_TYPES.items()
            ],
        }

    @app.post("/api/acknowledgment")
    def acknowledge(_body: AcknowledgeIn) -> dict[str, Any]:
        return {"acknowledged_at": store.acknowledge()}

    @app.get("/api/domains")
    def list_domains() -> dict[str, Any]:
        return {"domains": [domain_view(r) for r in store.list_domains()]}

    @app.post("/api/domains", status_code=201)
    def add_domain(body: DomainIn) -> dict[str, Any]:
        target = parse_scan_target(body.domain)
        if store.get_domain(target.name) is None:
            store.add_domain(target.name, target.host, target.kind, target.port, verification.new_token())
            store.audit("domain_added", target=target.name, status="ok")
        return {"domain": domain_view(store.get_domain(target.name) or {})}

    @app.post("/api/domains/{name}/verify")
    def verify_domain(name: str, body: VerifyIn) -> dict[str, Any]:
        target, record = known_domain(name)
        if target.kind == "loopback":
            raise ScanRefused(422, "Local addresses do not need verification.")
        manager.require_live_mode()
        if body.method == "dns":
            result = verification.check_dns(target.host, record["token"], txt_lookup)
        else:
            result = verification.check_file(target.host, record["token"], file_fetch)
        if result.ok:
            store.mark_verified(target.name, result.method)
        store.audit(
            "domain_verified" if result.ok else "verification_failed", target=target.name,
            verification_method=result.method, status="ok" if result.ok else "failed", summary=result.detail,
        )
        return {"ok": result.ok, "detail": result.detail, "domain": domain_view(store.get_domain(target.name) or {})}

    @app.delete("/api/domains/{name}")
    def delete_domain(name: str) -> dict[str, Any]:
        target, _record = known_domain(name)
        store.delete_domain(target.name)
        store.audit("domain_removed", target=target.name, status="ok")
        return {"removed": target.name}

    @app.get("/api/scans")
    def list_scans(demo: bool = False) -> dict[str, Any]:
        return {"scans": manager.history(demo)}

    @app.post("/api/scans", status_code=202)
    def start_scan(body: ScanIn) -> dict[str, Any]:
        target = None if body.demo else parse_scan_target(body.domain)
        return {"scan": manager.start(target, body.scan_type, demo=body.demo)}

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict[str, Any]:
        scan = manager.get(scan_id) if len(scan_id) <= 40 else None
        if scan is None:
            raise ScanRefused(404, "Scan not found.")
        if scan.get("result"):
            scan["result"] = {k: v for k, v in scan["result"].items() if k != "export"}
        return {"scan": scan}

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str) -> dict[str, Any]:
        scan = manager.cancel(scan_id) if len(scan_id) <= 40 else None
        if scan is None:
            raise ScanRefused(404, "Scan not found.")
        scan.pop("result", None)
        return {"scan": scan}

    @app.get("/api/scans/{scan_id}/report.json")
    def report_json(scan_id: str) -> JSONResponse:
        scan = finished_scan(scan_id)
        result = scan["result"]
        body = {
            "scan": {k: scan[k] for k in ("id", "target", "mode", "scan_type", "status", "started_at", "finished_at",
                                         "verification_method")},
            "demo_data": scan["mode"] == "demo",
            "summary": result["summary"],
            "findings": result["findings"],
            "fix_first": result["fix_first"],
            "warnings": result["warnings"],
            "scanner_export": result["export"],
        }
        return JSONResponse(
            body, headers={"Content-Disposition": f'attachment; filename="{filename(scan, "json")}"'}
        )

    @app.get("/api/scans/{scan_id}/report.html")
    def report_html(scan_id: str) -> HTMLResponse:
        finished_scan(scan_id)
        return HTMLResponse(manager.report_html(scan_id) or "", headers={"Content-Security-Policy": REPORT_CSP})

    @app.get("/api/scans/{scan_id}/report.pdf")
    def report_pdf(scan_id: str) -> Response:
        scan = finished_scan(scan_id)
        with tempfile.TemporaryDirectory(prefix="webscan-pdf-") as tmp:
            html_path, pdf_path = Path(tmp) / "report.html", Path(tmp) / "report.pdf"
            html_path.write_text(manager.report_html(scan_id) or "", encoding="utf-8")
            ok, _engine = write_pdf(html_path, pdf_path)
            if not ok:
                raise ScanRefused(
                    503, "PDF export needs Chrome, Edge, or the optional WeasyPrint package on this computer. "
                         "Open the printable report instead and use your browser's Print > Save as PDF."
                )
            content = pdf_path.read_bytes()
        return Response(
            content, media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename(scan, "pdf")}"'},
        )

    @app.get("/api/compare")
    def compare(previous: str = "", current: str = "") -> dict[str, Any]:
        if not (0 < len(previous) <= 40 and 0 < len(current) <= 40):
            raise ScanRefused(422, "Choose two scans to compare.")
        return {"comparison": manager.compare(previous, current)}

    @app.get("/api/audit")
    def audit() -> dict[str, Any]:
        return {"entries": store.list_audit()}

    app.state.manager = manager
    return app
