"""Scan manager: runs the existing passive checks against one verified target, in the background.

Every rule that protects a target is enforced here on the server, not in the browser:
live-mode switch, authorization acknowledgment, ownership verification, SSRF check,
concurrency cap, cooldown, rate limit, deadline, and cancellation.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urljoin, urlsplit

from webscan.audit.logger import AuditLogger
from webscan.config import AssetRegistry, ConfigError, Settings, load_providers, load_scoring
from webscan.context import RunContext, setup_logging
from webscan.enrichment.platform import detect_platform
from webscan.history import diff_runs
from webscan.ingest.normalize import build_findings
from webscan.models import Finding
from webscan.pipeline import prioritize
from webscan.providers.guard import ExternalCallGuard, LiveModeError
from webscan.providers.local.checks import CHECKS, homepage
from webscan.sanitize.redact import Redactor
from webscan.scope.enforcer import ScopeEnforcer, ScopeError
from webscan.web import verification
from webscan.web.demo import DEMO_TARGET, demo_results
from webscan.web.fetcher import GuardedFetcher, ScanCancelled, ScanTimedOut
from webscan.web.netguard import (
    LOOPBACK_IP,
    BlockedAddressError,
    ResolutionError,
    Resolver,
    Target,
    resolve_target,
)
from webscan.web.present import present
from webscan.web.ratelimit import ScanBusyError, ScanGate, TargetLimiters
from webscan.web.settings import WebSettings
from webscan.web.storage import Store, now_iso

log = logging.getLogger("webscan")

CHECK_LABELS = {
    "headers": "Security headers",
    "tls": "TLS certificate and HTTPS redirect",
    "cookies": "Cookie flags",
    "email": "Email spoofing protection (SPF, DMARC, DKIM)",
    "privacy": "Trackers and privacy policy",
    "exposed_files": "Commonly exposed files",
}
SCAN_TYPES: dict[str, dict[str, Any]] = {
    "quick": {
        "label": "Quick scan",
        "description": "Security headers, TLS certificate, HTTPS redirect, and cookie flags. A handful of requests.",
        "checks": ["headers", "tls", "cookies"],
    },
    "full": {
        "label": "Full scan",
        "description": "Everything in the quick scan, plus email spoofing protection, trackers and privacy "
                       "policy, and a short list of commonly exposed files.",
        "checks": ["headers", "tls", "cookies", "email", "privacy", "exposed_files"],
    },
}
STEP_CONNECT = "Connecting to the site"
STEP_SCORE = "Scoring and prioritizing findings"
FINAL_STATES = ("completed", "cancelled", "failed", "timed_out")
DEMO_STEP_SECONDS = 0.7
LIVE_MODE_MESSAGE = (
    "Live scanning is switched off. Set WEBSCAN_LIVE_MODE=true in the .env file and restart to verify "
    "domains and run real scans. Demo mode works without it."
)


class ScanRefused(Exception):  # noqa: N818
    """The request was understood but a guardrail blocks it. Carries an HTTP status and a clear message."""

    def __init__(self, status_code: int, message: str, retry_after: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.retry_after = retry_after


class SiteUnreachable(Exception):  # noqa: N818
    pass


class RedirectsElsewhere(Exception):  # noqa: N818
    """The site answers only with a redirect to another host, which is out of scope."""


@dataclass
class ScanState:
    id: str
    target: str
    mode: str  # "real" | "demo"
    scan_type: str
    steps: list[str]
    verification_method: str | None = None
    status: str = "running"
    step_index: int = 0
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    error: str | None = None
    cancel: threading.Event = field(default_factory=threading.Event)
    fetcher: GuardedFetcher | None = None

    def progress(self) -> dict[str, Any]:
        running = self.status == "running"
        return {
            "steps": self.steps,
            "step_index": self.step_index,
            "current": self.steps[self.step_index] if running and self.step_index < len(self.steps) else None,
            "percent": 100 if self.status == "completed" else int(self.step_index / max(1, len(self.steps)) * 100),
        }

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id, "target": self.target, "mode": self.mode, "scan_type": self.scan_type,
            "status": self.status, "started_at": self.started_at, "finished_at": self.finished_at,
            "verification_method": self.verification_method, "error": self.error, "grade": None, "total": None,
            "counts": None, "progress": self.progress(),
        }


def build_scan_context(settings: Settings, target: Target) -> RunContext:
    """A RunContext whose approved inventory is exactly one verified target.

    The existing scope enforcer and live-mode guard are used unchanged, so a web scan passes
    the same gates as `webscan scan --live`.
    """
    scoring_cfg = load_scoring(settings)
    providers_cfg = load_providers(settings)
    if target.kind == "loopback":
        scope_data: dict[str, Any] = {"local_only": {"ips": [LOOPBACK_IP]}}
    else:
        scope_data = {"domains": [target.host]}
    scope = ScopeEnforcer(scope_data, source="verified web target")
    asset: dict[str, Any] = {
        "alias": target.name,
        "description": "Local application under test" if target.kind == "loopback" else "Verified website",
        "hostnames": [target.name],
        "exposure_tier": "public",
        "asset_criticality": 2,
    }
    if target.kind == "public":
        asset["email_domain"] = target.host
    assets = AssetRegistry(
        {"organization_alias": target.name, "assets": [asset]}, scoring_cfg["unknown_asset_defaults"]
    )
    redactor = Redactor(alias_map={target.host: target.host, LOOPBACK_IP: "localhost"})
    audit = AuditLogger(settings.log_dir / "audit.jsonl", redactor=redactor, command="web")
    guard = ExternalCallGuard(settings, providers_cfg, scope, audit, live_requested=True, demo=False)
    return RunContext(
        settings=settings, scoring_cfg=scoring_cfg, providers_cfg=providers_cfg, scope=scope, assets=assets,
        redactor=redactor, audit=audit, guard=guard, lang="en", demo=False, live_requested=True,
    )


class ScanManager:
    def __init__(
        self,
        settings: Settings,
        web: WebSettings,
        store: Store,
        resolver: Resolver | None = None,
        demo_step_seconds: float = DEMO_STEP_SECONDS,
    ) -> None:
        self.settings = settings
        self.web = web
        self.store = store
        self.demo_store = Store(None)
        self.resolver = resolver
        self.limiters = TargetLimiters(web.max_requests_per_second)
        self.gate = ScanGate(web.max_concurrent_scans, web.scan_cooldown_seconds)
        self.demo_step_seconds = demo_step_seconds
        self._lock = threading.Lock()
        self._running: dict[str, ScanState] = {}
        self._demo_seeded = False
        setup_logging(settings.log_dir)

    # ------------------------------------------------------------------ guardrail checks

    @property
    def live_mode(self) -> bool:
        return self.settings.live_mode_env

    def require_live_mode(self) -> None:
        if not self.live_mode:
            raise ScanRefused(403, LIVE_MODE_MESSAGE)

    def domain_status(self, record: dict[str, Any]) -> str:
        if record["kind"] == "loopback":
            return "exempt"
        return verification.status(record.get("verified_at"), self.web.verification_ttl_days)

    def _authorize_scan(self, target: Target) -> str:
        """Every server-side precondition for a real scan. Returns the verification method used."""
        self.require_live_mode()
        if not self.store.acknowledged_at():
            raise ScanRefused(
                403, "Confirm that you own this site or have written permission to test it before scanning."
            )
        record = self.store.get_domain(target.name)
        if record is None:
            raise ScanRefused(403, "Add this domain and verify ownership before scanning it.")
        status = self.domain_status(record)
        if status == "exempt":
            return verification.LOOPBACK_METHOD
        if status == "expired":
            raise ScanRefused(
                403, f"Verification for {target.name} has expired. Check verification again before scanning."
            )
        if status != "verified":
            raise ScanRefused(403, f"{target.name} is not verified. Verify ownership before scanning it.")
        return record["method"]

    # ------------------------------------------------------------------ starting and stopping

    def start(self, target: Target | None, scan_type: str, demo: bool = False) -> dict[str, Any]:
        if scan_type not in SCAN_TYPES:
            raise ScanRefused(422, "Unknown scan type.")
        checks = SCAN_TYPES[scan_type]["checks"]
        steps = [STEP_CONNECT, *(CHECK_LABELS[c] for c in checks), STEP_SCORE]
        if demo:
            self._seed_demo()
            state = ScanState(f"demo-{uuid.uuid4().hex[:12]}", DEMO_TARGET, "demo", scan_type, steps, "demo")
            runner = self._run_demo
            args: tuple = (state,)
        else:
            if target is None:
                raise ScanRefused(422, "Choose a domain to scan.")
            method = self._authorize_scan(target)
            try:
                self.gate.enter(target.name)
            except ScanBusyError as exc:
                self.store.audit("scan_refused", target=target.name, verification_method=method, status="blocked",
                                 summary=str(exc))
                raise ScanRefused(429, str(exc), exc.retry_after) from exc
            state = ScanState(uuid.uuid4().hex[:16], target.name, "real", scan_type, steps, method)
            self.store.audit("scan_started", target=target.name, verification_method=method, status="ok",
                             summary=SCAN_TYPES[scan_type]["label"])
            runner = self._run_real
            args = (state, target, checks)
        with self._lock:
            self._running[state.id] = state
        threading.Thread(target=runner, args=args, name=f"scan-{state.id}", daemon=True).start()
        return state.public()

    def cancel(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            state = self._running.get(scan_id)
            if state is not None and state.status == "running":
                state.status = "cancelled"
                state.finished_at = now_iso()
                state.cancel.set()
                if state.fetcher is not None:
                    state.fetcher.abort()
        return state.public() if state is not None else self.get(scan_id)

    # ------------------------------------------------------------------ workers

    def _advance(self, state: ScanState, index: int) -> None:
        if state.cancel.is_set():
            raise ScanCancelled()
        state.step_index = index

    def _finish(self, state: ScanState, status: str, error: str | None = None,
                result: dict[str, Any] | None = None, html: str | None = None) -> None:
        store = self.demo_store if state.mode == "demo" else self.store
        with self._lock:
            if state.status == "running":
                state.status, state.error, state.finished_at = status, error, now_iso()
            if state.status != "completed":
                result = html = None
            summary = (result or {}).get("summary", {})
            store.save_scan(
                {
                    **state.public(), "grade": summary.get("grade"), "total": summary.get("total"),
                    "counts": summary.get("counts"), "result": result, "report_html": html,
                }
            )
            self._running.pop(state.id, None)
        if state.mode == "real":
            counts = summary.get("counts") or {}
            text = (
                f"Grade {summary.get('grade')}; {summary.get('total')} findings ("
                + ", ".join(f"{counts.get(p, 0)} {p}" for p in ("Critical", "High", "Medium", "Low", "Info")) + ")"
                if state.status == "completed" else (state.error or state.status)
            )
            self.store.audit(f"scan_{state.status}", target=state.target,
                             verification_method=state.verification_method,
                             status="ok" if state.status == "completed" else state.status, summary=text)

    def _run_demo(self, state: ScanState) -> None:
        try:
            for index in range(len(state.steps)):
                self._advance(state, index)
                if state.cancel.wait(self.demo_step_seconds):
                    raise ScanCancelled()
            result, html = demo_results(self.settings.log_dir)[1]
            state.step_index = len(state.steps)
            self._finish(state, "completed", result=result, html=html)
        except ScanCancelled:
            self._finish(state, "cancelled")
        except Exception:  # noqa: BLE001 - never leave a scan stuck in "running"
            log.exception("demo scan failed")
            self._finish(state, "failed", "The demo data could not be loaded.")

    def _run_real(self, state: ScanState, target: Target, checks: list[str]) -> None:
        try:
            ctx = build_scan_context(self.settings, target)
            ip = resolve_target(target, self.resolver) if self.resolver else resolve_target(target)
            fetcher = GuardedFetcher(
                ctx, target, ip, self.limiters.get(target.name), state.cancel,
                deadline=time.monotonic() + self.web.scan_timeout_seconds,
            )
            state.fetcher = fetcher
            host = target.name
            cfg = ctx.providers_cfg.get("local", {})
            asset = ctx.assets.lookup(host)

            self._advance(state, 0)
            page = homepage(fetcher, host)
            elsewhere = self._offsite_redirect(fetcher, target)
            if page is None:
                raise RedirectsElsewhere(elsewhere) if elsewhere else SiteUnreachable()
            if asset is not None and asset.platform is None:
                asset.platform = detect_platform(page.headers, page.body)
            if elsewhere:
                ctx.warn(
                    f"This site redirects visitors to a different host ({elsewhere}), which was not scanned. "
                    "Add and verify that host to scan it."
                )

            raw: list[Finding] = []
            enabled = cfg.get("checks", list(CHECKS))
            for index, name in enumerate(checks, start=1):
                self._advance(state, index)
                check = CHECKS.get(name)
                if check is None or name not in enabled:
                    continue
                try:
                    issues = check(fetcher, host, asset, cfg)
                except (ScanCancelled, ScanTimedOut, LiveModeError, ScopeError):
                    raise
                except Exception as exc:  # noqa: BLE001 - one check failing must not stop the others
                    ctx.warn(f"Check '{CHECK_LABELS.get(name, name)}' failed and was skipped: {exc.__class__.__name__}")
                    continue
                raw.extend(build_findings(ctx, host, issues, "local", "live"))

            self._advance(state, len(state.steps) - 1)
            result, html = present(prioritize(ctx, raw), ctx)
            state.step_index = len(state.steps)
            self._finish(state, "completed", result=result, html=html)
        except ScanCancelled:
            self._finish(state, "cancelled")
        except ScanTimedOut:
            self._finish(state, "timed_out",
                         f"The scan timed out after {self.web.scan_timeout_seconds} seconds and was stopped.")
        except SiteUnreachable:
            self._finish(state, "failed",
                         f"{target.name} could not be reached. Check that the site is online and the name is correct.")
        except RedirectsElsewhere as exc:
            self._finish(state, "failed",
                         f"{target.name} only redirects to a different host ({exc}), and redirects to other hosts "
                         "are never followed. Add and verify that host, then scan it instead.")
        except ResolutionError:
            self._finish(state, "failed", f"{target.name} could not be found in DNS. Check the spelling.")
        except BlockedAddressError as exc:
            self._finish(state, "failed", str(exc))
        except (LiveModeError, ScopeError) as exc:
            self._finish(state, "failed", f"The scan was blocked by a safety check: {exc}")
        except ConfigError as exc:
            self._finish(state, "failed", f"Configuration problem: {exc}")
        except Exception:  # noqa: BLE001 - never leave a scan stuck in "running"
            log.exception("scan failed")
            self._finish(state, "failed", "The scan stopped because of an unexpected error. See logs/webscan.log.")
        finally:
            self.gate.leave(target.name)

    @staticmethod
    def _offsite_redirect(fetcher: GuardedFetcher, target: Target) -> str | None:
        """The other host this site sends visitors to, if any. Uses cached responses; never follows it."""
        for scheme in ("https", "http"):
            first = fetcher.get(f"{scheme}://{target.name}/")
            if first is None or not 300 <= first.status < 400:
                continue
            other = urlsplit(urljoin(first.url, first.headers.get("location", ""))).hostname
            if other and other.lower() != target.host:
                return other.lower()
        return None

    # ------------------------------------------------------------------ reading

    def _seed_demo(self) -> None:
        with self._lock:
            if self._demo_seeded:
                return
            self._demo_seeded = True
        result, html = demo_results(self.settings.log_dir)[0]
        earlier = (datetime.now(UTC) - timedelta(days=14)).isoformat(timespec="seconds")
        summary = result["summary"]
        self.demo_store.save_scan(
            {
                "id": "demo-earlier", "target": DEMO_TARGET, "mode": "demo", "scan_type": "full",
                "status": "completed", "started_at": earlier, "finished_at": earlier,
                "verification_method": "demo", "grade": summary["grade"], "total": summary["total"],
                "counts": summary["counts"], "result": result, "report_html": html,
            }
        )

    def _store_for(self, scan_id: str) -> Store:
        return self.demo_store if scan_id.startswith("demo-") else self.store

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            state = self._running.get(scan_id)
            if state is not None:
                return state.public()
        record = self._store_for(scan_id).get_scan(scan_id)
        if record is not None:
            done = record["status"] == "completed"
            record["progress"] = {"steps": [], "step_index": 0, "current": None, "percent": 100 if done else 0}
        return record

    def report_html(self, scan_id: str) -> str | None:
        return self._store_for(scan_id).get_report_html(scan_id)

    def history(self, demo: bool) -> list[dict[str, Any]]:
        if demo:
            self._seed_demo()
        with self._lock:
            running = [s.public() for s in self._running.values() if (s.mode == "demo") == demo]
        stored = (self.demo_store if demo else self.store).list_scans()
        seen = {s["id"] for s in running}
        return sorted([*running, *(s for s in stored if s["id"] not in seen)],
                      key=lambda s: s["started_at"], reverse=True)

    def compare(self, previous_id: str, current_id: str) -> dict[str, Any]:
        """What was fixed, newly introduced, or got worse between two scans of the same target."""
        previous, current = self.get(previous_id), self.get(current_id)
        if previous is None or current is None:
            raise ScanRefused(404, "One of the scans was not found.")
        if previous["target"] != current["target"]:
            raise ScanRefused(422, "Only scans of the same domain can be compared.")
        if not (previous.get("result") and current.get("result")):
            raise ScanRefused(422, "Only completed scans can be compared.")
        if previous["started_at"] > current["started_at"]:
            previous, current = current, previous

        def run(scan: dict[str, Any]) -> dict[str, Any]:
            return {
                "id": scan["id"], "created_at": scan["started_at"], "grade": scan["grade"], "total": scan["total"],
                "findings": [
                    {"finding_id": f["finding_id"], "name": f["title"], "asset_name": f["asset"],
                     "risk_score": float(f["risk"]), "priority": f["priority"]}
                    for f in scan["result"]["findings"]
                ],
            }

        diff = diff_runs(run(previous), run(current))
        diff["target"] = current["target"]
        diff["unchanged"] = current["total"] - len(diff["new"]) - len(diff["worse"])
        return diff
