"""HackerTarget provider: live API when permitted, otherwise mock files from data/mock/."""

from __future__ import annotations

import time
from pathlib import Path

from webscan.ingest.normalize import build_findings
from webscan.models import Finding, Issue
from webscan.providers.base import Provider
from webscan.providers.hackertarget import parser
from webscan.providers.hackertarget.client import HackerTargetClient, QuotaExceededError
from webscan.providers.hackertarget.endpoints import Endpoint, endpoints_for
from webscan.scope.enforcer import ScopeDecision


class HackerTargetProvider(Provider):
    name = "hackertarget"
    is_external = True

    def __init__(self, ctx, client: HackerTargetClient | None = None) -> None:
        super().__init__(ctx)
        self._client = client

    @property
    def cfg(self) -> dict:
        return self.ctx.providers_cfg["hackertarget"]

    @property
    def mock_dir(self) -> Path:
        return self.ctx.settings.data_dir / "mock" / "hackertarget"

    @property
    def client(self) -> HackerTargetClient:
        if self._client is None:
            self._client = HackerTargetClient(
                self.cfg, self.ctx.guard, self.ctx.audit,
                quota_path=self.ctx.settings.output_dir / "state" / "hackertarget_quota.json",
                api_key=self.ctx.settings.get_env("HACKERTARGET_API_KEY"),
            )
        return self._client

    def is_live(self) -> bool:
        # No key -> mock, even if live mode is on and the provider is approved.
        return super().is_live() and bool(self.ctx.settings.get_env("HACKERTARGET_API_KEY") or self._client)

    def _mock_text(self, endpoint: Endpoint, target: str) -> str | None:
        path = self.mock_dir / endpoint.key / f"{target.replace('/', '_')}.txt"
        return path.read_text(encoding="utf-8") if path.is_file() else None

    def _parse(self, endpoint: Endpoint, raw: str) -> list[Issue]:
        warn = self.ctx.warn
        if endpoint.key == "subnetcalc":
            parser.parse_subnetcalc(raw)  # context only, no findings
            return []
        if endpoint.key == "hostsearch":
            known = {h for asset in self.ctx.assets.assets for h in asset.hostnames}
            return parser.parse_hostsearch(raw, known, warn)
        return parser.PARSERS[endpoint.key](raw, warn)

    def _collect(self, target: str, decision: ScopeDecision, live: bool) -> list[Finding]:
        asset = self.ctx.assets.lookup(target)
        keys = list(self.cfg["endpoints"])
        if not live:
            keys += [k for k in self.cfg.get("wip_endpoints_in_mock", []) if k not in keys]
        endpoints = endpoints_for(decision.kind or "", keys, asset_has_hostnames=bool(asset and asset.hostnames))
        mode = "live" if live else "mock"
        findings: list[Finding] = []
        for endpoint in endpoints:
            try:
                if live:
                    if endpoint.wip:
                        continue
                    raw: str | None = self.client.get(endpoint, target)
                else:
                    started = time.perf_counter()
                    raw = self._mock_text(endpoint, target)
                    self.ctx.audit.log(
                        "mock_response", provider=self.name, targets=[target], mode="mock",
                        status="ok" if raw is not None else "no_mock_data", endpoint=endpoint.key,
                        duration_ms=(time.perf_counter() - started) * 1000,
                    )
                if not raw:
                    continue
                findings.extend(build_findings(self.ctx, target, self._parse(endpoint, raw), self.name, mode))
            except QuotaExceededError as exc:
                self.ctx.warn(f"HackerTarget quota reached; remaining lookups were skipped ({exc})")
                break
            except Exception as exc:  # noqa: BLE001 - one endpoint failing must not stop the others
                self.ctx.warn(f"HackerTarget '{endpoint.key}' lookup failed and was skipped: {exc}")
        return findings
