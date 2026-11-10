"""Local passive checks provider. Runs from this machine; shares no data with third parties."""

from __future__ import annotations

from webscan.enrichment.platform import detect_platform
from webscan.ingest.normalize import build_findings
from webscan.models import Finding
from webscan.providers.base import Provider
from webscan.providers.local.checks import CHECKS, homepage
from webscan.providers.local.fetch import Fetcher, FixtureFetcher, LiveFetcher
from webscan.scope.enforcer import ScopeDecision


class LocalChecksProvider(Provider):
    name = "local"
    is_external = False  # talks only to the approved target itself

    def __init__(self, ctx, fetcher: Fetcher | None = None) -> None:
        super().__init__(ctx)
        self._fetcher = fetcher

    def _collect(self, target: str, decision: ScopeDecision, live: bool) -> list[Finding]:
        if decision.kind != "domain":
            return []  # checks are hostname-based (TLS names, DNS, pages)
        cfg = self.ctx.providers_cfg.get("local", {})
        fetcher = self._fetcher
        if fetcher is None:
            if live:
                fetcher = LiveFetcher(self.ctx, self.name)
            else:
                fixtures = FixtureFetcher(self.ctx.settings.data_dir / "mock" / "local")
                if not fixtures.has(target):
                    return []
                fetcher = fixtures
        asset = self.ctx.assets.lookup(target)

        if asset is not None and asset.platform is None:
            page = homepage(fetcher, target)
            if page is not None:
                asset.platform = detect_platform(page.headers, page.body)

        findings: list[Finding] = []
        mode = "live" if live else "mock"
        for check_name in cfg.get("checks", list(CHECKS)):
            check = CHECKS.get(check_name)
            if check is None:
                continue
            try:
                issues = check(fetcher, target, asset, cfg)
            except Exception as exc:  # noqa: BLE001 - one check failing must not stop the others
                self.ctx.warn(f"Local check '{check_name}' failed and was skipped: {exc.__class__.__name__}: {exc}")
                continue
            findings.extend(build_findings(self.ctx, target, issues, self.name, mode))
        return findings
