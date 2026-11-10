"""Shared plumbing for 🚧 WIP third-party providers.

Every stub returns realistic mock data from data/mock/<name>.json unless live mode is on
AND the organization has approved that specific provider. Live request code is written from
public documentation and marked ``# TODO: verify against live API``.
"""

from __future__ import annotations

import json
import time
from abc import abstractmethod
from typing import Any, ClassVar

from webscan.ingest.normalize import build_findings
from webscan.models import Finding, Issue
from webscan.providers.base import Provider
from webscan.scope.enforcer import ScopeDecision

TIMEOUT = 20


class StubProvider(Provider):
    wip: ClassVar[bool] = True
    env_vars: ClassVar[tuple[str, ...]] = ()
    accepts: ClassVar[frozenset[str]] = frozenset({"domain"})
    data_sent: ClassVar[str] = ""  # plain statement of what would leave the organization

    def is_enabled(self) -> bool:
        return self.name in self.ctx.providers_cfg.get("approved_providers", [])

    def mock_data(self) -> dict[str, Any]:
        path = self.ctx.settings.data_dir / "mock" / f"{self.name}.json"
        if not path.is_file():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def mock_payload(self, target: str) -> Any | None:
        return self.mock_data().get("responses", {}).get(target)

    def applies_to(self, target: str, decision: ScopeDecision) -> bool:
        return decision.kind in self.accepts

    def guarded_get(self, target: str, url: str, **kwargs: Any) -> Any:
        """GET with the full gate (live mode + approval + scope), a timeout, and an audit record."""
        import requests

        self.ctx.guard.authorize(self.name, target, third_party=self.is_external)
        started = time.perf_counter()
        status = "error"
        try:
            response = requests.get(url, timeout=TIMEOUT, **kwargs)
            status = "ok" if response.ok else "error"
            response.raise_for_status()
            return response
        finally:
            self.ctx.audit.log(
                "api_call", provider=self.name, targets=[target], mode="live", status=status,
                duration_ms=(time.perf_counter() - started) * 1000,
            )

    def _collect(self, target: str, decision: ScopeDecision, live: bool) -> list[Finding]:
        if not self.applies_to(target, decision):
            return []
        payload = self._fetch_live(target) if live else self.mock_payload(target)
        if payload is None:
            return []
        return build_findings(self.ctx, target, self._parse(target, payload), self.name, "live" if live else "mock")

    @abstractmethod
    def _fetch_live(self, target: str) -> Any | None:
        """Call the real API. Any exception is contained by Provider.run()."""

    @abstractmethod
    def _parse(self, target: str, payload: Any) -> list[Issue]:
        """Turn one API response (live or mock) into issues."""


def is_apex(target: str) -> bool:
    """Rough check for a registrable domain (two labels). Good enough for the stubs."""
    return target.count(".") == 1
