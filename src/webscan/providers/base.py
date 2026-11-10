"""Provider interface.

Every data source (HackerTarget, Quantro, local checks, WIP stubs) implements ``Provider``.
``run()`` is final: it performs the scope check and audit logging, then delegates to
``_collect()``. Subclasses cannot override ``run()``, so no provider can skip enforcement.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from webscan.models import Finding
from webscan.scope.enforcer import ScopeDecision, ScopeError

if TYPE_CHECKING:
    from webscan.context import RunContext


class Provider(ABC):
    name: ClassVar[str] = ""
    is_external: ClassVar[bool] = True  # True -> target data would leave the organization
    wip: ClassVar[bool] = False

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if "run" in cls.__dict__:
            raise TypeError(f"{cls.__name__} must not override Provider.run(); implement _collect() instead")

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def is_enabled(self) -> bool:
        return self.name in self.ctx.providers_cfg.get("enabled_providers", [])

    def is_live(self) -> bool:
        """True only when live mode is on AND (for external providers) the org approved it."""
        return self.ctx.guard.live_allowed(self.name, third_party=self.is_external)[0]

    def run(self, target: str) -> list[Finding]:
        """Scope-check the target, then collect findings. Never raises except ScopeError."""
        audit = self.ctx.audit
        try:
            decision = self.ctx.scope.require(target, external=self.is_external)
        except ScopeError as exc:
            audit.log("scope_rejection", provider=self.name, targets=[str(target)], status="rejected", detail=str(exc))
            raise
        live = self.is_live()
        mode = "live" if live else "mock"
        start = time.perf_counter()
        try:
            findings = self._collect(decision.target, decision, live)
        except Exception as exc:  # noqa: BLE001 - a provider failure must never crash a run
            self.ctx.warn(f"Provider '{self.name}' failed and was skipped: {exc.__class__.__name__}: {exc}")
            audit.log(
                "provider_run", provider=self.name, targets=[decision.target], mode=mode, status="error",
                duration_ms=(time.perf_counter() - start) * 1000, detail=f"{exc.__class__.__name__}: {exc}",
            )
            return []
        audit.log(
            "provider_run", provider=self.name, targets=[decision.target], mode=mode, status="ok",
            duration_ms=(time.perf_counter() - start) * 1000, findings=len(findings),
        )
        return findings

    @abstractmethod
    def _collect(self, target: str, decision: ScopeDecision, live: bool) -> list[Finding]:
        """Return findings for an already scope-checked target."""
