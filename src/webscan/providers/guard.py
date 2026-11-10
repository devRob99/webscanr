"""Gate that every outbound network call must pass.

A call is allowed only when ALL of these hold:
  * this is not a demo run,
  * the operator asked for live mode on the command line (--live),
  * WEBSCAN_LIVE_MODE=true in the environment / .env,
  * for third-party providers: the provider is listed in approved_providers,
  * the target passes the scope enforcer (and is public, for third-party providers).

HTTP clients call ``authorize()`` immediately before each request, so there is no code path
that reaches the network without these checks.
"""

from __future__ import annotations

from typing import Any

from webscan.audit.logger import AuditLogger
from webscan.config import Settings
from webscan.scope.enforcer import ScopeDecision, ScopeEnforcer, ScopeError


class LiveModeError(Exception):
    """Live network access was attempted but is not permitted."""


class ExternalCallGuard:
    def __init__(
        self,
        settings: Settings,
        providers_cfg: dict[str, Any],
        scope: ScopeEnforcer,
        audit: AuditLogger,
        live_requested: bool = False,
        demo: bool = False,
    ) -> None:
        self.settings = settings
        self.providers_cfg = providers_cfg
        self.scope = scope
        self.audit = audit
        self.live_requested = live_requested
        self.demo = demo

    def live_allowed(self, provider: str, third_party: bool = True) -> tuple[bool, str]:
        if self.demo:
            return False, "demo mode never uses the network"
        if not self.live_requested:
            return False, "live mode was not requested (--live)"
        if not self.settings.live_mode_env:
            return False, "WEBSCAN_LIVE_MODE is not set to true in .env"
        if provider not in self.providers_cfg.get("enabled_providers", []) and not third_party:
            return False, f"provider '{provider}' is not in enabled_providers"
        if third_party and provider not in self.providers_cfg.get("approved_providers", []):
            return False, f"provider '{provider}' is not listed in approved_providers in providers.json"
        return True, "live mode enabled and provider approved"

    def authorize(self, provider: str, target: str, third_party: bool = True) -> ScopeDecision:
        """Raise unless a live call to/about ``target`` by ``provider`` is permitted."""
        allowed, reason = self.live_allowed(provider, third_party)
        if not allowed:
            self.audit.log(
                "live_call_blocked", provider=provider, targets=[target], mode="mock", status="blocked", detail=reason
            )
            raise LiveModeError(f"Live call blocked: {reason}")
        try:
            return self.scope.require(target, external=third_party)
        except ScopeError as exc:
            self.audit.log(
                "scope_rejection", provider=provider, targets=[target], mode="live", status="rejected", detail=str(exc)
            )
            raise
