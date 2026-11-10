"""Have I Been Pwned domain search.

STATUS: 🚧 WIP
Purpose: tell the organization whether staff email addresses appear in known data breaches.
Env vars: HIBP_API_KEY (paid subscription; the domain must first be verified with HIBP).
Planned endpoint: GET https://haveibeenpwned.com/api/v3/breacheddomain/<domain>
                  header "hibp-api-key: <key>"; returns {"alias": ["BreachName", ...], ...}
Data that would leave the org: the organization's email domain.
TODO: verify against live API; confirm pricing and rate limits; handle HTTP 404 (no breaches).

Only counts and breach names are reported. Individual email aliases are never written to
findings, logs, or reports.
"""

from __future__ import annotations

from typing import Any

from webscan.models import Issue
from webscan.providers.stubs.base import StubProvider, is_apex
from webscan.scope.enforcer import ScopeDecision


class HibpProvider(StubProvider):
    name = "hibp"
    is_external = True
    env_vars = ("HIBP_API_KEY",)
    data_sent = "the organization's email domain"

    def applies_to(self, target: str, decision: ScopeDecision) -> bool:
        asset = self.ctx.assets.lookup(target)
        return decision.kind == "domain" and is_apex(target) and bool(asset and asset.email_domain == target)

    def _fetch_live(self, target: str) -> Any | None:
        key = self.ctx.settings.get_env("HIBP_API_KEY")
        if not key:
            return None
        # TODO: verify against live API
        return self.guarded_get(
            target, f"https://haveibeenpwned.com/api/v3/breacheddomain/{target}",
            headers={"hibp-api-key": key, "user-agent": "WebScan"},
        ).json()

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        if not isinstance(payload, dict) or not payload:
            return []
        breaches = sorted({name for names in payload.values() if isinstance(names, list) for name in names})
        return [
            Issue(
                name=f"{len(payload)} staff email address(es) appear in known data breaches",
                knowledge_id="breach-exposure",
                evidence=f"{len(payload)} address(es) across {len(breaches)} breach(es): {', '.join(breaches[:10])}. "
                         "Individual addresses are withheld.",
            )
        ]
