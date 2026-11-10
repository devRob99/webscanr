"""RDAP domain registration lookup.

STATUS: 🚧 WIP
Purpose: warn before the organization's domain name registration expires.
Env vars: none (RDAP is a public, keyless protocol).
Planned endpoint: GET https://rdap.org/domain/<domain> (redirects to the registry's RDAP server)
Data that would leave the org: the organization's domain name.
TODO: verify against live API; handle registries that omit the expiration event; cache results.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from webscan.models import Issue
from webscan.providers.stubs.base import StubProvider, is_apex
from webscan.scope.enforcer import ScopeDecision

WARN_DAYS = 60


class RdapProvider(StubProvider):
    name = "rdap"
    is_external = True
    data_sent = "the organization's domain name"

    def applies_to(self, target: str, decision: ScopeDecision) -> bool:
        return decision.kind == "domain" and is_apex(target)

    def _fetch_live(self, target: str) -> Any | None:
        # TODO: verify against live API
        return self.guarded_get(target, f"https://rdap.org/domain/{target}",
                                headers={"Accept": "application/rdap+json"}).json()

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        expires = next(
            (e.get("eventDate") for e in payload.get("events", []) if e.get("eventAction") == "expiration"), None
        )
        if not expires:
            return []
        today = payload.get("_mock_today")  # keeps the mock result stable over time
        now = datetime.fromisoformat(today.replace("Z", "+00:00")) if today else datetime.now(UTC)
        days = (datetime.fromisoformat(expires.replace("Z", "+00:00")) - now).days
        if days > WARN_DAYS:
            return []
        return [
            Issue(
                name=f"Domain registration expires in {days} day(s)" if days >= 0 else "Domain registration has expired",
                knowledge_id="domain-expiring",
                severity=8.0 if days <= 14 else None,
                evidence=f"RDAP expiration event: {expires[:10]}",
            )
        ]
