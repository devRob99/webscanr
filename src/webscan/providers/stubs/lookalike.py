"""Lookalike (typosquat) domain check.

STATUS: 🚧 WIP
Purpose: warn about registered domains that imitate the organization's (fake donation sites,
         impersonation email).
Env vars: none.
Planned method: generate variants LOCALLY, then ask DNS which of them resolve.
Data that would leave the org: DNS queries for the generated variants go to the configured DNS
        resolver, which reveals near-copies of the organization's domain. That is why this
        provider counts as external and needs approval.
TODO: verify live resolution behaviour; add WHOIS/RDAP age for hits; rate-limit DNS queries;
      consider certificate transparency logs as a passive alternative.

In redacted output only the number of hits is shown; the names appear only with --no-redact.
"""

from __future__ import annotations

from typing import Any

from webscan.models import Issue
from webscan.providers.stubs.base import StubProvider, is_apex
from webscan.scope.enforcer import ScopeDecision

_HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv"}
_TLDS = ["com", "net", "org", "co", "info", "online"]
_PREFIXES = ["donate-", "give-", "my", "secure-"]


def generate_variants(domain: str, limit: int = 40) -> list[str]:
    """Common typosquat patterns for a two-label domain, deterministic and deduplicated."""
    name, _, tld = domain.lower().partition(".")
    variants: list[str] = []
    for i in range(len(name)):  # omission
        variants.append(name[:i] + name[i + 1:])
    for i in range(len(name) - 1):  # adjacent swap
        variants.append(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    for i, ch in enumerate(name):  # doubling and look-alike characters
        variants.append(name[:i] + ch + name[i:])
        if ch in _HOMOGLYPHS:
            variants.append(name[:i] + _HOMOGLYPHS[ch] + name[i + 1:])
    for i in range(1, len(name)):  # hyphenation
        variants.append(name[:i] + "-" + name[i:])
    variants.extend(prefix + name for prefix in _PREFIXES)
    out = [f"{v}.{tld}" for v in variants if len(v) > 1]
    out.extend(f"{name}.{other}" for other in _TLDS if other != tld)
    seen = dict.fromkeys(v for v in out if v != domain.lower())
    return list(seen)[:limit]


class LookalikeProvider(StubProvider):
    name = "lookalike"
    is_external = True
    data_sent = "DNS queries for near-copies of the organization's domain"

    def applies_to(self, target: str, decision: ScopeDecision) -> bool:
        return decision.kind == "domain" and is_apex(target)

    def _fetch_live(self, target: str) -> Any | None:
        import dns.exception
        import dns.resolver

        self.ctx.guard.authorize(self.name, target, third_party=True)
        limit = int(self.ctx.providers_cfg.get("stubs", {}).get("lookalike_max_variants", 40))
        resolving = []
        for variant in generate_variants(target, limit):
            try:
                # TODO: verify against live DNS
                dns.resolver.resolve(variant, "A", lifetime=3)
                resolving.append(variant)
            except dns.exception.DNSException:
                continue
        self.ctx.audit.log("api_call", provider=self.name, targets=[target], mode="live", status="ok",
                           detail=f"{limit} DNS lookups")
        return {"resolving": resolving}

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        hits = [h for h in payload.get("resolving", []) if isinstance(h, str)]
        if not hits:
            return []
        names = ": " + ", ".join(hits) if self.ctx.no_redact else " (names are shown only with --no-redact)"
        return [
            Issue(name=f"{len(hits)} lookalike domain name(s) are registered", knowledge_id="lookalike-domain",
                  evidence=f"{len(hits)} generated variant(s) resolve in DNS{names}")
        ]
