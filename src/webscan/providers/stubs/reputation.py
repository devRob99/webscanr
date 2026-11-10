"""Site reputation: Google Safe Browsing and VirusTotal.

STATUS: 🚧 WIP
Purpose: detect when the organization's website is flagged as malicious (often the first
         visible sign of a compromise).
Env vars: GOOGLE_SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY (either or both)
Planned endpoints:
  POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=<key>
  GET  https://www.virustotal.com/api/v3/domains/<domain>   header "x-apikey: <key>"
Data that would leave the org: the organization's public hostnames / URLs.
TODO: verify against live APIs; check each service's terms for nonprofit and non-commercial
      use; consider the Safe Browsing Update API (hash prefixes) so URLs are not sent at all.
"""

from __future__ import annotations

import time
from typing import Any

from webscan.models import Issue
from webscan.providers.stubs.base import TIMEOUT, StubProvider

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]


class ReputationProvider(StubProvider):
    name = "reputation"
    is_external = True
    env_vars = ("GOOGLE_SAFE_BROWSING_API_KEY", "VIRUSTOTAL_API_KEY")
    data_sent = "the organization's public hostnames"

    def _fetch_live(self, target: str) -> Any | None:
        import requests

        result: dict[str, Any] = {}
        gsb_key = self.ctx.settings.get_env("GOOGLE_SAFE_BROWSING_API_KEY")
        vt_key = self.ctx.settings.get_env("VIRUSTOTAL_API_KEY")
        if gsb_key:
            self.ctx.guard.authorize(self.name, target, third_party=True)
            body = {
                "client": {"clientId": "webscan", "clientVersion": "0.1"},
                "threatInfo": {
                    "threatTypes": THREAT_TYPES, "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{target}/"}, {"url": f"https://{target}/"}],
                },
            }
            started = time.perf_counter()
            # TODO: verify against live API
            response = requests.post(GSB_URL, params={"key": gsb_key}, json=body, timeout=TIMEOUT)
            self.ctx.audit.log("api_call", provider=self.name, targets=[target], mode="live",
                               status="ok" if response.ok else "error", service="safebrowsing",
                               duration_ms=(time.perf_counter() - started) * 1000)
            response.raise_for_status()
            result["safebrowsing"] = response.json()
        if vt_key:
            # TODO: verify against live API
            response = self.guarded_get(target, f"https://www.virustotal.com/api/v3/domains/{target}",
                                        headers={"x-apikey": vt_key})
            result["virustotal"] = response.json()
        return result or None

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        reasons: list[str] = []
        matches = (payload.get("safebrowsing") or {}).get("matches") or []
        if matches:
            kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            reasons.append("Google Safe Browsing: " + ", ".join(kinds))
        stats = (((payload.get("virustotal") or {}).get("data") or {}).get("attributes") or {}).get(
            "last_analysis_stats"
        ) or {}
        flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        if flagged >= 2:  # a single engine is often a false positive
            reasons.append(f"VirusTotal: {flagged} security vendors flag this site")
        if not reasons:
            return []
        return [
            Issue(name="Website is flagged as malicious by a reputation service", knowledge_id="site-flagged-malicious",
                  evidence="; ".join(reasons))
        ]
