"""Shodan host lookup.

STATUS: 🚧 WIP
Purpose: open ports and exposed services that Shodan has already observed on public IPs.
Env vars: SHODAN_API_KEY
Planned endpoint: GET https://api.shodan.io/shodan/host/<ip>?key=<key>
Data that would leave the org: the organization's public IP addresses.
TODO: verify against live API; confirm plan limits; map more of the response (hostnames, tags).
"""

from __future__ import annotations

from typing import Any

from webscan.models import CVE_RE, Issue
from webscan.providers.stubs.base import StubProvider

_RISKY = {
    21: ("open-ftp", "FTP file transfer service open to the internet"),
    23: ("open-telnet", "Telnet remote login service open to the internet"),
    3389: ("open-rdp", "Remote Desktop (RDP) open to the internet"),
    3306: ("open-database-port", "Database port (MySQL) open to the internet"),
    5432: ("open-database-port", "Database port (PostgreSQL) open to the internet"),
    27017: ("open-database-port", "Database port (MongoDB) open to the internet"),
    6379: ("open-database-port", "Database port (Redis) open to the internet"),
}


class ShodanProvider(StubProvider):
    name = "shodan"
    is_external = True
    env_vars = ("SHODAN_API_KEY",)
    accepts = frozenset({"ip"})
    data_sent = "the organization's public IP addresses"

    def _fetch_live(self, target: str) -> Any | None:
        key = self.ctx.settings.get_env("SHODAN_API_KEY")
        if not key:
            return None
        # TODO: verify against live API. The key travels as a query parameter and is never logged.
        return self.guarded_get(target, f"https://api.shodan.io/shodan/host/{target}", params={"key": key}).json()

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        issues: list[Issue] = []
        for port in payload.get("ports", []):
            if port in _RISKY:
                knowledge_id, name = _RISKY[port]
                issues.append(Issue(name=name, knowledge_id=knowledge_id, evidence=f"Shodan observed port {port} open"))
        for cve in payload.get("vulns", []):
            cve = str(cve).upper()
            if CVE_RE.match(cve):
                issues.append(
                    Issue(name=f"Shodan reports the server may be affected by {cve}", cve_id=cve, severity=7.5,
                          evidence="Inferred by Shodan from the service banner; confirm before acting.")
                )
        return issues
