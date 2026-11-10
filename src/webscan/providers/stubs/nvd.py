"""NVD CVE API.

STATUS: 🚧 WIP
Purpose: CVE descriptions, CVSS vectors, and reference links to enrich findings.
Env vars: NVD_API_KEY (optional; raises the rate limit).
Planned endpoint: GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN
Data that would leave the org: CVE IDs only. No hostnames, IPs, or findings.
TODO: verify response shape against the live API; add caching to data/reference/; respect the
      rate limit (5 requests / 30 s without a key, 50 with one - confirm current limits).
"""

from __future__ import annotations

import time
from typing import Any

from webscan.models import CVE_RE, Finding, Issue
from webscan.providers.stubs.base import TIMEOUT, StubProvider

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdProvider(StubProvider):
    name = "nvd"
    is_external = True
    env_vars = ("NVD_API_KEY",)
    accepts = frozenset()  # not target-driven: use lookup() / enrich()
    data_sent = "CVE identifiers only"

    def _fetch_live(self, target: str) -> Any | None:
        return None

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        return []

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        """Details for one CVE: {"description", "cvss", "vector", "references"} or None."""
        cve_id = cve_id.upper()
        if not CVE_RE.match(cve_id):
            return None
        if not self.is_live():
            return self.mock_data().get("responses", {}).get(cve_id)
        import requests

        self.ctx.guard.authorize_provider(self.name)  # no target data is sent
        headers = {"apiKey": key} if (key := self.ctx.settings.get_env("NVD_API_KEY")) else {}
        started = time.perf_counter()
        status = "error"
        try:
            # TODO: verify against live API
            response = requests.get(API_URL, params={"cveId": cve_id}, headers=headers, timeout=TIMEOUT)
            response.raise_for_status()
            status = "ok"
            return self.parse_response(response.json())
        finally:
            self.ctx.audit.log("api_call", provider=self.name, mode="live", status=status, cve=cve_id,
                               duration_ms=(time.perf_counter() - started) * 1000)

    @staticmethod
    def parse_response(data: dict[str, Any]) -> dict[str, Any] | None:
        items = data.get("vulnerabilities") or []
        if not items:
            return None
        cve = items[0].get("cve", {})
        description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss, vector = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                data_block = metrics[key][0].get("cvssData", {})
                cvss, vector = data_block.get("baseScore"), data_block.get("vectorString")
                break
        return {
            "description": description, "cvss": cvss, "vector": vector,
            "references": [r["url"] for r in cve.get("references", []) if r.get("url")][:5],
        }

    def enrich(self, findings: list[Finding]) -> int:
        """Fill in missing descriptions and references. Returns how many findings were updated."""
        updated = 0
        for finding in findings:
            if not finding.cve_id:
                continue
            try:
                details = self.lookup(finding.cve_id)
            except Exception as exc:  # noqa: BLE001 - enrichment must never break a run
                self.ctx.warn(f"NVD lookup failed and was skipped: {exc.__class__.__name__}")
                break
            if not details:
                continue
            finding.description = finding.description or details.get("description", "")
            finding.references = list(dict.fromkeys([*finding.references, *details.get("references", [])]))
            updated += 1
        return updated
