"""GeoIP: location and network owner for public IPs.

STATUS: 🚧 WIP
Purpose: show where each public server is hosted and by whom (useful when an IP is flagged).
Env vars: GEOIP_DB_PATH (path to a local MaxMind GeoLite2 database).
Planned source: a LOCAL MaxMind GeoLite2 .mmdb file read with the `geoip2` package. Nothing
                leaves the machine, so this provider is not "external".
Data that would leave the org: none.
TODO: add `geoip2` as an optional dependency; verify field names against a real GeoLite2-City
      and GeoLite2-ASN database; document the MaxMind licence and download steps.
"""

from __future__ import annotations

from typing import Any

from webscan.models import Issue
from webscan.providers.stubs.base import StubProvider


class GeoIpProvider(StubProvider):
    name = "geoip"
    is_external = False  # local database lookup only
    env_vars = ("GEOIP_DB_PATH",)
    accepts = frozenset({"ip"})
    data_sent = "nothing (local database)"

    def _fetch_live(self, target: str) -> Any | None:
        path = self.ctx.settings.get_env("GEOIP_DB_PATH")
        if not path:
            return None
        import geoip2.database  # type: ignore[import-not-found]  # optional dependency

        # TODO: verify against a real GeoLite2 database
        with geoip2.database.Reader(path) as reader:
            city = reader.city(target)
            return {"country": city.country.iso_code, "city": city.city.name, "org": None, "asn": None}

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        owner = payload.get("org") or "unknown network"
        asn = f" (AS{payload['asn']})" if payload.get("asn") else ""
        return [
            Issue(
                name=f"Server location: {payload.get('country', 'unknown')}, hosted by {owner}{asn}",
                severity=0.0,
                remediation_key="info:hosting-location",
                description="Informational: where this public server is hosted.",
                evidence="GeoIP database lookup",
            )
        ]
