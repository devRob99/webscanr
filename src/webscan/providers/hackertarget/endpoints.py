"""HackerTarget endpoint definitions only. No request logic lives here.

Paths follow HackerTarget's public API documentation (https://hackertarget.com/ip-tools/).
Each endpoint is called as ``GET {base_url}{path}?q=<target>&apikey=<key>``.

TODO (team): confirm paths, response formats, and quotas against the organization's
HackerTarget account before the first live run.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Endpoint:
    key: str
    path: str
    description: str
    accepts: frozenset[str]  # target kinds: "domain", "ip", "cidr"
    response_format: str  # "text" | "csv" | "headers"
    # When an asset has hostnames, IP targets only run endpoints flagged ip_specific, so the
    # same host is not scanned twice (saves quota).
    ip_specific: bool = False
    wip: bool = False  # True -> never called live; mock data only


ENDPOINTS: dict[str, Endpoint] = {
    e.key: e
    for e in (
        Endpoint("nmap", "/nmap/", "Nmap port scan with service detection", frozenset({"domain", "ip"}), "text"),
        Endpoint("httpheaders", "/httpheaders/", "HTTP response headers", frozenset({"domain", "ip"}), "headers"),
        Endpoint("dnslookup", "/dnslookup/", "DNS records for a domain", frozenset({"domain"}), "text"),
        Endpoint("hostsearch", "/hostsearch/", "Known hostnames under a domain", frozenset({"domain"}), "csv"),
        Endpoint(
            "reverseiplookup", "/reverseiplookup/", "Other hostnames on the same IP", frozenset({"ip"}), "text",
            ip_specific=True,
        ),
        Endpoint(
            "subnetcalc", "/subnetcalc/", "Subnet details for a CIDR block", frozenset({"cidr"}), "text",
            ip_specific=True,
        ),
        # --- 🚧 WIP -----------------------------------------------------------------------
        # OpenVAS and Nikto are membership-tier tools on HackerTarget. They appear to be run
        # as scheduled scans from the member dashboard with results retrieved afterwards,
        # not as a simple GET returning the result.
        # TODO: verify against HackerTarget's docs and the org's account, then implement the
        # submit / poll / download workflow in client.py. The paths below are placeholders.
        Endpoint(
            "nikto", "/nikto/", "Nikto web server scan (WIP)", frozenset({"domain", "ip"}), "text", wip=True
        ),
        Endpoint(
            "openvas", "/openvas/", "OpenVAS vulnerability scan (WIP)", frozenset({"domain", "ip"}), "csv", wip=True
        ),
    )
}


def endpoints_for(kind: str, enabled: list[str], asset_has_hostnames: bool = False) -> list[Endpoint]:
    """Endpoints from the enabled list that apply to a target of this kind."""
    selected = []
    for key in enabled:
        endpoint = ENDPOINTS.get(key)
        if endpoint is None or kind not in endpoint.accepts:
            continue
        if kind == "ip" and asset_has_hostnames and not endpoint.ip_specific:
            continue
        selected.append(endpoint)
    return selected
