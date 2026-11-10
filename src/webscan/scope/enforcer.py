"""Scope enforcer: the single place that decides whether a target may be touched.

Rules, in order:
1. The input must be a clean IP address, CIDR block, or hostname. Anything else is rejected
   (shell metacharacters, whitespace, URLs, embedded credentials, wildcards, non-ASCII).
2. The target must be covered by the approved asset inventory (allowed_targets.json).
   A CIDR target is in scope only when it is fully contained in an allowed range.
3. Private, loopback, link-local, multicast, and reserved addresses, and internal-only
   hostnames, may never be sent to an external provider, even when whitelisted. They can
   only be scanned by approved local tools.

Fail-safe: a missing, malformed, or empty whitelist halts everything with ScopeError.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from webscan.sanitize.redact import INTERNAL_SUFFIXES

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MAX_TARGET_LENGTH = 253
_ALLOWED_CHARS_RE = re.compile(r"^[A-Za-z0-9.:/\-]+$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# RFC 1035 style labels; the last label must contain a letter (alphabetic TLD or punycode).
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")
_SHELL_META = set(";|&$`<>(){}[]!*?~#\\'\"%^=,+")

# Never routable to an external provider. Built explicitly (rather than from
# ipaddress.is_private) so the RFC 5737 documentation ranges used as placeholders are
# still treated as "public" examples. See docs/DECISIONS.md.
BLOCKED_EXTERNAL_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # RFC 1918
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local
        "172.16.0.0/12",  # RFC 1918
        "192.0.0.0/24",  # IETF protocol assignments
        "192.168.0.0/16",  # RFC 1918
        "198.18.0.0/15",  # benchmarking
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved (includes broadcast)
        "::/128",  # unspecified
        "::1/128",  # loopback
        "::ffff:0:0/96",  # IPv4-mapped (could hide a private IPv4 address)
        "64:ff9b::/96",  # NAT64
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)


class ScopeError(Exception):
    """The target is out of scope, unsafe, or the scope check could not be completed."""


@dataclass(frozen=True)
class ParsedTarget:
    raw: str
    normalized: str
    kind: str  # "ip" | "cidr" | "domain"
    network: IPNetwork | None = None  # set for ip and cidr


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    kind: str | None
    in_scope: bool
    external_ok: bool  # may this target be sent to a third-party provider?
    reason: str
    matched_rule: str | None = None

    def allowed(self, external: bool) -> bool:
        return self.in_scope and (self.external_ok or not external)


def parse_target(raw: Any) -> ParsedTarget:
    """Validate and classify one target. Raises ScopeError on anything that is not clean."""
    if not isinstance(raw, str):
        raise ScopeError("target must be text")
    if not raw:
        raise ScopeError("target is empty")
    if len(raw) > MAX_TARGET_LENGTH:
        raise ScopeError("target is too long")
    if any(ch.isspace() for ch in raw) or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise ScopeError("target contains whitespace or control characters")
    if "://" in raw:
        raise ScopeError("target looks like a URL; give only the hostname or IP")
    if "@" in raw:
        raise ScopeError("target contains '@' (embedded credentials are not allowed)")
    bad = sorted(set(raw) & _SHELL_META)
    if bad:
        if "*" in bad:
            raise ScopeError("wildcard targets are not allowed")
        raise ScopeError("target contains shell metacharacters")
    if not raw.isascii():
        raise ScopeError("target contains non-ASCII characters; use the punycode form")
    if not _ALLOWED_CHARS_RE.match(raw):
        raise ScopeError("target contains characters that are not valid in an IP, CIDR, or hostname")

    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise ScopeError(f"not a valid CIDR block ({exc})".replace(raw, "target")) from exc
        return ParsedTarget(raw, str(network), "cidr", network)

    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is not None:
        network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
        return ParsedTarget(raw, str(address), "ip", network)

    if ":" in raw:
        raise ScopeError("not a valid IP address (ports and IPv6 zone IDs are not allowed)")
    host = raw.lower().rstrip(".")
    if not _DOMAIN_RE.match(host):
        raise ScopeError("not a valid IP address, CIDR block, or hostname")
    return ParsedTarget(raw, host, "domain")


def _blocked_reason(network: IPNetwork) -> str | None:
    for blocked in BLOCKED_EXTERNAL_NETWORKS:
        if blocked.version == network.version and network.overlaps(blocked):
            return f"overlaps non-public range {blocked}"
    first = network.network_address
    if first.is_loopback or first.is_link_local or first.is_multicast or first.is_reserved or first.is_unspecified:
        return "is a loopback, link-local, multicast, or reserved address"
    return None


def _is_internal_hostname(host: str) -> bool:
    return host.rsplit(".", 1)[-1] in INTERNAL_SUFFIXES


class ScopeEnforcer:
    def __init__(self, data: Any, source: str = "allowed_targets") -> None:
        self.source = source
        self._load(data)

    # ------------------------------------------------------------------ loading (fail-safe)

    @classmethod
    def from_file(cls, path: Path) -> ScopeEnforcer:
        path = Path(path)
        if not path.exists():
            raise ScopeError(f"Whitelist {path.name} is missing. Refusing to run without an approved asset inventory.")
        try:
            with path.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ScopeError(f"Whitelist {path.name} is malformed ({exc.__class__.__name__}). Refusing to run.") from exc
        return cls(data, source=path.name)

    def _fail(self, message: str) -> ScopeError:
        return ScopeError(f"Whitelist {self.source} is malformed: {message}. Refusing to run.")

    def _load(self, data: Any) -> None:
        if not isinstance(data, dict):
            raise self._fail("top level must be an object")
        self.allow_wildcard_entries = data.get("allow_wildcard_entries", False)
        if not isinstance(self.allow_wildcard_entries, bool):
            raise self._fail("'allow_wildcard_entries' must be true or false")
        local = data.get("local_only", {})
        if not isinstance(local, dict):
            raise self._fail("'local_only' must be an object")

        self._domains: dict[str, bool] = {}  # exact host -> local_only
        self._wildcards: dict[str, bool] = {}  # parent domain -> local_only
        self._networks: list[tuple[IPNetwork, bool, str]] = []  # (network, local_only, label)

        for section, local_only in ((data, False), (local, True)):
            prefix = "local_only." if local_only else ""
            for key in ("domains", "ips", "cidrs"):
                value = section.get(key, [])
                if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                    raise self._fail(f"'{prefix}{key}' must be a list of strings")
            for entry in section.get("domains", []):
                self._add_domain(entry, local_only)
            for entry in section.get("ips", []):
                try:
                    address = ipaddress.ip_address(entry)
                except ValueError:
                    raise self._fail(f"an entry in '{prefix}ips' is not a valid IP address") from None
                network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
                self._networks.append((network, local_only, f"{prefix}ips"))
            for entry in section.get("cidrs", []):
                try:
                    network = ipaddress.ip_network(entry, strict=True)
                except ValueError:
                    raise self._fail(f"an entry in '{prefix}cidrs' is not a valid CIDR block") from None
                self._networks.append((network, local_only, f"{prefix}cidrs"))

        if not self._domains and not self._wildcards and not self._networks:
            raise self._fail("it lists no targets")

    def _add_domain(self, entry: str, local_only: bool) -> None:
        host = entry.lower().rstrip(".")
        if host.startswith("*."):
            if not self.allow_wildcard_entries:
                raise self._fail("wildcard domain entries need 'allow_wildcard_entries': true")
            parent = host[2:]
            if not _DOMAIN_RE.match(parent):
                raise self._fail("a wildcard domain entry is not a valid hostname")
            self._wildcards[parent] = local_only
            return
        if not _DOMAIN_RE.match(host):
            raise self._fail("an entry in 'domains' is not a valid hostname")
        self._domains[host] = local_only

    def listed_domains(self) -> list[str]:
        """Every whitelisted hostname (used by the redactor to mask them in output)."""
        return sorted({*self._domains, *self._wildcards})

    # ------------------------------------------------------------------ checks

    def check(self, raw: Any) -> ScopeDecision:
        """Evaluate a target without raising. Any doubt results in in_scope=False."""
        shown = raw if isinstance(raw, str) else repr(raw)
        try:
            parsed = parse_target(raw)
        except ScopeError as exc:
            return ScopeDecision(shown, None, False, False, f"Rejected: {exc}")
        try:
            if parsed.kind == "domain":
                return self._check_domain(parsed)
            return self._check_network(parsed)
        except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected
            return ScopeDecision(parsed.normalized, parsed.kind, False, False, f"Scope check failed: {exc}")

    def _check_domain(self, parsed: ParsedTarget) -> ScopeDecision:
        host = parsed.normalized
        local_only: bool | None = self._domains.get(host)
        rule = "exact domain entry"
        if local_only is None:
            for parent, parent_local in self._wildcards.items():
                if host.endswith("." + parent):
                    local_only, rule = parent_local, "wildcard domain entry"
                    break
        if local_only is None:
            return ScopeDecision(host, "domain", False, False, "Out of scope: hostname is not in the approved inventory")
        if local_only:
            return ScopeDecision(
                host, "domain", True, False,
                "In scope for approved local tools only (listed under local_only)", rule,
            )
        if _is_internal_hostname(host):
            return ScopeDecision(
                host, "domain", True, False,
                "In scope for approved local tools only (internal-only hostname suffix)", rule,
            )
        return ScopeDecision(host, "domain", True, True, "In scope: hostname is in the approved inventory", rule)

    def _check_network(self, parsed: ParsedTarget) -> ScopeDecision:
        network = parsed.network
        if network is None:
            raise ScopeError("target has no network form")
        matches = [
            (allowed, local_only, label)
            for allowed, local_only, label in self._networks
            if allowed.version == network.version and network.subnet_of(allowed)
        ]
        if not matches:
            overlapping = any(
                allowed.version == network.version and network.overlaps(allowed) for allowed, _, _ in self._networks
            )
            reason = (
                "Out of scope: range only partially overlaps the approved inventory"
                if overlapping
                else "Out of scope: address is not in the approved inventory"
            )
            return ScopeDecision(parsed.normalized, parsed.kind, False, False, reason)
        blocked = _blocked_reason(network)
        # A target is external-safe only if a non-local entry covers it AND it is public.
        public_match = next((m for m in matches if not m[1]), None)
        if blocked:
            return ScopeDecision(
                parsed.normalized, parsed.kind, True, False,
                f"In scope for approved local tools only (address {blocked}; never sent to external providers)",
                matches[0][2],
            )
        if public_match is None:
            return ScopeDecision(
                parsed.normalized, parsed.kind, True, False,
                "In scope for approved local tools only (listed under local_only)", matches[0][2],
            )
        return ScopeDecision(
            parsed.normalized, parsed.kind, True, True,
            "In scope: fully contained in the approved inventory", public_match[2],
        )

    def require(self, raw: Any, external: bool) -> ScopeDecision:
        """Return the decision or raise ScopeError. Call this before any network activity."""
        decision = self.check(raw)
        if not decision.in_scope:
            raise ScopeError(decision.reason)
        if external and not decision.external_ok:
            raise ScopeError(
                "Blocked: this target may not be sent to an external provider. " + decision.reason
            )
        return decision
