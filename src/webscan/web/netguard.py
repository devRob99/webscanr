"""Target validation and SSRF protection for scans started from the web UI.

A target is either a public hostname (must pass ownership verification) or a loopback
address for testing a local app. Before any connection the hostname is resolved and every
address it maps to is checked; the connection is then made to that checked address, so a
DNS answer that changes between the check and the request cannot redirect the scan.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from webscan.sanitize.redact import INTERNAL_SUFFIXES
from webscan.scope.enforcer import BLOCKED_EXTERNAL_NETWORKS, ScopeError, parse_target

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[..., list[Any]]

_LOOPBACK_RE = re.compile(r"^(localhost|127\.0\.0\.1)(?::(\d{1,5}))?$")
LOOPBACK_IP = "127.0.0.1"


class TargetError(ValueError):
    """The target is malformed or of a kind the web UI never scans."""


class BlockedAddressError(Exception):
    """The hostname resolves to a private, internal, or otherwise non-public address."""


class ResolutionError(Exception):
    """The hostname could not be resolved."""


@dataclass(frozen=True)
class Target:
    host: str  # hostname used in URLs and for display ("example.org" or "localhost")
    kind: str  # "public" | "loopback"
    port: int | None = None  # loopback only

    @property
    def name(self) -> str:
        """Stable identifier: the host, plus the port for loopback targets."""
        return f"{self.host}:{self.port}" if self.port else self.host

    @property
    def scope_name(self) -> str:
        """What the scope enforcer is asked about."""
        return LOOPBACK_IP if self.kind == "loopback" else self.host


def parse_scan_target(raw: Any) -> Target:
    """Validate user input. Accepts a public hostname, or localhost / 127.0.0.1 with an optional port."""
    if not isinstance(raw, str):
        raise TargetError("Enter a domain name.")
    value = raw.strip().lower().rstrip(".")
    if not value:
        raise TargetError("Enter a domain name.")
    loopback = _LOOPBACK_RE.match(value)
    if loopback:
        port = int(loopback.group(2)) if loopback.group(2) else None
        if port is not None and not 1 <= port <= 65535:
            raise TargetError("The port must be between 1 and 65535.")
        return Target("localhost", "loopback", port)
    try:
        parsed = parse_target(value)
    except ScopeError as exc:
        raise TargetError(f"Not a valid domain name: {exc}. Enter only the hostname, for example example.org.") from exc
    if parsed.kind != "domain":
        raise TargetError(
            "IP addresses and ranges cannot be scanned. Enter a domain name you own, or localhost for a local app."
        )
    if parsed.normalized.rsplit(".", 1)[-1] in INTERNAL_SUFFIXES:
        raise TargetError("Internal-only hostnames cannot be scanned.")
    return Target(parsed.normalized, "public")


def is_blocked_ip(value: str | IPAddress) -> bool:
    """True for private, loopback, link-local, cloud-metadata, CGNAT, multicast, and reserved addresses."""
    try:
        address = ipaddress.ip_address(value) if isinstance(value, str) else value
    except ValueError:
        return True  # not an address at all: fail closed
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return is_blocked_ip(mapped)
    if any(address.version == network.version and address in network for network in BLOCKED_EXTERNAL_NETWORKS):
        return True
    return not address.is_global


def resolve_public(host: str, resolver: Resolver = socket.getaddrinfo) -> list[str]:
    """Resolve a hostname and return its addresses, IPv4 first. Raises if ANY address is non-public."""
    try:
        infos = resolver(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ResolutionError(f"{host} could not be resolved") from exc
    addresses = list(dict.fromkeys(str(info[4][0]).split("%", 1)[0] for info in infos))
    if not addresses:
        raise ResolutionError(f"{host} could not be resolved")
    if any(is_blocked_ip(address) for address in addresses):
        raise BlockedAddressError(
            f"{host} resolves to a private or internal address. Scanning it is blocked to protect internal systems."
        )
    return sorted(addresses, key=lambda a: ipaddress.ip_address(a).version)


def resolve_target(target: Target, resolver: Resolver = socket.getaddrinfo) -> str:
    """The single address a scan of this target may connect to."""
    if target.kind == "loopback":
        return LOOPBACK_IP
    return resolve_public(target.host, resolver)[0]
