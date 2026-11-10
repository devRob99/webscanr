"""Parsers for raw HackerTarget output.

Each ``parse_*`` function is pure: raw text in, a list of provider-neutral ``Issue`` objects
out. ``ingest.normalize.build_findings`` then attaches asset context to produce ``Finding``
objects. A malformed line or row is skipped (and reported through ``warn``); it never raises.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Callable

from webscan.models import CVE_RE, Issue
from webscan.providers.local.headers import analyze_headers

Warn = Callable[[str], None]


def _noop(_message: str) -> None:
    return None


# ------------------------------------------------------------------ software version rules

VERSION_NOTE = "Detected from the version banner; confirm the installed version before acting."


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


def banner_issues(banner: str, where: str = "") -> list[Issue]:
    """Known-vulnerable or unsupported software inferred from a version banner."""
    issues: list[Issue] = []
    evidence = f"{where}{banner.strip()} ({VERSION_NOTE})"

    match = re.search(r"OpenSSH[ _/]?(\d+\.\d+)(?:p(\d+))?", banner, re.IGNORECASE)
    if match:
        version = (*_version_tuple(match.group(1)), int(match.group(2) or 0))
        if version < (9, 3, 2):
            issues.append(
                Issue(
                    name="OpenSSH before 9.3p2: remote code execution via forwarded ssh-agent",
                    cve_id="CVE-2023-38408", severity=9.8, evidence=evidence,
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
                )
            )

    match = re.search(r"Apache(?: httpd)?[ /](\d+\.\d+\.\d+)", banner, re.IGNORECASE)
    if match:
        version = _version_tuple(match.group(1))
        if version == (2, 4, 49):
            issues.append(
                Issue(
                    name="Apache HTTP Server 2.4.49: path traversal and file disclosure",
                    cve_id="CVE-2021-41773", severity=7.5, evidence=evidence,
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                )
            )
        elif version == (2, 4, 50):
            issues.append(
                Issue(
                    name="Apache HTTP Server 2.4.50: path traversal and remote code execution",
                    cve_id="CVE-2021-42013", severity=9.8, evidence=evidence,
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
                )
            )

    if re.search(r"vsftpd 2\.3\.4", banner, re.IGNORECASE):
        issues.append(
            Issue(
                name="vsftpd 2.3.4: backdoored FTP server version", cve_id="CVE-2011-2523", severity=9.8,
                evidence=evidence, references=["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
            )
        )

    match = re.search(r"PHP/(\d+\.\d+)", banner, re.IGNORECASE)
    if match and _version_tuple(match.group(1)) < (8, 1):
        issues.append(
            Issue(
                name=f"Unsupported PHP version ({match.group(1)}) no longer receives security fixes",
                knowledge_id="outdated-php", severity=7.5, evidence=evidence,
                references=["https://www.php.net/supported-versions.php"],
            )
        )
    return issues


# ------------------------------------------------------------------ nmap

_NMAP_PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$")

# service name or port -> (knowledge_id, issue name)
_RISKY_SERVICES: dict[str, tuple[str, str]] = {
    "ftp": ("open-ftp", "FTP file transfer service open to the internet"),
    "telnet": ("open-telnet", "Telnet remote login service open to the internet"),
    "ms-wbt-server": ("open-rdp", "Remote Desktop (RDP) open to the internet"),
    "mysql": ("open-database-port", "Database port (MySQL) open to the internet"),
    "postgresql": ("open-database-port", "Database port (PostgreSQL) open to the internet"),
    "ms-sql-s": ("open-database-port", "Database port (Microsoft SQL Server) open to the internet"),
    "mongodb": ("open-database-port", "Database port (MongoDB) open to the internet"),
    "redis": ("open-database-port", "Database port (Redis) open to the internet"),
}
_RISKY_PORTS = {21: "ftp", 23: "telnet", 3389: "ms-wbt-server", 3306: "mysql", 5432: "postgresql",
                1433: "ms-sql-s", 27017: "mongodb", 6379: "redis"}


def parse_nmap(text: str, warn: Warn = _noop) -> list[Issue]:
    """Open risky services and vulnerable versions from plain-text Nmap output."""
    issues: list[Issue] = []
    for line in text.splitlines():
        match = _NMAP_PORT_RE.match(line.strip())
        if not match:
            continue
        try:
            port, proto, state, service, version = match.groups()
            if state != "open":
                continue
            port_number = int(port)
            if not 0 < port_number < 65536:
                raise ValueError("port out of range")
            service_key = service.split("/")[-1].rstrip("?")
            rule = _RISKY_SERVICES.get(service_key) or _RISKY_SERVICES.get(_RISKY_PORTS.get(port_number, ""))
            where = f"Port {port}/{proto} ({service}): "
            if rule:
                issues.append(
                    Issue(name=rule[1], knowledge_id=rule[0], evidence=f"{where}{version or 'open'}".strip())
                )
            if version:
                issues.extend(banner_issues(version, where))
        except ValueError as exc:
            warn(f"Skipped an unreadable Nmap line: {exc}")
    return issues


# ------------------------------------------------------------------ http headers


def parse_header_block(text: str) -> tuple[dict[str, str], bool]:
    """Return (headers of the final response, whether that response was served over HTTPS).

    HackerTarget returns raw header blocks, one per response when redirects are followed.
    """
    blocks: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        line = line.rstrip()
        if line.upper().startswith("HTTP/"):
            current = {":status": line}
            blocks.append(current)
        elif ":" in line and current is not None:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            current[key] = f"{current[key]}, {value.strip()}" if key in current else value.strip()
    if not blocks:
        return {}, False
    https = False
    for block in blocks[:-1]:
        if block.get("location", "").lower().startswith("https://"):
            https = True
    final = blocks[-1]
    if "strict-transport-security" in final:
        https = True
    return final, https


def parse_httpheaders(text: str, warn: Warn = _noop) -> list[Issue]:
    headers, https = parse_header_block(text)
    if not headers:
        warn("HTTP header output contained no response headers")
        return []
    issues = analyze_headers(headers, https=https)
    for name in ("server", "x-powered-by"):
        if headers.get(name):
            issues.extend(banner_issues(headers[name], f"{name.title()} header: "))
    return issues


# ------------------------------------------------------------------ dns lookup


def parse_dns_records(text: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    for line in text.splitlines():
        if " : " not in line:
            continue
        rtype, _, value = line.partition(" : ")
        records.setdefault(rtype.strip().upper(), []).append(value.strip().strip('"'))
    return records


def parse_dnslookup(text: str, warn: Warn = _noop) -> list[Issue]:
    records = parse_dns_records(text)
    if not records:
        warn("DNS lookup output contained no records")
        return []
    issues: list[Issue] = []
    spf = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    if "MX" in records and not spf:
        issues.append(
            Issue(name="No SPF record for the email domain", knowledge_id="missing-spf",
                  evidence="Domain has MX records but no TXT record starting with v=spf1")
        )
    elif any(t.split()[-1].lower() in ("+all", "all") for t in spf):
        issues.append(
            Issue(name="SPF record allows any server to send email for the domain", knowledge_id="missing-spf",
                  evidence="SPF record ends in +all")
        )
    return issues


# ------------------------------------------------------------------ host search / reverse IP / subnet


def parse_hostsearch(text: str, known_hosts: set[str] | None = None, warn: Warn = _noop) -> list[Issue]:
    """Hostnames under the domain that are missing from the asset inventory."""
    known = {h.lower() for h in (known_hosts or set())}
    unknown: list[str] = []
    for row in csv.reader(io.StringIO(text)):
        if not row or not row[0].strip():
            continue
        if len(row) < 2:
            warn("Skipped a host search row without an IP column")
            continue
        host = row[0].strip().lower()
        if host not in known:
            unknown.append(host)
    if not unknown:
        return []
    return [
        Issue(
            name=f"{len(unknown)} public hostname(s) not in the asset inventory",
            knowledge_id="unknown-public-host",
            evidence="Hostnames found in public DNS data: " + ", ".join(sorted(unknown)),
        )
    ]


def parse_reverseip(text: str, warn: Warn = _noop) -> list[Issue]:
    hosts = [line.strip().lower() for line in text.splitlines() if line.strip() and " " not in line.strip()]
    if len(hosts) <= 1:
        return []
    return [
        Issue(
            name=f"Server is shared with {len(hosts) - 1} other website(s)",
            knowledge_id="shared-hosting",
            evidence=f"{len(hosts)} hostnames resolve to this IP address (names withheld)",
        )
    ]


def parse_subnetcalc(text: str) -> dict[str, str]:
    """Subnet facts as a dict. Context only; produces no findings."""
    facts: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            facts[key.strip().lower()] = value.strip()
    return facts


# ------------------------------------------------------------------ nikto (🚧 WIP endpoint)

_NIKTO_SKIP_RE = re.compile(
    r"^(Target (IP|Hostname|Port)|Start Time|End Time|Server:|\d+ requests|\d+ host\(s\) tested|SSL Info|No CGI)",
    re.IGNORECASE,
)
_NIKTO_RULES: list[tuple[re.Pattern[str], str | None, str]] = [
    (re.compile(r"x-frame-options header is not present", re.I), "missing-x-frame-options",
     "Missing X-Frame-Options header (clickjacking protection)"),
    (re.compile(r"x-content-type-options header is not set", re.I), "missing-x-content-type-options",
     "Missing X-Content-Type-Options header"),
    (re.compile(r"strict-transport-security", re.I), "missing-hsts", "Missing Strict-Transport-Security (HSTS) header"),
    (re.compile(r"directory indexing", re.I), "directory-listing", "Directory listing enabled"),
    (re.compile(r"\.git/", re.I), "exposed-git", "Exposed .git repository"),
    (re.compile(r"backup|\.bak\b|\.sql\b|\.zip\b|\.tar", re.I), "exposed-backup", "Backup file exposed on the web server"),
    (re.compile(r"/(wp-)?admin/|admin login", re.I), "admin-interface-exposed", "Admin interface reachable from the internet"),
    (re.compile(r"jquery", re.I), "outdated-jquery", "Outdated jQuery library"),
    (re.compile(r"apache.*appears to be outdated", re.I), "outdated-apache", "Outdated Apache HTTP Server"),
    (re.compile(r"x-powered-by|leaks inodes|server banner", re.I), "server-version-disclosure",
     "Server software version disclosure in HTTP headers"),
]


def parse_nikto(text: str, warn: Warn = _noop) -> list[Issue]:
    issues: list[Issue] = []
    for raw in text.splitlines():
        if not raw.startswith("+ "):
            continue
        line = raw[2:].strip()
        if not line or _NIKTO_SKIP_RE.match(line):
            continue
        for pattern, knowledge_id, name in _NIKTO_RULES:
            if pattern.search(line):
                issues.append(Issue(name=name, knowledge_id=knowledge_id, evidence=f"Nikto: {line}"))
                break
        else:
            # No rule matched: keep the scanner's own wording so nothing is silently dropped.
            issues.append(Issue(name=line[:120], severity=3.0, evidence=f"Nikto: {line}", description=line))
    return issues


# ------------------------------------------------------------------ openvas (🚧 WIP endpoint)


def parse_openvas(text: str, warn: Warn = _noop) -> list[Issue]:
    """OpenVAS results in CSV form (assumed export columns; verify against a real export)."""
    issues: list[Issue] = []
    reader = csv.DictReader(io.StringIO(text))
    for number, row in enumerate(reader, start=2):
        try:
            name = (row.get("NVT Name") or "").strip()
            if not name:
                raise ValueError("missing NVT Name")
            severity = float(row.get("CVSS") or "")
            cves = [c.strip().upper() for c in re.split(r"[,\s]+", row.get("CVEs") or "") if c.strip()]
            invalid = [c for c in cves if not CVE_RE.match(c)]
            if invalid:
                raise ValueError("unreadable CVE list")
            port = (row.get("Port") or "").strip()
            evidence = f"OpenVAS: port {port}/{(row.get('Port Protocol') or '').strip()}" if port else "OpenVAS"
            common = dict(severity=severity, evidence=evidence, description=(row.get("Summary") or "").strip())
            if cves:
                issues.extend(Issue(name=name, cve_id=cve, **common) for cve in cves)
            else:
                issues.append(Issue(name=name, **common))
        except (ValueError, TypeError, AttributeError) as exc:
            warn(f"Skipped OpenVAS row {number}: {exc}")
    return issues


PARSERS: dict[str, Callable[..., list[Issue]]] = {
    "nmap": parse_nmap,
    "httpheaders": parse_httpheaders,
    "dnslookup": parse_dnslookup,
    "hostsearch": parse_hostsearch,
    "reverseiplookup": parse_reverseip,
    "nikto": parse_nikto,
    "openvas": parse_openvas,
}
