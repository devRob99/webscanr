"""Security header analysis, shared by the local header audit and the HackerTarget parser."""

from __future__ import annotations

import re
from collections.abc import Mapping

from webscan.models import Issue

_VERSION_RE = re.compile(r"\d+\.\d+")

_REQUIRED = (
    ("strict-transport-security", "missing-hsts", "Missing Strict-Transport-Security (HSTS) header"),
    ("content-security-policy", "missing-csp", "Missing Content-Security-Policy header"),
    ("x-content-type-options", "missing-x-content-type-options", "Missing X-Content-Type-Options header"),
    ("referrer-policy", "missing-referrer-policy", "Missing Referrer-Policy header"),
    ("permissions-policy", "missing-permissions-policy", "Missing Permissions-Policy header"),
)


def normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}


def analyze_headers(headers: Mapping[str, str], https: bool = True) -> list[Issue]:
    """Report missing security headers and headers that leak software versions."""
    h = normalize_headers(headers)
    issues: list[Issue] = []
    for name, knowledge_id, title in _REQUIRED:
        if name == "strict-transport-security" and not https:
            continue  # HSTS only counts on HTTPS responses
        if name not in h:
            issues.append(Issue(name=title, knowledge_id=knowledge_id, evidence=f"Response has no {name} header"))
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        issues.append(
            Issue(
                name="Missing X-Frame-Options header (clickjacking protection)",
                knowledge_id="missing-x-frame-options",
                evidence="Response has no x-frame-options header and no CSP frame-ancestors directive",
            )
        )
    if h.get("x-content-type-options") not in (None, "") and h["x-content-type-options"].lower() != "nosniff":
        issues.append(
            Issue(
                name="X-Content-Type-Options header is not set to nosniff",
                knowledge_id="missing-x-content-type-options",
                evidence=f"x-content-type-options: {h['x-content-type-options']}",
            )
        )
    leaks = []
    if _VERSION_RE.search(h.get("server", "")):
        leaks.append(f"Server: {h['server']}")
    if h.get("x-powered-by"):
        leaks.append(f"X-Powered-By: {h['x-powered-by']}")
    if leaks:
        issues.append(
            Issue(
                name="Server software version disclosure in HTTP headers",
                knowledge_id="server-version-disclosure",
                evidence="; ".join(leaks),
            )
        )
    return issues
