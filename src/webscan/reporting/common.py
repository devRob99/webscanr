"""Helpers shared by the terminal, export, and HTML reporters."""

from __future__ import annotations

from typing import Any

from webscan.knowledge import base as kb
from webscan.models import Finding
from webscan.scoring.engine import cvss_order

PRIORITY_COLORS = {"Critical": "#c62828", "High": "#e65100", "Medium": "#b58900", "Low": "#1565c0", "Info": "#6b7280"}


def display_title(finding: Finding, lang: str) -> str:
    """Plain-language title, with the CVE appended so same-type findings stay distinguishable."""
    explanation = kb.explain(finding.knowledge_id, lang, finding.platform, fallback_title=finding.vulnerability_name)
    title = explanation.title or finding.vulnerability_name
    return f"{title} ({finding.cve_id})" if finding.cve_id else title


def signals(finding: Finding, lang: str) -> list[str]:
    ui = kb.ui(lang)
    out: list[str] = []
    if finding.in_cisa_kev:
        out.append(ui["signal_kev"])
    elif finding.has_known_exploit:
        out.append(ui["signal_exploit"])
    if finding.epss_score is not None:
        out.append(f"{ui['signal_epss']} {finding.epss_score:.2f}")
    return out


def short_formula(finding: Finding) -> str:
    b = finding.score_breakdown
    if not b:
        return ""
    text = f"{b['cvss']:g} x {b['exposure_multiplier']:g} x {b['criticality_weight']:g} x {b['exploit_factor']:g}"
    return text + (" ^" if b.get("override_applied") else "")


def spotlight(findings: list[Finding]) -> dict[str, Any] | None:
    """The clearest example of risk ranking beating CVSS ordering.

    Picks the highest-ranked known-exploited finding with a medium CVSS score, and the
    highest-CVSS finding that WebScan ranks below it.
    """
    for low_rank, low in enumerate(findings, start=1):
        if not low.in_cisa_kev or low.base_severity >= 7.0:
            continue
        below = [(rank, f) for rank, f in enumerate(findings, start=1) if rank > low_rank]
        candidates = [(rank, f) for rank, f in below if f.base_severity >= 9.0 and f.asset_name != low.asset_name]
        if not candidates:
            continue
        high_rank, high = max(candidates, key=lambda item: (item[1].base_severity, -item[0]))
        return {"low": low, "low_rank": low_rank, "high": high, "high_rank": high_rank}
    return None


def comparison_rows(findings: list[Finding], limit: int = 5) -> list[tuple[Finding, Finding]]:
    """Pairs of (CVSS-order finding, WebScan-order finding) for a side-by-side view."""
    return list(zip(cvss_order(findings)[:limit], findings[:limit], strict=False))
