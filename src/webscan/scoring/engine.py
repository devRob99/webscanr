"""Risk scoring.

    Risk Score = CVSS Base x Exposure Multiplier x Asset Criticality Weight x Exploit Factor

The raw product is normalized to 0-100 by dividing by the largest product the configured
multipliers allow, then mapped to a priority band. Findings in CISA KEV or with a known
exploit are never ranked below the configured minimum (High by default). Every finding
keeps a breakdown of the calculation so a reviewer can see why it ranked where it did.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from webscan.models import PRIORITIES, Finding


def max_raw_score(cfg: dict[str, Any]) -> float:
    return (
        10.0
        * max(cfg["exposure_multipliers"].values())
        * max(cfg["criticality_weights"].values())
        * max(cfg["exploit_factors"].values())
    )


def band_for(score: float, cfg: dict[str, Any]) -> str:
    for priority in PRIORITIES:  # ordered Critical -> Info
        if score >= cfg["bands"][priority]:
            return priority
    return "Info"


def exploit_factor(finding: Finding, cfg: dict[str, Any]) -> tuple[float, str]:
    factors = cfg["exploit_factors"]
    if finding.in_cisa_kev:
        return factors["known_exploit"], "cisa_kev"
    if finding.has_known_exploit:
        return factors["known_exploit"], "known_exploit"
    if finding.epss_score is not None and finding.epss_score >= cfg["epss_threshold"]:
        return factors["epss_high"], "epss_high"
    return factors["none"], "none"


def score_finding(finding: Finding, cfg: dict[str, Any]) -> Finding:
    exposure = cfg["exposure_multipliers"][finding.exposure_tier]
    criticality = cfg["criticality_weights"][str(finding.asset_criticality)]
    exploit, reason = exploit_factor(finding, cfg)
    raw = finding.base_severity * exposure * criticality * exploit
    ceiling = max_raw_score(cfg)
    normalized = round(min(100.0, raw / ceiling * 100.0), 1)
    priority = band_for(normalized, cfg)

    override = False
    floor_priority = cfg["exploit_override_min_priority"]
    if reason in ("cisa_kev", "known_exploit") and PRIORITIES.index(priority) > PRIORITIES.index(floor_priority):
        override = True
        priority = floor_priority
        normalized = max(normalized, float(cfg["bands"][floor_priority]))

    finding.risk_score = normalized
    finding.priority = priority
    finding.score_breakdown = {
        "cvss": finding.base_severity,
        "exposure_tier": finding.exposure_tier,
        "exposure_multiplier": exposure,
        "asset_criticality": finding.asset_criticality,
        "criticality_weight": criticality,
        "exploit_factor": exploit,
        "exploit_reason": reason,
        "raw_score": round(raw, 2),
        "max_raw_score": round(ceiling, 2),
        "normalized_before_override": round(min(100.0, raw / ceiling * 100.0), 1),
        "override_applied": override,
        "formula": (
            f"{finding.base_severity:g} x {exposure:g} x {criticality:g} x {exploit:g} = {raw:.2f} "
            f"-> {raw:.2f} / {ceiling:g} x 100 = {min(100.0, raw / ceiling * 100.0):.1f}"
        ),
    }
    return finding


def sort_key(finding: Finding) -> tuple[float, float, float, str]:
    """Highest risk first; ties broken by EPSS, then CVSS (then id, for a stable order)."""
    return (-finding.risk_score, -(finding.epss_score or 0.0), -finding.base_severity, finding.finding_id)


def score_all(findings: Iterable[Finding], cfg: dict[str, Any]) -> list[Finding]:
    return sorted((score_finding(f, cfg) for f in findings), key=sort_key)


def cvss_order(findings: Iterable[Finding]) -> list[Finding]:
    """What a plain CVSS-sorted scanner report would show (used for the comparison view)."""
    return sorted(findings, key=lambda f: (-f.base_severity, f.finding_id))
