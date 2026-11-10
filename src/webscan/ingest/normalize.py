"""Normalization: turn provider Issues into Findings, and merge duplicates across sources."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from webscan.knowledge import base as kb
from webscan.models import Finding, FindingValidationError, Issue

if TYPE_CHECKING:
    from webscan.context import RunContext


def build_finding(ctx: RunContext, host: str, issue: Issue, source: str, data_source: str) -> Finding | None:
    """Attach asset context and knowledge-base metadata to an Issue.

    Returns None (after logging a redacted warning) when the record is invalid, so one bad
    record never stops ingestion.
    """
    try:
        target = issue.host or host
        if not target:
            raise FindingValidationError("record does not name a host")
        resolved = ctx.assets.resolve(target)
        if not resolved.known:
            ctx.warn(
                f"A finding refers to an asset that is not in assets_metadata ({resolved.alias}). "
                "Using conservative defaults (public, criticality 2). Add it to the inventory."
            )
        entry = kb.match(issue.name, issue.cve_id, issue.knowledge_id, issue.description)
        severity = issue.severity
        if severity is None:
            severity = entry.default_severity if entry else 0.0
        return Finding(
            vulnerability_name=ctx.redactor(issue.name).strip(),
            cve_id=issue.cve_id or None,
            base_severity=severity,
            asset_name=resolved.alias,
            exposure_tier=resolved.exposure_tier,
            asset_criticality=resolved.asset_criticality,
            has_known_exploit=bool(issue.has_known_exploit),
            sources=[source],
            remediation_key=issue.remediation_key or (entry.remediation_key if entry else None),
            evidence=ctx.redactor(issue.evidence),
            references=[ctx.redactor(r) for r in issue.references if isinstance(r, str)],
            knowledge_id=entry.id if entry else None,
            cis_ig1=list(entry.cis_ig1) if entry else [],
            nist_csf=list(entry.nist_csf) if entry else [],
            data_source=data_source,
            description=ctx.redactor(issue.description),
            platform=resolved.platform,
            asset_known=resolved.known,
        )
    except (FindingValidationError, TypeError, ValueError) as exc:
        ctx.warn(f"Skipped a malformed record from '{source}': {exc}")
        return None


def build_findings(
    ctx: RunContext, host: str, issues: Iterable[Issue], source: str, data_source: str
) -> list[Finding]:
    built = (build_finding(ctx, host, issue, source, data_source) for issue in issues)
    return [f for f in built if f is not None]


def _merge_text(first: str, second: str) -> str:
    if not second or second in first:
        return first
    return f"{first} | {second}" if first else second


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings that describe the same problem on the same asset; keep every source."""
    merged: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = finding.dedup_key
        kept = merged.get(key)
        if kept is None:
            merged[key] = finding
            continue
        kept.sources = sorted({*kept.sources, *finding.sources})
        if finding.base_severity > kept.base_severity:
            kept.base_severity = finding.base_severity
        kept.has_known_exploit = kept.has_known_exploit or finding.has_known_exploit
        kept.in_cisa_kev = kept.in_cisa_kev or finding.in_cisa_kev
        kept.evidence = _merge_text(kept.evidence, finding.evidence)
        kept.description = kept.description or finding.description
        kept.references = list(dict.fromkeys([*kept.references, *finding.references]))
        kept.remediation_key = kept.remediation_key or finding.remediation_key
        kept.knowledge_id = kept.knowledge_id or finding.knowledge_id
        if "live" in (kept.data_source, finding.data_source):
            kept.data_source = "live"
    return list(merged.values())
