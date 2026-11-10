"""Remediation batching: group findings that one fix clears.

Findings are grouped by ``remediation_key`` (for example ``upgrade:jquery>=3.5.0`` clears
several CVEs on several assets). Findings without a key fall back to their normalized name,
so the same vulnerability on many assets still becomes one task. Batches are ranked by the
total risk they remove.
"""

from __future__ import annotations

from collections.abc import Iterable

from webscan.knowledge import base as kb
from webscan.models import PRIORITIES, Batch, Finding, normalize_name


def batch_key(finding: Finding) -> str:
    return finding.remediation_key or f"fix:{normalize_name(finding.vulnerability_name)}"


def build_batches(findings: Iterable[Finding], lang: str = "en") -> list[Batch]:
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        key = batch_key(finding)
        if key.startswith("info:"):
            continue  # informational notes are not remediation tasks
        groups.setdefault(key, []).append(finding)

    batches: list[Batch] = []
    for key, members in groups.items():
        members.sort(key=lambda f: -f.risk_score)
        top = members[0]
        entry = kb.entry_for_remediation_key(key) or kb.get_entry(top.knowledge_id)
        batches.append(
            Batch(
                key=key,
                title=kb.batch_title(key, lang, fallback=top.vulnerability_name),
                finding_ids=[f.finding_id for f in members],
                finding_count=len(members),
                assets=sorted({f.asset_name for f in members}),
                cves=sorted({f.cve_id for f in members if f.cve_id}),
                max_risk_score=top.risk_score,
                total_risk=round(sum(f.risk_score for f in members), 1),
                top_priority=min((f.priority for f in members), key=PRIORITIES.index),
                effort=entry.effort if entry else "moderate",
                knowledge_id=entry.id if entry else top.knowledge_id,
            )
        )
    batches.sort(key=lambda b: (-b.total_risk, -b.max_risk_score, b.key))
    return batches
