"""JSON and CSV export of prioritized results. Everything passes through the redaction layer."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from webscan.context import RunContext
from webscan.pipeline import ScanResult
from webscan.reporting.common import display_title

FINDING_COLUMNS = [
    "rank", "priority", "risk_score", "title", "vulnerability_name", "cve_id", "base_severity", "asset_name",
    "exposure_tier", "asset_criticality", "has_known_exploit", "in_cisa_kev", "epss_score", "remediation_key",
    "sources", "data_source", "knowledge_id", "cis_ig1", "nist_csf", "score_formula", "evidence", "finding_id",
]
BATCH_COLUMNS = [
    "rank", "fix", "remediation_key", "finding_count", "assets", "cves", "top_priority", "max_risk_score",
    "total_risk", "effort",
]


def _cell(value: Any) -> Any:
    """Flatten lists and neutralize spreadsheet formulas (CSV injection)."""
    if isinstance(value, (list, tuple)):
        value = "; ".join(str(v) for v in value)
    if value is None:
        return ""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def export_json(result: ScanResult, ctx: RunContext, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = ctx.redactor.redact_obj(result.to_dict())
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def export_csv(result: ScanResult, ctx: RunContext, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FINDING_COLUMNS)
        writer.writeheader()
        for rank, finding in enumerate(result.findings, start=1):
            row = finding.to_dict()
            row.update(
                rank=rank,
                title=display_title(finding, ctx.lang),
                score_formula=finding.score_breakdown.get("formula", ""),
            )
            writer.writerow({col: _cell(ctx.redactor.redact_obj(row.get(col))) for col in FINDING_COLUMNS})
    return path


def export_batches_csv(result: ScanResult, ctx: RunContext, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=BATCH_COLUMNS)
        writer.writeheader()
        for rank, batch in enumerate(result.batches, start=1):
            row = batch.to_dict()
            row.update(rank=rank, fix=batch.title, remediation_key=batch.key)
            writer.writerow({col: _cell(ctx.redactor.redact_obj(row.get(col))) for col in BATCH_COLUMNS})
    return path
