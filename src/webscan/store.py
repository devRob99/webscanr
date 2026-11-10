"""Local state: the current raw findings, kept between commands in output/state/ (gitignored).

Findings are stored already normalized (asset aliases, redacted evidence). Each stored
finding has exactly one source; duplicates across sources are merged at prioritization time.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from webscan.context import RunContext
from webscan.models import Finding, FindingValidationError

RAW_FILE = "findings_raw.json"
RESULT_FILE = "prioritized.json"


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def load_raw(ctx: RunContext) -> list[Finding]:
    path = ctx.state_dir / RAW_FILE
    if not path.exists():
        return []
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        ctx.warn("Stored findings could not be read and were ignored.")
        return []
    findings = []
    for record in records if isinstance(records, list) else []:
        try:
            findings.append(Finding.from_dict(record))
        except (FindingValidationError, TypeError):
            ctx.warn("Skipped an unreadable stored finding.")
    return findings


def save_raw(ctx: RunContext, findings: list[Finding]) -> Path:
    path = ctx.state_dir / RAW_FILE
    _write_json(path, [f.to_dict() for f in findings])
    return path


def replace(ctx: RunContext, new: list[Finding], sources: set[str], assets: set[str] | None = None) -> list[Finding]:
    """Swap in fresh findings for the given sources (and assets), keeping everything else."""

    def superseded(finding: Finding) -> bool:
        return bool(set(finding.sources) & sources) and (assets is None or finding.asset_name in assets)

    merged = [f for f in load_raw(ctx) if not superseded(f)] + list(new)
    save_raw(ctx, merged)
    return merged


def save_result(ctx: RunContext, result_dict: dict[str, Any]) -> Path:
    path = ctx.state_dir / RESULT_FILE
    _write_json(path, result_dict)
    return path


def load_findings_file(ctx: RunContext, path: Path) -> list[Finding]:
    """Read findings from a JSON file: either a list, or an object with a "findings" list."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    records = data.get("findings", []) if isinstance(data, dict) else data
    findings = []
    for record in records if isinstance(records, list) else []:
        try:
            findings.append(Finding.from_dict(record))
        except (FindingValidationError, TypeError):
            ctx.warn("Skipped an unreadable finding in the input file.")
    return findings
