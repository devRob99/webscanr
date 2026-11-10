"""Turns a prioritized ScanResult into the JSON the UI shows, reusing the report view builder."""

from __future__ import annotations

from typing import Any

from webscan.context import RunContext
from webscan.pipeline import ScanResult
from webscan.reporting.html_report import build_view, render_html


def present(result: ScanResult, ctx: RunContext, lang: str = "en") -> tuple[dict[str, Any], str]:
    """Return (result JSON for the UI and JSON export, self-contained HTML report)."""
    view = build_view(result, ctx, lang)
    findings: list[dict[str, Any]] = []
    for asset in view["assets"]:
        for finding in asset["findings"]:
            findings.append(
                {
                    **finding,
                    "asset": asset["alias"],
                    "asset_description": asset["description"],
                    "exposure": asset["exposure"],
                    "platform": asset["platform"],
                }
            )
    findings.sort(key=lambda f: f["rank"])
    summary = result.summary
    data = {
        "summary": {
            "grade": summary.grade,
            "grade_score": summary.grade_score,
            "counts": summary.counts,
            "total": summary.total_findings,
            "assets_affected": summary.assets_affected,
            "known_exploited": summary.kev_count,
            "paragraph": view["paragraph"],
        },
        "fix_first": view["fix_first"],
        "batches": view["batches"],
        "findings": findings,
        "warnings": list(result.meta.get("warnings", [])),
        "meta": {k: view["meta"].get(k) for k in ("tool", "version", "generated_at", "data_mode", "reference_data")},
        # The scanner's own export shape (same as `webscan report --format json`), redacted.
        "export": ctx.redactor.redact_obj(result.to_dict()),
    }
    return data, render_html(result, ctx, lang)
