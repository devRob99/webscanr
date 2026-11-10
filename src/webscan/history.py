"""Scan history and change detection (optional later-phase feature).

Each prioritized run is recorded in a local SQLite file under output/state/ (gitignored).
Only already-normalized data is stored: asset aliases, never raw hostnames or IPs.
When a run differs from the previous one, a short alert is appended to a local file;
nothing is sent to any external notification service.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from webscan.context import RunContext
from webscan.knowledge import base as kb
from webscan.pipeline import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    data_mode TEXT NOT NULL,
    grade TEXT NOT NULL,
    grade_score REAL NOT NULL,
    total INTEGER NOT NULL,
    counts TEXT NOT NULL,
    findings TEXT NOT NULL
)
"""


def db_path(ctx: RunContext) -> Path:
    return ctx.state_dir / "history.sqlite"


def _connect(ctx: RunContext) -> sqlite3.Connection:
    path = db_path(ctx)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    return conn


def _row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["counts"] = json.loads(data["counts"])
    data["findings"] = json.loads(data["findings"])
    return data


def record_run(ctx: RunContext, result: ScanResult) -> int:
    findings = [
        {
            "finding_id": f.finding_id,
            "name": ctx.redactor.redact(f.vulnerability_name),
            "asset_name": f.asset_name,
            "risk_score": f.risk_score,
            "priority": f.priority,
            "cve_id": f.cve_id,
            "knowledge_id": f.knowledge_id,
        }
        for f in result.findings
    ]
    with closing(_connect(ctx)) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO runs (created_at, data_mode, grade, grade_score, total, counts, findings) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(UTC).isoformat(timespec="seconds"),
                result.meta.get("data_mode", "mock"),
                result.summary.grade,
                result.summary.grade_score,
                len(findings),
                json.dumps(result.summary.counts),
                json.dumps(findings),
            ),
        )
        run_id = int(cursor.lastrowid or 0)
    change = latest_changes(ctx)
    if change and (change["new"] or change["worse"]):
        alert = {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "run_id": run_id,
            "new_findings": len(change["new"]),
            "risk_increased": len(change["worse"]),
            "resolved": len(change["resolved"]),
            "grade": f"{change['previous']['grade']} -> {change['current']['grade']}",
        }
        alerts = ctx.output_dir / "alerts.jsonl"
        alerts.parent.mkdir(parents=True, exist_ok=True)
        with alerts.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert) + "\n")
    return run_id


def list_runs(ctx: RunContext, limit: int = 50) -> list[dict[str, Any]]:
    """Most recent runs first."""
    if not db_path(ctx).exists():
        return []
    with closing(_connect(ctx)) as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r) for r in rows]


def diff_runs(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    before = {f["finding_id"]: f for f in previous["findings"]}
    after = {f["finding_id"]: f for f in current["findings"]}
    worse = [
        {**after[i], "previous_risk_score": before[i]["risk_score"]}
        for i in after.keys() & before.keys()
        if after[i]["risk_score"] > before[i]["risk_score"]
    ]
    return {
        "previous": {k: previous[k] for k in ("id", "created_at", "grade", "total")},
        "current": {k: current[k] for k in ("id", "created_at", "grade", "total")},
        "new": sorted((after[i] for i in after.keys() - before.keys()), key=lambda f: -f["risk_score"]),
        "resolved": sorted((before[i] for i in before.keys() - after.keys()), key=lambda f: -f["risk_score"]),
        "worse": sorted(worse, key=lambda f: -f["risk_score"]),
    }


def latest_changes(ctx: RunContext) -> dict[str, Any] | None:
    runs = list_runs(ctx, limit=2)
    if len(runs) < 2:
        return None
    return diff_runs(runs[1], runs[0])


def render_changes(diff: dict[str, Any], ctx: RunContext, console: Console) -> None:
    ui = kb.ui(ctx.lang)
    prev, curr = diff["previous"], diff["current"]
    console.print(
        f"[bold]{ui['changes_heading']}[/bold]  "
        f"({prev['created_at']} {prev['grade']} -> {curr['created_at']} {curr['grade']})"
    )
    if not (diff["new"] or diff["resolved"] or diff["worse"]):
        console.print(ui["changes_none"])
        return
    for key, label in (("new", "changes_new"), ("worse", "changes_worse"), ("resolved", "changes_resolved")):
        if not diff[key]:
            continue
        table = Table(title=f"{ui[label]} ({len(diff[key])})", title_justify="left")
        table.add_column(ui["col_priority"])
        table.add_column(ui["col_risk"], justify="right")
        table.add_column(ui["col_asset"])
        table.add_column(ui["col_finding"], overflow="fold")
        for item in diff[key]:
            title = kb.explain(item.get("knowledge_id"), ctx.lang, fallback_title=item["name"]).title or item["name"]
            if item.get("cve_id"):
                title = f"{title} ({item['cve_id']})"
            risk = f"{item['risk_score']:g}"
            if "previous_risk_score" in item:
                risk = f"{item['previous_risk_score']:g} -> {risk}"
            table.add_row(ui[f"pri_{item['priority']}"], risk, ctx.redactor(item["asset_name"]), ctx.redactor(title))
        console.print(table)
