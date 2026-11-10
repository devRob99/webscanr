"""Color-coded terminal summary (rich). All dynamic text passes through the redactor."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from webscan.context import RunContext
from webscan.knowledge import base as kb
from webscan.models import PRIORITIES
from webscan.pipeline import ScanResult
from webscan.reporting.common import comparison_rows, display_title, short_formula, signals, spotlight

PRIORITY_STYLES = {
    "Critical": "bold red",
    "High": "dark_orange",
    "Medium": "yellow",
    "Low": "blue",
    "Info": "dim",
}
GRADE_STYLES = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold red"}


def _priority(priority: str, ui: dict[str, str]) -> Text:
    return Text(ui[f"pri_{priority}"], style=PRIORITY_STYLES[priority])


def render(result: ScanResult, ctx: RunContext, console: Console | None = None, top: int = 10) -> None:
    console = console or Console()
    lang = ctx.lang
    ui = kb.ui(lang)
    r = ctx.redactor
    summary = result.summary
    findings = result.findings

    # --- header -------------------------------------------------------------------------
    header = Text()
    header.append(f"{r(result.meta.get('organization', ''))}\n", style="bold")
    header.append(f"{ui['overall_grade']}: ")
    header.append(summary.grade, style=GRADE_STYLES[summary.grade])
    header.append(f"   {ui['findings_total']}: {summary.total_findings}\n")
    if result.meta.get("data_mode") == "live":
        header.append(ui["live_banner"], style="bold green")
    else:
        header.append(ui["mock_banner"], style="bold magenta")
    console.print(Panel(header, title=ui["app_title"], border_style="cyan"))

    console.print(Panel(r(summary.paragraph), title=ui["heading_exec_summary"], border_style="white"))

    # --- counts -------------------------------------------------------------------------
    counts = Table(title=ui["heading_summary"], title_justify="left")
    counts.add_column(ui["col_priority"])
    counts.add_column(ui["col_count"], justify="right")
    for priority in PRIORITIES:
        counts.add_row(_priority(priority, ui), str(summary.counts[priority]))
    console.print(counts)

    # --- prioritization vs CVSS ---------------------------------------------------------
    if len(findings) >= 2:
        compare = Table(title=ui["heading_compare"], title_justify="left", caption=ui["compare_intro"],
                        caption_justify="left")
        compare.add_column(ui["col_rank"], justify="right")
        compare.add_column(ui["compare_cvss"], overflow="fold")
        compare.add_column(ui["compare_webscan"], overflow="fold")
        for index, (by_cvss, by_risk) in enumerate(comparison_rows(findings), start=1):
            left = Text(f"CVSS {by_cvss.base_severity:g}  ", style="dim")
            left.append(r(f"{display_title(by_cvss, lang)} - {by_cvss.asset_name}"))
            right = _priority(by_risk.priority, ui)
            right.append(f" {by_risk.risk_score:g}  ", style="default")
            right.append(r(f"{display_title(by_risk, lang)} - {by_risk.asset_name}"), style="default")
            compare.add_row(str(index), left, right)
        console.print(compare)
        example = spotlight(findings)
        if example:
            low, high = example["low"], example["high"]
            console.print(
                Panel(
                    r(
                        ui["compare_spotlight"].format(
                            low_name=display_title(low, lang), low_asset=low.asset_name,
                            low_cvss=f"{low.base_severity:g}", low_rank=example["low_rank"],
                            high_name=display_title(high, lang), high_asset=high.asset_name,
                            high_cvss=f"{high.base_severity:g}", high_rank=example["high_rank"],
                        )
                    ),
                    border_style="green",
                )
            )

    # --- top findings -------------------------------------------------------------------
    table = Table(title=ui["heading_top_findings"], title_justify="left")
    table.add_column(ui["col_rank"], justify="right")
    table.add_column(ui["col_priority"])
    table.add_column(ui["col_risk"], justify="right")
    table.add_column(ui["col_cvss"], justify="right")
    table.add_column(ui["col_asset"], overflow="fold", min_width=12)
    table.add_column(ui["col_finding"], overflow="fold", ratio=1, min_width=18)
    table.add_column(ui["col_signals"])
    table.add_column(ui["col_why"], no_wrap=True)
    for rank, finding in enumerate(findings[:top], start=1):
        style = PRIORITY_STYLES[finding.priority]
        asset = r(finding.asset_name) + ("" if finding.asset_known else " *")
        table.add_row(
            str(rank), _priority(finding.priority, ui), Text(f"{finding.risk_score:g}", style=style),
            f"{finding.base_severity:g}", asset, r(display_title(finding, lang)),
            Text(", ".join(signals(finding, lang)), style="bold red" if finding.in_cisa_kev else ""),
            short_formula(finding),
        )
    if not findings:
        console.print(ui["no_findings"])
    else:
        console.print(table)
        console.print(f"  {ui['calc_note']}", style="dim")
        if any(not f.asset_known for f in findings[:top]):
            console.print(f"  * {ui['unlisted_asset']}", style="dim")
        if any(f.score_breakdown.get("override_applied") for f in findings[:top]):
            console.print(f"  ^ {ui['override_note']}", style="dim")

    # --- batches ------------------------------------------------------------------------
    if result.batches:
        batches = Table(title=ui["heading_batches"], title_justify="left")
        batches.add_column(ui["col_rank"], justify="right")
        batches.add_column(ui["col_fix"], overflow="fold")
        batches.add_column(ui["col_clears"], justify="right")
        batches.add_column(ui["col_assets"], overflow="fold")
        batches.add_column(ui["col_top_risk"], justify="right")
        batches.add_column(ui["col_total_risk"], justify="right")
        batches.add_column(ui["col_effort"])
        for rank, batch in enumerate(result.batches[:8], start=1):
            batches.add_row(
                str(rank), r(batch.title), str(batch.finding_count), r(", ".join(batch.assets)),
                Text(f"{batch.max_risk_score:g}", style=PRIORITY_STYLES[batch.top_priority]),
                f"{batch.total_risk:g}", ui[f"effort_{batch.effort}"],
            )
        console.print(batches)

        fix_first = Text()
        for rank, batch in enumerate(summary.top_batches, start=1):
            fix_first.append(f"{rank}. {r(batch.title)}\n", style="bold")
            fix_first.append(
                "   " + ui["clears_text"].format(n=batch.finding_count, a=len(batch.assets)) + "\n", style="dim"
            )
            first = next((f for f in findings if f.finding_id == batch.finding_ids[0]), None)
            if first:
                steps = kb.explain(first.knowledge_id, lang, first.platform, first.vulnerability_name).fix
                if steps:
                    fix_first.append(f"   {ui['first_step']}: {r(steps[0])}\n")
        console.print(Panel(fix_first, title=ui["heading_fix_first"], border_style="green"))

    if result.meta.get("warnings"):
        notes = "\n".join(f"- {r(w)}" for w in result.meta["warnings"])
        console.print(Panel(notes, title=ui["heading_warnings"], border_style="yellow"))
