"""Board-ready HTML report and PDF export.

The HTML file is fully self-contained (inline CSS, no scripts, no external resources), so
opening or printing it never contacts another server.

PDF export tries, in order: WeasyPrint, Playwright, a locally installed Chrome/Chromium/Edge
in headless mode. If none is available the HTML report is still produced.
"""

from __future__ import annotations

import shutil
import subprocess  # noqa: S404 - used only to run a local browser with a fixed argument list
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from webscan.context import RunContext
from webscan.knowledge import base as kb
from webscan.models import PRIORITIES
from webscan.pipeline import ScanResult
from webscan.reporting.common import PRIORITY_COLORS, comparison_rows, display_title, spotlight
from webscan.summary import render_paragraph

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
GRADE_COLORS = {"A": "#2e7d32", "B": "#558b2f", "C": "#b58900", "D": "#e65100", "F": "#c62828"}

_BROWSER_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]
_BROWSER_NAMES = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "msedge"]


def build_view(result: ScanResult, ctx: RunContext, lang: str, alt_href: str | None = None) -> dict[str, Any]:
    """Everything the template needs, already redacted and translated."""
    ui = kb.ui(lang)
    r = ctx.redactor
    findings = result.findings
    by_id = {f.finding_id: f for f in findings}
    platform_names = kb._load(lang if lang in kb.LANGS else "en")["platform_names"]

    def batch_view(batch) -> dict[str, Any]:
        top = by_id.get(batch.finding_ids[0])
        return {
            "title": r(kb.batch_title(batch.key, lang, fallback=top.vulnerability_name if top else batch.title)),
            "count": batch.finding_count,
            "assets": [r(a) for a in batch.assets],
            "max_risk": f"{batch.max_risk_score:g}",
            "total_risk": f"{batch.total_risk:g}",
            "priority": batch.top_priority,
            "effort": ui[f"effort_{batch.effort}"],
        }

    fix_first = []
    for batch in result.summary.top_batches:
        top = by_id.get(batch.finding_ids[0])
        view = batch_view(batch)
        explanation = kb.explain(
            top.knowledge_id if top else None, lang, top.platform if top else None,
            fallback_title=top.vulnerability_name if top else "", fallback_description=top.description if top else "",
        )
        view.update(
            clears=ui["clears_text"].format(n=batch.finding_count, a=len(batch.assets)),
            why=r(explanation.why),
            steps=[r(s) for s in explanation.fix],
        )
        fix_first.append(view)

    assets: dict[str, dict[str, Any]] = {}
    for rank, finding in enumerate(findings, start=1):
        meta = ctx.assets.get(finding.asset_name)
        group = assets.setdefault(
            finding.asset_name,
            {
                "alias": r(finding.asset_name),
                "description": r(meta.description) if meta else "",
                "exposure": ui[f"exposure_{finding.exposure_tier}"],
                "criticality": ui[f"criticality_{finding.asset_criticality}"],
                "platform": platform_names.get(finding.platform or "", ""),
                "known": finding.asset_known,
                "findings": [],
            },
        )
        explanation = kb.explain(
            finding.knowledge_id, lang, finding.platform, fallback_title=finding.vulnerability_name,
            fallback_description=finding.description,
        )
        breakdown = finding.score_breakdown
        group["findings"].append(
            {
                "rank": rank,
                "finding_id": finding.finding_id,
                "title": r(display_title(finding, lang)),
                "priority": finding.priority,
                "risk": f"{finding.risk_score:g}",
                "cvss": f"{finding.base_severity:g}",
                "epss": f"{finding.epss_score:.2f}" if finding.epss_score is not None else "",
                "cve": finding.cve_id or "",
                "kev": finding.in_cisa_kev,
                "exploit": finding.has_known_exploit,
                "what": r(explanation.what),
                "why": r(explanation.why),
                "fix": [r(s) for s in explanation.fix],
                "platform_note": r(explanation.platform_note) if explanation.platform_note else "",
                "controlled": explanation.platform_controlled,
                "name": r(finding.vulnerability_name),
                "description": r(finding.description) if explanation.from_knowledge_base else "",
                "sources": finding.sources,
                "data_source": finding.data_source,
                "evidence": r(finding.evidence),
                "references": [r(ref) for ref in finding.references],
                "formula": breakdown.get("formula", ""),
                "override": bool(breakdown.get("override_applied")),
                "cis": [f"CIS {c}" for c in finding.cis_ig1],
                "nist": list(finding.nist_csf),
            }
        )

    names = kb.frameworks(lang)
    framework_blocks = []
    for key, heading, attr in (("cis_ig1", ui["cis_heading"], "cis_ig1"), ("nist_csf", ui["nist_heading"], "nist_csf")):
        tally: dict[str, int] = {}
        for finding in findings:
            for item in getattr(finding, attr):
                tally[item] = tally.get(item, 0) + 1
        rows = [
            {"id": item, "title": names[key].get(item, ""), "count": count}
            for item, count in sorted(tally.items(), key=lambda kv: [int(p) if p.isdigit() else p for p in
                                                                     kv[0].replace("-", ".").split(".")])
        ]
        framework_blocks.append({"heading": heading, "rows": rows})

    example = spotlight(findings)
    spotlight_text = ""
    if example:
        low, high = example["low"], example["high"]
        spotlight_text = r(
            ui["compare_spotlight"].format(
                low_name=display_title(low, lang), low_asset=low.asset_name, low_cvss=f"{low.base_severity:g}",
                low_rank=example["low_rank"], high_name=display_title(high, lang), high_asset=high.asset_name,
                high_cvss=f"{high.base_severity:g}", high_rank=example["high_rank"],
            )
        )
    comparison = [
        {
            "cvss_score": f"{a.base_severity:g}", "cvss_title": r(display_title(a, lang)), "cvss_asset": r(a.asset_name),
            "risk_score": f"{b.risk_score:g}", "risk_priority": b.priority, "risk_title": r(display_title(b, lang)),
            "risk_asset": r(b.asset_name),
        }
        for a, b in comparison_rows(findings)
    ]

    meta = dict(result.meta)
    meta["organization"] = r(meta.get("organization", ""))
    return {
        "lang": lang,
        "ui": ui,
        "meta": meta,
        "generated_date": str(meta.get("generated_at", ""))[:10],
        "summary": result.summary,
        "paragraph": r(render_paragraph(result.summary, lang, meta["organization"])),
        "grade_color": GRADE_COLORS[result.summary.grade],
        "priorities": PRIORITIES,
        "colors": PRIORITY_COLORS,
        "fix_first": fix_first,
        "batches": [batch_view(b) for b in result.batches],
        "assets": list(assets.values()),
        "frameworks": framework_blocks,
        "spotlight_text": spotlight_text,
        "comparison": comparison,
        "alt_href": alt_href,
    }


def render_html(result: ScanResult, ctx: RunContext, lang: str | None = None, alt_href: str | None = None) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template("report.html.j2").render(**build_view(result, ctx, lang or ctx.lang, alt_href))


def write_html(
    result: ScanResult, ctx: RunContext, path: Path, lang: str | None = None, alt_href: str | None = None
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, ctx, lang, alt_href), encoding="utf-8")
    return path


def find_browser() -> str | None:
    for candidate in _BROWSER_PATHS:
        if Path(candidate).is_file():
            return candidate
    for name in _BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def write_pdf(html_path: Path, pdf_path: Path) -> tuple[bool, str]:
    """Convert an HTML report to PDF. Returns (success, engine used or reason it failed)."""
    html_path, pdf_path = Path(html_path).resolve(), Path(pdf_path).resolve()
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]

        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return True, "weasyprint"
    except Exception:  # noqa: BLE001, S110 - not installed or native libraries missing: try the next engine
        pass
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(html_path.as_uri())
            page.pdf(path=str(pdf_path), format="Letter", print_background=True)
            browser.close()
        return True, "playwright"
    except Exception:  # noqa: BLE001, S110 - not installed: try the next engine
        pass
    browser_path = find_browser()
    if browser_path:
        try:
            subprocess.run(  # noqa: S603 - fixed argument list, no shell, local file only
                [browser_path, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--no-first-run",
                 "--disable-extensions", "--disable-background-networking",
                 f"--print-to-pdf={pdf_path}", html_path.as_uri()],
                check=True, capture_output=True, timeout=90,
            )
            if pdf_path.is_file() and pdf_path.stat().st_size > 0:
                return True, "headless browser"
        except (OSError, subprocess.SubprocessError):
            pass
    return False, "no PDF engine available (install the 'pdf' extra, Playwright, or Chrome); HTML report was kept"
