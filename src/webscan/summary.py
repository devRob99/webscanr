"""Executive summary: letter grade, "fix these 3 first", and a plain-language paragraph.

Grade formula (all numbers configurable in scoring.json under "grade"):

    grade_score = max(0, 100 - sum(penalty[priority] for each finding))
    A >= 90, B >= 80, C >= 70, D >= 60, otherwise F
    Any Critical finding caps the grade at D.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from webscan.knowledge import base as kb
from webscan.models import PRIORITIES, Batch, Finding

GRADES = ("A", "B", "C", "D", "F")


@dataclass
class Summary:
    grade: str
    grade_score: float
    grade_capped: bool
    counts: dict[str, int]
    total_findings: int
    assets_affected: int
    kev_count: int
    top_batches: list[Batch] = field(default_factory=list)
    top_batches_risk_share: float = 0.0  # share of total risk removed by the top batches (0-100)
    paragraph: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_grade(findings: list[Finding], cfg: dict[str, Any]) -> tuple[str, float, bool]:
    grade_cfg = cfg["grade"]
    penalty = sum(grade_cfg["penalties"].get(f.priority, 0) for f in findings)
    score = max(0.0, 100.0 - penalty)
    letter = "F"
    for candidate in ("A", "B", "C", "D"):
        if score >= grade_cfg["thresholds"][candidate]:
            letter = candidate
            break
    capped = False
    cap = grade_cfg.get("critical_caps_at", "D")
    if any(f.priority == "Critical" for f in findings) and GRADES.index(letter) < GRADES.index(cap):
        letter, capped = cap, True
    return letter, score, capped


def pick_fix_first(batches: list[Batch], count: int = 3) -> list[Batch]:
    """The "fix these first" list: the highest-ranked batches that clear a Critical or High finding.

    Batches are ranked by total risk removed. A batch made only of many low-priority items
    can outrank a single serious one on that measure, so urgent batches are taken first and
    the list is topped up from the remaining batches in rank order.
    """
    urgent = [b for b in batches if b.top_priority in ("Critical", "High")]
    rest = [b for b in batches if b not in urgent]
    return (urgent + rest)[:count]


def build_summary(
    findings: list[Finding], batches: list[Batch], cfg: dict[str, Any], lang: str = "en", organization: str = ""
) -> Summary:
    counts = {p: sum(1 for f in findings if f.priority == p) for p in PRIORITIES}
    grade, score, capped = compute_grade(findings, cfg)
    top = pick_fix_first(batches)
    total_risk = sum(f.risk_score for f in findings)
    share = round(sum(b.total_risk for b in top) / total_risk * 100, 0) if total_risk else 0.0
    summary = Summary(
        grade=grade,
        grade_score=score,
        grade_capped=capped,
        counts=counts,
        total_findings=len(findings),
        assets_affected=len({f.asset_name for f in findings}),
        kev_count=sum(1 for f in findings if f.in_cisa_kev or f.has_known_exploit),
        top_batches=top,
        top_batches_risk_share=share,
    )
    summary.paragraph = render_paragraph(summary, lang, organization)
    return summary


def render_paragraph(summary: Summary, lang: str, organization: str = "") -> str:
    ui = kb.ui(lang)
    org = organization or ui["the_organization"]
    if summary.total_findings == 0:
        return ui["summary_none"].format(org=org)
    parts = [
        ui["summary_counts"].format(
            org=org,
            total=summary.total_findings,
            assets=summary.assets_affected,
            critical=summary.counts["Critical"],
            high=summary.counts["High"],
            medium=summary.counts["Medium"],
            low=summary.counts["Low"] + summary.counts["Info"],
        )
    ]
    if summary.kev_count:
        parts.append(ui["summary_kev"].format(kev=summary.kev_count))
    parts.append(ui[f"summary_grade_{summary.grade}"])
    if summary.top_batches:
        parts.append(ui["summary_top"].format(n=len(summary.top_batches), share=int(summary.top_batches_risk_share)))
    return " ".join(parts)
