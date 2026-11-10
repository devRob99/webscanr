"""End-to-end pipeline: collect -> normalize/dedupe -> enrich -> score -> batch -> summarize."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from webscan import __version__
from webscan.batching.engine import build_batches
from webscan.config import Asset
from webscan.context import RunContext
from webscan.enrichment.reference import enrich, load_reference
from webscan.ingest.normalize import dedupe
from webscan.models import Batch, Finding
from webscan.providers.base import Provider
from webscan.providers.quantro.provider import QuantroProvider
from webscan.providers.registry import target_providers
from webscan.scope.enforcer import ScopeError
from webscan.scoring.engine import score_all
from webscan.summary import Summary, build_summary


@dataclass
class ScanResult:
    findings: list[Finding]
    batches: list[Batch]
    summary: Summary
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "summary": self.summary.to_dict(),
            "batches": [b.to_dict() for b in self.batches],
            "findings": [f.to_dict() for f in self.findings],
        }


def collect(ctx: RunContext, assets: list[Asset], providers: list[Provider]) -> list[Finding]:
    """Run providers against every target of the given assets.

    All targets are scope-checked up front; a single out-of-scope target halts the whole
    scan before any provider runs. Internal-only targets are never handed to external providers.
    """
    decisions = {}
    for asset in assets:
        for target in asset.targets:
            decision = ctx.scope.check(target)
            if not decision.in_scope:
                ctx.audit.log(
                    "scope_rejection", targets=[target], mode=ctx.mode_label, status="rejected",
                    detail=decision.reason,
                )
                raise ScopeError(
                    f"Asset '{asset.alias}' lists a target that is not in the approved inventory "
                    f"({decision.reason}). Nothing was scanned."
                )
            decisions[target] = decision

    findings: list[Finding] = []
    for asset in assets:
        for target in asset.targets:
            for provider in providers:
                if provider.is_external and not decisions[target].external_ok:
                    ctx.audit.log(
                        "provider_skipped", provider=provider.name, targets=[target], mode=ctx.mode_label,
                        status="skipped", detail="internal-only target is never sent to external providers",
                    )
                    continue
                findings.extend(provider.run(target))
    return findings


def prioritize(ctx: RunContext, raw_findings: list[Finding], bundled_reference: bool | None = None) -> ScanResult:
    """Dedupe, enrich with KEV/EPSS, score, sort, batch, and summarize."""
    started = time.perf_counter()
    bundled = ctx.demo if bundled_reference is None else bundled_reference
    reference = load_reference(ctx.settings.data_dir / "reference", bundled_only=bundled)
    if not reference.kev:
        ctx.warn("No CISA KEV snapshot found; known-exploited status is unavailable.")
    findings = dedupe(Finding.from_dict(f.to_dict()) for f in raw_findings)  # work on copies
    enrich(findings, reference)
    findings = score_all(findings, ctx.scoring_cfg)
    batches = build_batches(findings, ctx.lang)
    summary = build_summary(findings, batches, ctx.scoring_cfg, ctx.lang, ctx.assets.organization_alias)
    sources = {f.data_source for f in findings}
    meta = {
        "tool": "WebScan",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "organization": ctx.assets.organization_alias,
        "language": ctx.lang,
        "data_mode": "mock" if sources <= {"mock"} else ("live" if sources == {"live"} else "mixed"),
        "demo": ctx.demo,
        "redacted": not ctx.no_redact,
        "reference_data": {"kev": reference.kev_source, "epss": reference.epss_source},
        "raw_finding_count": len(raw_findings),
        "warnings": list(ctx.warnings),
    }
    ctx.audit.log(
        "prioritize", mode=meta["data_mode"], status="ok", findings=len(findings), batches=len(batches),
        grade=summary.grade, duration_ms=(time.perf_counter() - started) * 1000,
    )
    return ScanResult(findings, batches, summary, meta)


def run_demo_collection(ctx: RunContext, include_wip: bool = False) -> list[Finding]:
    """Collect raw findings from every mock source. Uses no network."""
    providers = target_providers(ctx, include_wip=include_wip)
    findings = collect(ctx, ctx.assets.assets, providers)
    findings.extend(QuantroProvider(ctx).ingest_file())
    return findings
