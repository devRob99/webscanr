"""Quantro provider: reads a report file the partner delivered. Makes no network calls.

STATUS: 🚧 WIP - built against an assumed schema. See parser.py and docs/providers/quantro.md.
"""

from __future__ import annotations

import time
from pathlib import Path

from webscan.ingest.normalize import build_findings
from webscan.models import Finding
from webscan.providers.base import Provider
from webscan.providers.quantro.parser import QuantroFormatError, load_report, parse_report
from webscan.scope.enforcer import ScopeDecision


class QuantroProvider(Provider):
    name = "quantro"
    is_external = False  # local file ingestion only
    wip = True

    def __init__(self, ctx, report_path: Path | None = None) -> None:
        super().__init__(ctx)
        self.report_path = Path(report_path) if report_path else None

    @property
    def mock_report(self) -> Path:
        return self.ctx.settings.data_dir / "mock" / "quantro_report.json"

    def _is_mock(self, path: Path) -> bool:
        return path.resolve() == self.mock_report.resolve()

    def ingest_file(self, path: Path | None = None) -> list[Finding]:
        """Ingest every record in a report. Raises QuantroFormatError if the file is unusable."""
        path = Path(path or self.report_path or self.mock_report)
        started = time.perf_counter()
        mode = "mock" if self._is_mock(path) else "live"
        try:
            data = load_report(path)
            mapping = self.ctx.providers_cfg["quantro"]["field_mapping"]
            issues = parse_report(data, mapping, self.ctx.warn)
        except QuantroFormatError as exc:
            self.ctx.audit.log(
                "quantro_ingest", provider=self.name, mode=mode, status="error", detail=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )
            raise
        findings = build_findings(self.ctx, "", issues, self.name, mode)
        self.ctx.audit.log(
            "quantro_ingest", provider=self.name, mode=mode, status="ok",
            targets=sorted({i.host for i in issues if i.host}), findings=len(findings),
            duration_ms=(time.perf_counter() - started) * 1000,
        )
        return findings

    def _collect(self, target: str, decision: ScopeDecision, live: bool) -> list[Finding]:
        """Findings in the configured report that belong to one target."""
        path = self.report_path or (self.mock_report if self.ctx.demo else None)
        if path is None:
            return []
        data = load_report(path)
        issues = parse_report(data, self.ctx.providers_cfg["quantro"]["field_mapping"], self.ctx.warn)
        mine = [i for i in issues if i.host == target.lower()]
        return build_findings(self.ctx, target, mine, self.name, "mock" if self._is_mock(path) else "live")
