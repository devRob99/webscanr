"""Rebuild data/mock_results.json: the combined demo dataset of normalized, unscored findings.

It is produced by running every mock source through the real parsers, so it always matches
what `webscan demo` collects. Placeholder data only. Run: python scripts/build_mock_results.py
"""

import json
import tempfile
from pathlib import Path

from webscan.context import build_context
from webscan.pipeline import run_demo_collection

ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory() as tmp:
    ctx = build_context("build-mock-results", demo=True, output_dir=Path(tmp) / "o", log_dir=Path(tmp) / "l", env={})
    findings = run_demo_collection(ctx)

data = {
    "_comment": (
        "Combined demo dataset: normalized findings from the mock HackerTarget, Quantro, and local-check "
        "sources, before deduplication and scoring. Placeholder assets only. Try it with: "
        "webscan prioritize --input data/mock_results.json --example-config. "
        "Regenerate with scripts/build_mock_results.py."
    ),
    "findings": [f.to_dict() for f in findings],
}
out = ROOT / "data" / "mock_results.json"
out.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {len(findings)} findings to {out}")
