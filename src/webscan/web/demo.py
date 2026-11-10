"""Demo mode: results built from the project's bundled mock data. Makes no network requests."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from webscan.context import build_context
from webscan.pipeline import prioritize, run_demo_collection
from webscan.web.present import present

DEMO_TARGET = "demo.example.com"


@lru_cache(maxsize=1)
def demo_results(log_dir: Path | None = None) -> tuple[tuple[dict[str, Any], str], tuple[dict[str, Any], str]]:
    """(earlier scan, current scan), each as (result JSON, HTML report).

    Both come from the same mock collection `webscan demo` uses. Each leaves out a few
    different findings so that comparing them shows items fixed and items newly introduced.
    """
    ctx = build_context("web-demo", demo=True, log_dir=log_dir, env={})
    raw = sorted(run_demo_collection(ctx), key=lambda f: f.finding_id)
    earlier = [f for i, f in enumerate(raw) if i % 9 != 0]
    current = [f for i, f in enumerate(raw) if i % 11 != 4]
    return present(prioritize(ctx, earlier), ctx), present(prioritize(ctx, current), ctx)
