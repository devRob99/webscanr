"""Quantro report ingestion.

STATUS: 🚧 WIP - the real Quantro export format is unknown. This parser reads the ASSUMED
JSON schema in data/mock/quantro_report.json and is driven entirely by the field mapping
in config/providers.json ("quantro.field_mapping"), so it can be re-pointed at the real
format without code changes. See docs/providers/quantro.md.

TODO: replace the assumed schema once a sanitized real report is available.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from webscan.models import Issue

Warn = Callable[[str], None]


class QuantroFormatError(Exception):
    """The report as a whole could not be read (bad JSON, findings list not found)."""


def dig(obj: Any, path: str | None) -> Any:
    """Follow a dotted path ("a.b.0.c") through dicts and lists; None when anything is missing."""
    if not path:
        return None
    current = obj
    for part in str(path).split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def _to_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "y", "1")
    return bool(value)


def _severity(record: dict[str, Any], fields: dict[str, str], label_scores: dict[str, float]) -> float:
    raw = dig(record, fields.get("base_severity"))
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw.strip())
        except ValueError:
            pass
    label = dig(record, fields.get("severity_label"))
    if isinstance(label, str) and label.strip().lower() in label_scores:
        return float(label_scores[label.strip().lower()])
    raise ValueError("no usable severity score or label")


def parse_report(data: Any, mapping: dict[str, Any], warn: Warn = lambda _m: None) -> list[Issue]:
    """Convert a loaded Quantro report into Issues using the configured field mapping."""
    fields: dict[str, str] = mapping.get("fields", {})
    label_scores = {str(k).lower(): float(v) for k, v in mapping.get("severity_label_scores", {}).items()}
    records = dig(data, mapping.get("findings_path", "findings")) if mapping.get("findings_path") else data
    if not isinstance(records, list):
        raise QuantroFormatError("could not find the list of findings; check quantro.field_mapping.findings_path")

    issues: list[Issue] = []
    for index, record in enumerate(records, start=1):
        try:
            if not isinstance(record, dict):
                raise ValueError("record is not an object")
            name = dig(record, fields.get("vulnerability_name"))
            host = dig(record, fields.get("host"))
            if not isinstance(name, str) or not name.strip():
                raise ValueError("missing vulnerability name")
            if not isinstance(host, str) or not host.strip():
                raise ValueError("missing host")
            cve = dig(record, fields.get("cve_id"))
            if isinstance(cve, list):
                cve = cve[0] if cve else None
            cve = cve.strip() if isinstance(cve, str) and cve.strip() else None
            references = dig(record, fields.get("references")) or []
            if isinstance(references, str):
                references = [references]
            issues.append(
                Issue(
                    name=name.strip(),
                    severity=_severity(record, fields, label_scores),
                    cve_id=cve,
                    evidence=str(dig(record, fields.get("evidence")) or ""),
                    description=str(dig(record, fields.get("description")) or ""),
                    references=[r for r in references if isinstance(r, str)],
                    has_known_exploit=_to_bool(dig(record, fields.get("has_known_exploit"))),
                    host=host.strip().lower(),
                )
            )
        except (ValueError, TypeError, AttributeError) as exc:
            warn(f"Skipped Quantro record #{index}: {exc}")
    return issues


def load_report(path: Path) -> Any:
    try:
        with Path(path).open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise QuantroFormatError("report file not found") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise QuantroFormatError(f"report is not readable JSON ({exc.__class__.__name__})") from exc
