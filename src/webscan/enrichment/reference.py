"""Exploitability enrichment from local CISA KEV and EPSS snapshots.

Scoring reads only local files, so no finding or target data leaves the machine.
``refresh()`` downloads the two public catalogs; it sends nothing about the organization.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from webscan.models import CVE_RE, Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

KEV_BUNDLED, KEV_FULL = "kev_snapshot.json", "kev_full.json"
EPSS_BUNDLED, EPSS_FULL = "epss_snapshot.csv", "epss_full.csv.gz"


class ReferenceDataError(Exception):
    pass


@dataclass
class ReferenceData:
    kev: set[str] = field(default_factory=set)
    epss: dict[str, float] = field(default_factory=dict)
    kev_source: str = "none"
    epss_source: str = "none"


def parse_kev(text: str) -> set[str]:
    data = json.loads(text)
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ReferenceDataError("KEV file has no 'vulnerabilities' list")
    cves = {str(i.get("cveID", "")).upper() for i in items if isinstance(i, dict)}
    cves = {c for c in cves if CVE_RE.match(c)}
    if not cves:
        raise ReferenceDataError("KEV file contains no CVE IDs")
    return cves


def parse_epss(text: str) -> dict[str, float]:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    scores: dict[str, float] = {}
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        cve = (row.get("cve") or "").upper()
        try:
            score = float(row.get("epss") or "")
        except ValueError:
            continue
        if CVE_RE.match(cve) and 0.0 <= score <= 1.0:
            scores[cve] = score
    if not scores:
        raise ReferenceDataError("EPSS file contains no scores")
    return scores


def _read(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def load_reference(reference_dir: Path, bundled_only: bool = False) -> ReferenceData:
    """Load KEV and EPSS, preferring refreshed full files unless ``bundled_only``."""
    ref = ReferenceData()
    kev_candidates = [KEV_BUNDLED] if bundled_only else [KEV_FULL, KEV_BUNDLED]
    epss_candidates = [EPSS_BUNDLED] if bundled_only else [EPSS_FULL, EPSS_BUNDLED]
    for name in kev_candidates:
        path = reference_dir / name
        if path.exists():
            try:
                ref.kev, ref.kev_source = parse_kev(_read(path)), name
                break
            except (OSError, ValueError, ReferenceDataError):
                continue
    for name in epss_candidates:
        path = reference_dir / name
        if path.exists():
            try:
                ref.epss, ref.epss_source = parse_epss(_read(path)), name
                break
            except (OSError, ValueError, ReferenceDataError):
                continue
    return ref


def enrich(findings: Iterable[Finding], ref: ReferenceData) -> None:
    """Set in_cisa_kev, has_known_exploit, and epss_score from the local snapshots."""
    for finding in findings:
        if not finding.cve_id:
            continue
        if finding.cve_id in ref.kev:
            finding.in_cisa_kev = True
            finding.has_known_exploit = True
        if finding.cve_id in ref.epss:
            finding.epss_score = ref.epss[finding.cve_id]


def _download(url: str) -> bytes:
    import requests

    response = requests.get(url, timeout=60, headers={"User-Agent": "WebScan reference-data refresh"})
    response.raise_for_status()
    return response.content


def _atomic_write(path: Path, content: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(content)
    os.replace(tmp, path)


def refresh(reference_dir: Path, download: Callable[[str], bytes] = _download) -> dict[str, int]:
    """Download the public KEV and EPSS files, validate them, then replace the local copies.

    Only two fixed public URLs are requested. No target, finding, or organization data is sent.
    """
    reference_dir.mkdir(parents=True, exist_ok=True)
    kev_raw = download(KEV_URL)
    kev = parse_kev(kev_raw.decode("utf-8"))
    epss_raw = download(EPSS_URL)
    try:
        epss_text = gzip.decompress(epss_raw).decode("utf-8")
    except (OSError, EOFError) as exc:
        raise ReferenceDataError("EPSS download is not a gzip file") from exc
    epss = parse_epss(epss_text)
    _atomic_write(reference_dir / KEV_FULL, kev_raw)
    _atomic_write(reference_dir / EPSS_FULL, epss_raw)
    return {"kev": len(kev), "epss": len(epss)}
