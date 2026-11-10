"""Standardized data contract shared by every provider, the scoring engine, and the reports."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field, fields
from typing import Any

EXPOSURE_TIERS = ("public", "internal", "staging")
PRIORITIES = ("Critical", "High", "Medium", "Low", "Info")
DATA_SOURCES = ("live", "mock")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


class FindingValidationError(ValueError):
    """Raised when a Finding is created with values outside the data contract."""


def normalize_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


@dataclass
class Issue:
    """A provider-neutral observation produced by a parser, before asset context is attached.

    Parsers stay pure (raw text in, issues out). ``ingest.normalize.build_finding`` turns an
    Issue into a Finding by attaching the asset alias, exposure tier, and criticality.
    """

    name: str
    severity: float | None = None  # None -> use the knowledge catalog default
    cve_id: str | None = None
    knowledge_id: str | None = None
    evidence: str = ""
    description: str = ""
    references: list[str] = field(default_factory=list)
    has_known_exploit: bool = False
    remediation_key: str | None = None
    host: str | None = None  # set when the raw record names its own host (e.g. Quantro)


@dataclass
class Finding:
    # --- required contract fields (names fixed by the project spec) ---
    vulnerability_name: str
    cve_id: str | None
    base_severity: float  # CVSS or partner score, 0.0-10.0
    asset_name: str  # asset alias from assets_metadata, not a raw hostname
    exposure_tier: str  # "public" | "internal" | "staging"
    asset_criticality: int  # 1 (Low) to 3 (Critical)
    has_known_exploit: bool
    # --- supporting fields ---
    finding_id: str = ""
    sources: list[str] = field(default_factory=list)
    epss_score: float | None = None
    in_cisa_kev: bool = False
    risk_score: float = 0.0
    priority: str = "Info"
    remediation_key: str | None = None
    evidence: str = ""  # redacted
    references: list[str] = field(default_factory=list)
    knowledge_id: str | None = None
    cis_ig1: list[str] = field(default_factory=list)
    nist_csf: list[str] = field(default_factory=list)
    data_source: str = "mock"  # "live" | "mock"
    # --- extras used by reports ---
    description: str = ""  # scanner's own description, used when no knowledge entry matches
    platform: str | None = None
    asset_known: bool = True  # False -> asset missing from metadata, conservative defaults used
    score_breakdown: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.vulnerability_name, str) or not self.vulnerability_name.strip():
            raise FindingValidationError("vulnerability_name must be a non-empty string")
        if not isinstance(self.asset_name, str) or not self.asset_name.strip():
            raise FindingValidationError("asset_name must be a non-empty string")
        if isinstance(self.base_severity, bool) or not isinstance(self.base_severity, (int, float)):
            raise FindingValidationError("base_severity must be a number")
        self.base_severity = float(self.base_severity)
        if not 0.0 <= self.base_severity <= 10.0:
            raise FindingValidationError(f"base_severity {self.base_severity} is outside 0.0-10.0")
        if self.exposure_tier not in EXPOSURE_TIERS:
            raise FindingValidationError(f"exposure_tier must be one of {EXPOSURE_TIERS}")
        if isinstance(self.asset_criticality, bool) or self.asset_criticality not in (1, 2, 3):
            raise FindingValidationError("asset_criticality must be 1, 2, or 3")
        if self.cve_id is not None:
            cve = str(self.cve_id).strip().upper()
            if not CVE_RE.match(cve):
                raise FindingValidationError(f"cve_id {self.cve_id!r} is not a valid CVE identifier")
            self.cve_id = cve
        if self.epss_score is not None and not 0.0 <= float(self.epss_score) <= 1.0:
            raise FindingValidationError("epss_score must be between 0.0 and 1.0")
        if self.data_source not in DATA_SOURCES:
            raise FindingValidationError(f"data_source must be one of {DATA_SOURCES}")
        if self.priority not in PRIORITIES:
            raise FindingValidationError(f"priority must be one of {PRIORITIES}")
        self.has_known_exploit = bool(self.has_known_exploit)
        if not self.finding_id:
            self.finding_id = self.compute_id()

    @property
    def dedup_key(self) -> tuple[str, str]:
        """Two findings with the same key describe the same problem on the same asset."""
        if self.cve_id:
            return (self.asset_name, self.cve_id)
        return (self.asset_name, self.knowledge_id or normalize_name(self.vulnerability_name))

    def compute_id(self) -> str:
        digest = hashlib.sha256("|".join(self.dedup_key).encode()).hexdigest()
        return f"F-{digest[:10]}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Batch:
    """One remediation task that clears one or more findings."""

    key: str
    title: str
    finding_ids: list[str]
    finding_count: int
    assets: list[str]
    cves: list[str]
    max_risk_score: float
    total_risk: float
    top_priority: str
    effort: str  # quick | moderate | involved
    knowledge_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
