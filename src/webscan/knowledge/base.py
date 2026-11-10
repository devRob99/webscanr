"""Local knowledge base: matches findings to plain-language EN/ES explanations and fixes.

Everything is read from JSON files shipped with the package. Nothing is sent anywhere.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

KNOWLEDGE_DIR = Path(__file__).resolve().parent
LANGS = ("en", "es")
EFFORTS = ("quick", "moderate", "involved")


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    default_severity: float
    remediation_key: str
    effort: str
    group: str
    cves: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    cis_ig1: tuple[str, ...] = ()
    nist_csf: tuple[str, ...] = ()


@dataclass
class Explanation:
    """What a report shows for one finding, in one language."""

    title: str
    what: str
    why: str
    fix: list[str] = field(default_factory=list)
    platform_note: str | None = None
    platform_controlled: bool = False
    from_knowledge_base: bool = True


@cache
def _load(name: str) -> dict[str, Any]:
    with (KNOWLEDGE_DIR / f"{name}.json").open(encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def catalog() -> dict[str, CatalogEntry]:
    entries: dict[str, CatalogEntry] = {}
    for raw in _load("catalog")["entries"]:
        entries[raw["id"]] = CatalogEntry(
            id=raw["id"],
            default_severity=float(raw["default_severity"]),
            remediation_key=raw["remediation_key"],
            effort=raw["effort"],
            group=raw["group"],
            cves=tuple(c.upper() for c in raw.get("cves", [])),
            keywords=tuple(k.lower() for k in raw.get("keywords", [])),
            cis_ig1=tuple(raw.get("cis_ig1", [])),
            nist_csf=tuple(raw.get("nist_csf", [])),
        )
    return entries


def get_entry(knowledge_id: str | None) -> CatalogEntry | None:
    return catalog().get(knowledge_id) if knowledge_id else None


def match(
    name: str = "", cve_id: str | None = None, knowledge_id: str | None = None, description: str = ""
) -> CatalogEntry | None:
    """Find the catalog entry for a finding: explicit id, then CVE, then keyword rules."""
    entries = catalog()
    if knowledge_id and knowledge_id in entries:
        return entries[knowledge_id]
    if cve_id:
        cve = cve_id.upper()
        for entry in entries.values():
            if cve in entry.cves:
                return entry
    for text in (name, description):
        haystack = (text or "").lower()
        if not haystack:
            continue
        for entry in entries.values():
            if any(_keyword_re(keyword).search(haystack) for keyword in entry.keywords):
                return entry
    return None


@cache
def _keyword_re(keyword: str) -> re.Pattern[str]:
    # Whole-word match, so "rdp" does not fire on "wordpress" or "ftp" on "sftp".
    return re.compile(r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])")


def entry_for_remediation_key(key: str | None) -> CatalogEntry | None:
    if not key:
        return None
    for entry in catalog().values():
        if entry.remediation_key == key:
            return entry
    return None


def _lang(lang: str) -> str:
    return lang if lang in LANGS else "en"


def ui(lang: str) -> dict[str, str]:
    """Interface strings (labels, headings) for a language."""
    return _load(_lang(lang))["ui"]


def explain(
    knowledge_id: str | None,
    lang: str = "en",
    platform: str | None = None,
    fallback_title: str = "",
    fallback_description: str = "",
) -> Explanation:
    """Plain-language text for a finding, with platform-specific fix steps when available."""
    data = _load(_lang(lang))
    entry = get_entry(knowledge_id)
    text = data["entries"].get(knowledge_id or "")
    if not entry or not text:
        generic = data["ui"]
        return Explanation(
            title=fallback_title,
            what=fallback_description or generic["no_plain_language"],
            why=generic["generic_why"],
            fix=[generic["generic_fix"]],
            from_knowledge_base=False,
        )
    fix = list(text["fix"])
    note, controlled = None, False
    guidance = data.get("platform_guidance", {}).get(entry.group, {}).get(platform or "")
    override = text.get("platform_fix", {}).get(platform or "")
    if override:
        fix = list(override)
    if guidance:
        controlled = bool(guidance.get("controlled"))
        note = guidance.get("note")
        if guidance.get("steps") and not override:
            fix = list(guidance["steps"]) if controlled else [*guidance["steps"], *fix]
    return Explanation(text["title"], text["what"], text["why"], fix, note, controlled)


def batch_title(remediation_key: str, lang: str = "en", fallback: str = "") -> str:
    """Short action phrase for a remediation batch."""
    data = _load(_lang(lang))
    title = data.get("batch_titles", {}).get(remediation_key)
    if title:
        return title
    entry = entry_for_remediation_key(remediation_key)
    if entry and entry.id in data["entries"]:
        return data["entries"][entry.id]["title"]
    return fallback or remediation_key


def frameworks(lang: str = "en") -> dict[str, dict[str, str]]:
    """{'cis_ig1': {id: title}, 'nist_csf': {id: title}} in the requested language."""
    data = _load("frameworks")
    lang = _lang(lang)
    return {name: {key: value[lang] for key, value in data[name].items()} for name in ("cis_ig1", "nist_csf")}
