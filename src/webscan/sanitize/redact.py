"""Redaction for logs, console output, and reports.

One ``Redactor`` is built from the asset metadata. It replaces known hostnames and IPs with
their asset alias and masks anything else that looks sensitive. The module-level ``redact()``
function uses whichever redactor is active, so logging, console, and reports share one path.
"""

from __future__ import annotations

import re
from typing import Any

IP_MASK = "[REDACTED-IP]"
HOST_MASK = "[REDACTED-HOST]"
EMAIL_MASK = "[REDACTED-EMAIL]"
SECRET_MASK = "[REDACTED-SECRET]"  # noqa: S105 - this is a mask label, not a secret

INTERNAL_SUFFIXES = (
    "local", "internal", "lan", "corp", "home", "intranet", "localdomain", "localhost", "private",
)

_IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?(?![\w]|\.\d)"
)
_IPV6_RE = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}(?::?[0-9A-Fa-f]{1,4}){1,7}(?:/\d{1,3})?(?![\w:])"
    r"|(?<![\w:])::1(?![\w:])"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_INTERNAL_HOST_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:" + "|".join(INTERNAL_SUFFIXES) + r")\b",
    re.IGNORECASE,
)
_SECRET_PATTERNS = [
    # key=value style secrets in URLs, headers, and config dumps
    re.compile(
        r"(?i)\b(api[_-]?key|apikey|token|secret|password|passwd|pwd|access[_-]?key|auth)"
        r"(\s*[=:]\s*)([\"']?)[^\s\"'&,;]{4,}\3"
    ),
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),  # JWT
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),  # long hex strings (keys, hashes used as tokens)
]


def _secret_sub(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex >= 2:
        return f"{match.group(1)}{match.group(2)}{SECRET_MASK}"
    if match.lastindex == 1:
        return f"{match.group(1)} {SECRET_MASK}"
    return SECRET_MASK


class Redactor:
    def __init__(
        self,
        alias_map: dict[str, str] | None = None,
        org_domains: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        """
        alias_map: raw hostname or IP -> asset alias.
        org_domains: the organization's domains; any other hostname under them is masked.
        """
        self.enabled = enabled
        self.alias_map = {k.lower(): v for k, v in (alias_map or {}).items() if k}
        self._alias_re: re.Pattern[str] | None = None
        if self.alias_map:
            # Longest first so "donate.example.org" wins over "example.org".
            keys = sorted(self.alias_map, key=len, reverse=True)
            self._alias_re = re.compile(
                r"(?<![\w.-])(" + "|".join(re.escape(k) for k in keys) + r")(?![\w-]|\.[A-Za-z0-9])",
                re.IGNORECASE,
            )
        domains = sorted({d.lower().lstrip("*.") for d in (org_domains or []) if d}, key=len, reverse=True)
        self._org_re: re.Pattern[str] | None = None
        if domains:
            self._org_re = re.compile(
                r"(?<![\w.-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*(?:"
                + "|".join(re.escape(d) for d in domains)
                + r")(?![\w-]|\.[A-Za-z0-9])",
                re.IGNORECASE,
            )

    def alias_for(self, target: str) -> str | None:
        return self.alias_map.get(str(target).lower().rstrip("."))

    def redact(self, text: Any) -> str:
        """Always-on redaction, regardless of ``enabled`` (used by the audit log)."""
        s = "" if text is None else str(text)
        if not s:
            return s
        for pattern in _SECRET_PATTERNS:
            s = pattern.sub(_secret_sub, s)
        s = _EMAIL_RE.sub(EMAIL_MASK, s)
        if self._alias_re:
            s = self._alias_re.sub(lambda m: self.alias_map[m.group(1).lower()], s)
        if self._org_re:
            s = self._org_re.sub(HOST_MASK, s)
        s = _INTERNAL_HOST_RE.sub(HOST_MASK, s)
        s = _IPV4_RE.sub(IP_MASK, s)
        s = _IPV6_RE.sub(IP_MASK, s)
        return s

    def __call__(self, text: Any) -> str:
        """Redact unless the operator explicitly turned redaction off for local output."""
        if not self.enabled:
            return "" if text is None else str(text)
        return self.redact(text)

    def redact_obj(self, obj: Any) -> Any:
        """Recursively redact every string in a JSON-like structure."""
        if isinstance(obj, str):
            return self(obj)
        if isinstance(obj, dict):
            return {k: self.redact_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact_obj(v) for v in obj]
        return obj


_active = Redactor()


def set_active_redactor(redactor: Redactor) -> None:
    global _active
    _active = redactor


def get_active_redactor() -> Redactor:
    return _active


def redact(text: Any) -> str:
    """The single redaction entry point used by logging, console, and reports."""
    return _active(text)


def redact_always(text: Any) -> str:
    """Redact even if the operator passed --no-redact (audit log and warnings)."""
    return _active.redact(text)
