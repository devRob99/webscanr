"""Append-only audit log (JSON Lines).

Records who ran what, against which asset aliases, in live or mock mode, and how it ended.
Raw hostnames, IPs, and keys never reach the file: targets are converted to asset aliases and
every string goes through always-on redaction, even when the operator passed --no-redact.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from webscan.sanitize.redact import Redactor


def default_operator() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no usable OS user (containers, CI)
        return "unknown"


class AuditLogger:
    def __init__(
        self,
        path: Path | None,
        operator: str | None = None,
        redactor: Redactor | None = None,
        command: str = "",
    ) -> None:
        self.path = Path(path) if path else None
        self.operator = operator or default_operator()
        self.redactor = redactor or Redactor()
        self.command = command
        self._lock = threading.Lock()

    def alias(self, target: str) -> str:
        """Asset alias for a target, or a non-reversible label when it is not in the inventory."""
        found = self.redactor.alias_for(target)
        if found:
            return found
        digest = hashlib.sha256(str(target).encode("utf-8", "replace")).hexdigest()[:8]
        return f"unlisted:{digest}"

    def log(
        self,
        event: str,
        *,
        provider: str | None = None,
        targets: list[str] | None = None,
        mode: str = "mock",
        status: str = "ok",
        duration_ms: float | None = None,
        detail: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "operator": self.redactor.redact(self.operator),
            "command": self.command,
            "event": event,
            "provider": provider,
            "targets": [self.alias(t) for t in (targets or [])],
            "mode": mode,
            "status": status,
            "duration_ms": None if duration_ms is None else round(duration_ms, 1),
        }
        if detail:
            record["detail"] = self.redactor.redact(detail)
        for key, value in extra.items():
            record[key] = self.redactor.redact_obj(value) if isinstance(value, (str, list, dict)) else value
        if self.path:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:  # append-only
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def timed(self, event: str, **fields: Any) -> _Timed:
        return _Timed(self, event, fields)


class _Timed:
    """Context manager: logs the event with duration and ok/error status on exit."""

    def __init__(self, logger: AuditLogger, event: str, fields: dict[str, Any]) -> None:
        self.logger, self.event, self.fields = logger, event, fields
        self.clock: Callable[[], float] = time.perf_counter
        self.status: str | None = None
        self.detail: str | None = None

    def __enter__(self) -> _Timed:
        self._start = self.clock()
        return self

    def __exit__(self, exc_type, exc, _tb) -> bool:
        elapsed = (self.clock() - self._start) * 1000
        fields = dict(self.fields)
        if exc is not None:
            fields["status"] = "error"
            fields["detail"] = f"{exc_type.__name__}: {exc}"
        else:
            if self.status:
                fields["status"] = self.status
            if self.detail:
                fields["detail"] = self.detail
        self.logger.log(self.event, duration_ms=elapsed, **fields)
        return False
