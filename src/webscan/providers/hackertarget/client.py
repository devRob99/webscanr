"""HackerTarget HTTP client: rate limiting, concurrency cap, daily quota, retry with backoff.

Safety properties:
  * Every request first passes ``ExternalCallGuard.authorize`` (live mode + provider
    approval + scope check, public targets only). Without that, nothing is sent.
  * The API key is sent as the ``apikey`` query parameter and is never logged.
  * The daily quota counter is persisted to disk, so restarts do not reset it.
  * HTTP 429 / 5xx / timeouts are retried with exponential backoff and jitter.
  * HackerTarget sometimes reports errors as plain text with HTTP 200; those are detected
    and treated as errors rather than parsed as results.

TODO (team): confirm the quota, rate limits, and error strings against the organization's
HackerTarget plan before the first live run.
"""

from __future__ import annotations

import json
import random
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from typing import Any

import requests

from webscan.audit.logger import AuditLogger
from webscan.providers.guard import ExternalCallGuard
from webscan.providers.hackertarget.endpoints import Endpoint

PROVIDER = "hackertarget"
USER_AGENT = "WebScan/0.1 (authorized nonprofit security assessment)"


class HackerTargetError(Exception):
    """A request failed in a way that should not be retried."""


class QuotaExceededError(HackerTargetError):
    """The daily request quota is used up (local counter or reported by the API)."""


class RetriesExhaustedError(HackerTargetError):
    """The request kept failing with retryable errors."""


_TEXT_ERRORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"api count exceeded", re.I), "quota"),
    (re.compile(r"(too many requests|rate limit)", re.I), "rate"),
    (re.compile(r"^\s*no (dns )?(a )?records found", re.I), "empty"),
    (re.compile(r"^\s*error\b", re.I), "error"),
    (re.compile(r"^\s*invalid (api ?key|key)", re.I), "error"),
]


def detect_text_error(body: str) -> tuple[str, str] | None:
    """Classify an error that arrived as plain text: (kind, first line) or None if it is a result."""
    head = (body or "").strip()[:300]
    if not head:
        return ("empty", "empty response")
    first_line = head.splitlines()[0]
    for pattern, kind in _TEXT_ERRORS:
        if pattern.search(head if kind in ("quota", "rate") else first_line):
            return (kind, first_line)
    return None


class QuotaTracker:
    """Daily request counter persisted as JSON: {"date": "YYYY-MM-DD", "count": N}."""

    def __init__(self, path: Path, daily_limit: int, today: Callable[[], str] = lambda: date.today().isoformat()):
        self.path = Path(path)
        self.daily_limit = int(daily_limit)
        self._today = today
        self._lock = threading.Lock()

    def _read(self) -> int:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("date") == self._today():
                return int(data.get("count", 0))
        except (OSError, ValueError, AttributeError, TypeError):
            pass
        return 0

    def _write(self, count: int) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"date": self._today(), "count": count}), encoding="utf-8")

    @property
    def used(self) -> int:
        with self._lock:
            return self._read()

    @property
    def remaining(self) -> int:
        return max(0, self.daily_limit - self.used)

    def consume(self) -> int:
        """Count one request, or raise QuotaExceededError when the day's quota is spent."""
        with self._lock:
            count = self._read()
            if count >= self.daily_limit:
                raise QuotaExceededError(f"Daily HackerTarget quota of {self.daily_limit} requests reached")
            self._write(count + 1)
            return count + 1

    def mark_exhausted(self) -> None:
        with self._lock:
            self._write(max(self.daily_limit, self._read()))


class RateLimiter:
    """Enforces a minimum delay between the start of consecutive requests."""

    def __init__(self, min_delay: float, clock: Callable[[], float], sleep: Callable[[float], None]) -> None:
        self.min_delay = float(min_delay)
        self._clock, self._sleep = clock, sleep
        self._lock = threading.Lock()
        self._last: float | None = None

    def wait(self) -> float:
        with self._lock:
            waited = 0.0
            now = self._clock()
            if self._last is not None:
                waited = max(0.0, self.min_delay - (now - self._last))
                if waited > 0:
                    self._sleep(waited)
            self._last = self._clock()
            return waited


class HackerTargetClient:
    def __init__(
        self,
        cfg: dict[str, Any],
        guard: ExternalCallGuard,
        audit: AuditLogger,
        quota_path: Path,
        api_key: str | None = None,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        rng: Callable[[], float] = random.random,
        today: Callable[[], str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.guard = guard
        self.audit = audit
        self._api_key = api_key
        self.base_url = str(cfg["base_url"]).rstrip("/")
        if not self.base_url.startswith("https://"):
            raise HackerTargetError("HackerTarget base_url must use HTTPS")
        self.timeout = float(cfg["timeout_seconds"])
        self.max_retries = int(cfg["max_retries"])
        self.backoff_base = float(cfg["backoff_base_seconds"])
        self.backoff_max = float(cfg["backoff_max_seconds"])
        self.max_concurrent = max(1, int(cfg["max_concurrent"]))
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self._sleep, self._clock, self._rng = sleep, clock, rng
        self.limiter = RateLimiter(cfg["min_delay_seconds"], clock, sleep)
        self.quota = QuotaTracker(quota_path, cfg["daily_quota"], **({"today": today} if today else {}))
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)

    def backoff_delay(self, attempt: int, retry_after: str | None = None) -> float:
        """Exponential backoff with jitter (50-100% of the step), honoring Retry-After."""
        step = min(self.backoff_max, self.backoff_base * (2**attempt))
        delay = step * (0.5 + 0.5 * self._rng())
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except ValueError:
                pass
        return min(self.backoff_max, delay)

    def _log(self, endpoint: Endpoint, target: str, status: str, started: float, **extra: Any) -> None:
        self.audit.log(
            "api_call", provider=PROVIDER, targets=[target], mode="live", status=status,
            duration_ms=(self._clock() - started) * 1000, endpoint=endpoint.key, **extra,
        )

    def get(self, endpoint: Endpoint, target: str) -> str:
        """Fetch one endpoint for one target and return the raw response text."""
        if endpoint.wip:
            raise HackerTargetError(f"Endpoint '{endpoint.key}' is WIP and cannot be called live yet")
        self.guard.authorize(PROVIDER, target, third_party=True)  # raises if not permitted
        url = f"{self.base_url}{endpoint.path}"
        params = {"q": target}
        if self._api_key:
            params["apikey"] = self._api_key

        last_problem = "unknown error"
        for attempt in range(self.max_retries + 1):
            retry_after: str | None = None
            with self._semaphore:
                self.quota.consume()
                self.limiter.wait()
                started = self._clock()
                try:
                    response = self.session.get(url, params=params, timeout=self.timeout)
                except (requests.Timeout, requests.ConnectionError) as exc:
                    last_problem = "timeout" if isinstance(exc, requests.Timeout) else "connection error"
                    self._log(endpoint, target, "retry", started, attempt=attempt + 1, detail=last_problem)
                else:
                    status = response.status_code
                    if status == 429 or 500 <= status < 600:
                        last_problem = f"HTTP {status}"
                        retry_after = response.headers.get("Retry-After")
                        self._log(endpoint, target, "retry", started, attempt=attempt + 1, http_status=status)
                    elif status != 200:
                        self._log(endpoint, target, "error", started, attempt=attempt + 1, http_status=status)
                        raise HackerTargetError(f"HackerTarget returned HTTP {status} for {endpoint.key}")
                    else:
                        problem = detect_text_error(response.text)
                        if problem is None:
                            self._log(endpoint, target, "ok", started, attempt=attempt + 1, http_status=200)
                            return response.text
                        kind, message = problem
                        if kind == "empty":
                            self._log(endpoint, target, "ok", started, attempt=attempt + 1, detail="no results")
                            return ""
                        if kind == "quota":
                            self.quota.mark_exhausted()
                            self._log(endpoint, target, "error", started, attempt=attempt + 1, detail="quota exceeded")
                            raise QuotaExceededError("HackerTarget reports the API quota is exceeded")
                        if kind == "rate":
                            last_problem = "rate limited (reported in response body)"
                            self._log(endpoint, target, "retry", started, attempt=attempt + 1, detail=last_problem)
                        else:
                            self._log(endpoint, target, "error", started, attempt=attempt + 1, detail=message)
                            raise HackerTargetError(f"HackerTarget error for {endpoint.key}: {message}")
            if attempt < self.max_retries:
                self._sleep(self.backoff_delay(attempt, retry_after))  # outside the semaphore
        raise RetriesExhaustedError(
            f"HackerTarget {endpoint.key} failed after {self.max_retries + 1} attempts ({last_problem})"
        )

    def get_many(self, jobs: list[tuple[Endpoint, str]]) -> list[tuple[Endpoint, str, str | Exception]]:
        """Queue several requests. Concurrency, pacing, and quota limits still apply.

        Returns one (endpoint, target, text-or-exception) tuple per job, in order. A failed
        job does not stop the others, except that once the quota is spent the rest fail fast.
        """

        def run(job: tuple[Endpoint, str]) -> str | Exception:
            try:
                return self.get(*job)
            except Exception as exc:  # noqa: BLE001 - reported per job
                return exc

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as pool:
            results = list(pool.map(run, jobs))
        return [(endpoint, target, result) for (endpoint, target), result in zip(jobs, results, strict=True)]
