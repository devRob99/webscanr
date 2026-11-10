"""Throttling: requests per target, concurrent scans, and a cooldown between scans of one domain."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    """Spaces calls so that no more than ``max_per_second`` start in any second.

    ``acquire`` blocks until the caller's slot arrives. It returns False without taking a
    slot when ``cancel`` is set first, so a cancelled scan stops waiting immediately.
    """

    def __init__(
        self,
        max_per_second: float,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float, threading.Event | None], bool] | None = None,
    ) -> None:
        if max_per_second <= 0:
            raise ValueError("max_per_second must be positive")
        self.interval = 1.0 / max_per_second
        self._clock = clock
        self._wait = wait or self._default_wait
        self._lock = threading.Lock()
        self._next_slot = 0.0

    @staticmethod
    def _default_wait(seconds: float, cancel: threading.Event | None) -> bool:
        if cancel is None:
            time.sleep(seconds)
            return False
        return cancel.wait(seconds)

    def acquire(self, cancel: threading.Event | None = None) -> bool:
        if cancel is not None and cancel.is_set():
            return False
        with self._lock:
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self.interval
            delay = slot - now
        if delay > 0 and self._wait(delay, cancel):
            return False
        return True


class TargetLimiters:
    """One shared RateLimiter per target, so verification and scans draw from the same budget."""

    def __init__(self, max_per_second: float) -> None:
        self.max_per_second = max_per_second
        self._lock = threading.Lock()
        self._limiters: dict[str, RateLimiter] = {}

    def get(self, target: str) -> RateLimiter:
        with self._lock:
            return self._limiters.setdefault(target, RateLimiter(self.max_per_second))


class ScanBusyError(Exception):
    """A scan cannot start now. ``retry_after`` is the number of seconds to wait (0 if unknown)."""

    def __init__(self, message: str, retry_after: int = 0) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ScanGate:
    """Caps concurrent scans and enforces a cooldown between scans of the same target."""

    def __init__(self, max_concurrent: int, cooldown_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.max_concurrent = max_concurrent
        self.cooldown = cooldown_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._active: set[str] = set()
        self._last_finished: dict[str, float] = {}

    def enter(self, target: str) -> None:
        with self._lock:
            if target in self._active:
                raise ScanBusyError("A scan of this domain is already running.")
            if len(self._active) >= self.max_concurrent:
                raise ScanBusyError(
                    f"{self.max_concurrent} scans are already running. Wait for one to finish and try again."
                )
            last = self._last_finished.get(target)
            if last is not None:
                remaining = self.cooldown - (self._clock() - last)
                if remaining > 0:
                    seconds = int(remaining) + 1
                    raise ScanBusyError(
                        f"This domain was scanned moments ago. Wait {seconds} seconds before scanning it again.",
                        retry_after=seconds,
                    )
            self._active.add(target)

    def leave(self, target: str) -> None:
        with self._lock:
            self._active.discard(target)
            self._last_finished[target] = self._clock()
