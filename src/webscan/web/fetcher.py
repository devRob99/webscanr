"""Transport for web-initiated scans.

``GuardedFetcher`` extends the scanner's own ``LiveFetcher`` (same passive requests, same
audit trail, same live-mode guard) and adds what an interactive scan needs: connections
pinned to an address that passed the SSRF check, a strict single-host scope, a shared
rate limit, an overall deadline, and immediate cancellation.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from webscan.providers.local.fetch import MAX_BODY_BYTES, USER_AGENT, HttpResponse, LiveFetcher, TlsInfo
from webscan.web.netguard import Target
from webscan.web.ratelimit import RateLimiter


class ScanCancelled(Exception):  # noqa: N818 - a control-flow signal, not an error
    """The user cancelled the scan."""


class ScanTimedOut(Exception):  # noqa: N818
    """The scan ran past its overall deadline."""


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-validated IP address while keeping the hostname for the Host header."""

    def __init__(self, host: str, port: int | None, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(_PinnedHTTPConnection):
    default_port = 443

    def connect(self) -> None:
        super().connect()
        self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)


def pinned_get(
    url: str,
    ip: str,
    timeout: float,
    max_bytes: int = MAX_BODY_BYTES,
    on_connection: Callable[[http.client.HTTPConnection | None], None] | None = None,
) -> HttpResponse:
    """One GET to ``url``, connecting to ``ip``. Never follows redirects. Raises OSError / HTTPException."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError("only plain http(s) URLs are fetched")
    factory = _PinnedHTTPSConnection if parts.scheme == "https" else _PinnedHTTPConnection
    conn = factory(parts.hostname, parts.port, ip, timeout)
    if on_connection:
        on_connection(conn)
    try:
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request(
            "GET", path,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"},
        )
        response = conn.getresponse()
        raw = response.read(max_bytes)
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            body = raw.decode(charset, "replace")
        except LookupError:
            body = raw.decode("utf-8", "replace")
        headers = {name.lower(): ", ".join(response.headers.get_all(name) or []) for name in response.headers}
        return HttpResponse(
            url=url, status=response.status, headers=headers, body=body,
            set_cookies=list(response.headers.get_all("Set-Cookie") or []),
        )
    finally:
        if on_connection:
            on_connection(None)
        conn.close()


class GuardedFetcher(LiveFetcher):
    def __init__(
        self,
        ctx,
        target: Target,
        ip: str,
        limiter: RateLimiter,
        cancel: threading.Event,
        deadline: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(ctx, "local")
        self.target = target
        self.ip = ip
        self.limiter = limiter
        self.cancel = cancel
        self.deadline = deadline
        self._clock = clock
        self._cache: dict[str, HttpResponse | None] = {}
        self._active: Any = None  # connection or socket in flight, closed by abort()
        self.request_count = 0

    # ------------------------------------------------------------------ gates

    def _in_scope(self, host: str, port: int | None = None, check_port: bool = False) -> bool:
        name, _, tail = host.partition(":")
        if tail and port is None:
            port = int(tail) if tail.isdigit() else -1
        if name.lower().rstrip(".") != self.target.host:
            return False
        return not check_port or port == self.target.port

    def _checkpoint(self) -> None:
        if self.cancel.is_set():
            raise ScanCancelled()
        if self._clock() >= self.deadline:
            raise ScanTimedOut()

    def _authorize(self, host: str) -> None:
        """Called before every network operation. Cancel, deadline, single-host scope, live-mode guard."""
        self._checkpoint()
        name = host.partition(":")[0].lower().rstrip(".")
        if name != self.target.host and not name.endswith("." + self.target.host):
            from webscan.scope.enforcer import ScopeError

            raise ScopeError("request is outside the verified domain")
        self.ctx.guard.authorize(self.provider, self.target.scope_name, third_party=False)

    def _pace(self) -> None:
        if not self.limiter.acquire(self.cancel):
            raise ScanCancelled()
        self._checkpoint()
        self.request_count += 1

    def _request_timeout(self) -> float:
        return max(1.0, min(self.timeout, self.deadline - self._clock()))

    def abort(self) -> None:
        """Close whatever is in flight so a cancelled scan stops at once."""
        active = self._active
        sock = getattr(active, "sock", active)
        if sock is not None:
            for close in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
                try:
                    close()
                except OSError:
                    pass

    def _track(self, active: Any) -> None:
        self._active = active

    # ------------------------------------------------------------------ Fetcher protocol

    def get(self, url: str) -> HttpResponse | None:
        if url in self._cache:
            self._checkpoint()
            return self._cache[url]
        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError:
            port = -1
        if parts.scheme not in ("http", "https") or not self._in_scope(parts.hostname or "", port, check_port=True):
            # Links and redirects that leave the verified host are never followed.
            self.ctx.audit.log(
                "scope_rejection", provider=self.provider, targets=[self.target.host], mode="live",
                status="rejected", detail="request outside the verified host was not sent",
            )
            return None
        self._authorize(parts.hostname or "")
        self._pace()
        started = time.perf_counter()
        try:
            response = pinned_get(url, self.ip, self._request_timeout(), on_connection=self._track)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            if self.cancel.is_set():
                raise ScanCancelled() from exc
            self._audit(self.target.host, "error", started, detail=exc.__class__.__name__)
            self._cache[url] = None
            return None
        self._audit(self.target.host, "ok", started, http_status=response.status)
        self._cache[url] = response
        return response

    def _handshake(self, host: str, context: ssl.SSLContext) -> dict[str, Any] | None:
        self._checkpoint()
        with socket.create_connection((self.ip, self.target.port or 443), timeout=self._request_timeout()) as raw:
            self._track(raw)
            try:
                with context.wrap_socket(raw, server_hostname=self.target.host) as tls_sock:
                    return tls_sock.getpeercert()
            finally:
                self._track(None)

    def tls(self, host: str) -> TlsInfo | None:
        info = super().tls(host)
        self._checkpoint()  # a socket closed by abort() looks like "no TLS"; report the cancel instead
        return info

    def txt(self, name: str, scope_domain: str) -> list[str] | None:
        if self.target.kind != "public":
            return None
        self._pace()
        return super().txt(name, scope_domain)
