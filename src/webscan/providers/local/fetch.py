"""How local checks reach a target: recorded fixtures (demo/tests) or live requests (gated).

Local checks make the same plain requests a regular visitor's browser or mail server would.
The live fetcher authorizes every request through the ExternalCallGuard and never follows a
redirect automatically, so it cannot be led to a host outside the approved inventory.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

MAX_BODY_BYTES = 500_000
USER_AGENT = "WebScan/0.1 (authorized nonprofit security assessment)"


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased names
    body: str = ""
    set_cookies: list[str] = field(default_factory=list)

    @property
    def https(self) -> bool:
        return self.url.lower().startswith("https://")


@dataclass
class TlsInfo:
    valid: bool
    days_remaining: int | None = None
    error: str | None = None
    legacy_protocols: list[str] = field(default_factory=list)
    legacy_tested: bool = False


class Fetcher(Protocol):
    def get(self, url: str) -> HttpResponse | None: ...

    def tls(self, host: str) -> TlsInfo | None: ...

    def txt(self, name: str, scope_domain: str) -> list[str] | None: ...


class FixtureFetcher:
    """Serves recorded responses from data/mock/local/<host>.json. Never touches the network."""

    def __init__(self, fixture_dir: Path) -> None:
        self.fixture_dir = Path(fixture_dir)
        self._cache: dict[str, dict[str, Any] | None] = {}

    def has(self, host: str) -> bool:
        return self._load(host) is not None

    def _load(self, host: str) -> dict[str, Any] | None:
        host = host.lower()
        if host not in self._cache:
            path = self.fixture_dir / f"{host}.json"
            self._cache[host] = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
        return self._cache[host]

    def get(self, url: str) -> HttpResponse | None:
        parts = urlsplit(url)
        fixture = self._load(parts.hostname or "")
        if not fixture:
            return None
        pages = fixture.get("http", {})
        record = pages.get(url)
        if record is None:
            root = f"{parts.scheme}://{parts.hostname}/"
            if root not in pages:
                return None  # this scheme is not reachable on the host
            record = fixture.get("not_found", {"status": 404, "headers": {}, "body": "Not Found"})
        return HttpResponse(
            url=url,
            status=int(record.get("status", 200)),
            headers={k.lower(): v for k, v in record.get("headers", {}).items()},
            body=record.get("body", ""),
            set_cookies=list(record.get("set_cookies", [])),
        )

    def tls(self, host: str) -> TlsInfo | None:
        fixture = self._load(host)
        data = fixture.get("tls") if fixture else None
        if not data:
            return None
        return TlsInfo(
            valid=bool(data.get("valid", True)),
            days_remaining=data.get("days_remaining"),
            error=data.get("error"),
            legacy_protocols=list(data.get("legacy_protocols", [])),
            legacy_tested=True,
        )

    def txt(self, name: str, scope_domain: str) -> list[str] | None:
        fixture = self._load(scope_domain)
        if not fixture or "dns" not in fixture:
            return None
        return list(fixture["dns"].get(name.lower(), []))


class LiveFetcher:
    """Live requests from this machine straight to an approved target.

    TODO: verify against live targets (with written authorization) before relying on results.
    """

    def __init__(self, ctx, provider: str = "local") -> None:
        self.ctx = ctx
        self.provider = provider
        cfg = ctx.providers_cfg.get("local", {})
        self.timeout = float(cfg.get("timeout_seconds", 10))
        self.delay = float(cfg.get("request_delay_seconds", 1.0))
        self._last = 0.0
        self._session = None

    def _authorize(self, host: str) -> None:
        self.ctx.guard.authorize(self.provider, host, third_party=False)

    def _pace(self) -> None:
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get(self, url: str) -> HttpResponse | None:
        import requests

        host = urlsplit(url).hostname or ""
        self._authorize(host)  # raises for anything outside the approved inventory
        self._pace()
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": USER_AGENT})
        started = time.perf_counter()
        try:
            response = self._session.get(url, timeout=self.timeout, allow_redirects=False, stream=True)
            body = response.raw.read(MAX_BODY_BYTES, decode_content=True).decode(
                response.encoding or "utf-8", "replace"
            )
            cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
            response.close()
        except requests.RequestException as exc:
            self._audit(host, "error", started, detail=exc.__class__.__name__)
            return None
        self._audit(host, "ok", started, http_status=response.status_code)
        return HttpResponse(
            url=url, status=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()}, body=body, set_cookies=list(cookies),
        )

    def _audit(self, host: str, status: str, started: float, **extra: Any) -> None:
        self.ctx.audit.log(
            "local_request", provider=self.provider, targets=[host], mode="live", status=status,
            duration_ms=(time.perf_counter() - started) * 1000, **extra,
        )

    def _handshake(self, host: str, context: ssl.SSLContext) -> dict[str, Any] | None:
        with socket.create_connection((host, 443), timeout=self.timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert()

    def tls(self, host: str) -> TlsInfo | None:
        self._authorize(host)
        self._pace()
        started = time.perf_counter()
        try:
            cert = self._handshake(host, ssl.create_default_context())
        except ssl.SSLCertVerificationError as exc:
            self._audit(host, "ok", started, detail="certificate failed validation")
            return TlsInfo(valid=False, error=exc.verify_message or "certificate failed validation")
        except (OSError, ssl.SSLError):
            self._audit(host, "error", started, detail="no TLS connection")
            return None
        info = TlsInfo(valid=True)
        if cert and cert.get("notAfter"):
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC)
            info.days_remaining = (expires - datetime.now(UTC)).days
        # Legacy protocol probe. Modern OpenSSL builds often refuse TLS 1.0/1.1 outright; in
        # that case the probe is inconclusive and nothing is reported.
        for label, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                legacy.check_hostname = False
                legacy.verify_mode = ssl.CERT_NONE  # probing protocol support only; no data is exchanged
                legacy.minimum_version = version
                legacy.maximum_version = version
                self._pace()
                self._handshake(host, legacy)
                info.legacy_protocols.append(label)
                info.legacy_tested = True
            except ssl.SSLError as exc:
                info.legacy_tested = info.legacy_tested or "alert" in str(exc).lower()
            except (OSError, ValueError):
                continue
        self._audit(host, "ok", started)
        return info

    def txt(self, name: str, scope_domain: str) -> list[str] | None:
        self._authorize(scope_domain)
        started = time.perf_counter()
        try:
            import dns.exception
            import dns.resolver

            try:
                answer = dns.resolver.resolve(name, "TXT", lifetime=self.timeout)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                self._audit(scope_domain, "ok", started, detail="no TXT record")
                return []
            except dns.exception.DNSException:
                self._audit(scope_domain, "error", started, detail="DNS lookup failed")
                return None
        except ImportError:
            return None
        self._audit(scope_domain, "ok", started)
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answer]
