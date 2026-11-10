"""Web UI settings. Every host, port, and limit comes from the environment / .env."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass

LOOPBACK_NAMES = ("localhost",)


class WebConfigError(ValueError):
    """A web setting is missing or unsafe."""


def _loopback_host(value: str, key: str) -> str:
    host = value.strip().lower()
    if host in LOOPBACK_NAMES:
        return host
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise WebConfigError(
        f"{key}={value!r} is not a loopback address. The web UI only binds to 127.0.0.1 so it is "
        "never exposed to the local network."
    )


def _number(env: Mapping[str, str], key: str, default: float, minimum: float, maximum: float) -> float:
    raw = str(env.get(key, "")).strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise WebConfigError(f"{key} must be a number") from exc
    if not minimum <= value <= maximum:
        raise WebConfigError(f"{key} must be between {minimum:g} and {maximum:g}")
    return value


@dataclass(frozen=True)
class WebSettings:
    ui_host: str = "127.0.0.1"
    ui_port: int = 5500
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    verification_ttl_days: int = 30
    max_requests_per_second: float = 2.0
    max_concurrent_scans: int = 2
    scan_cooldown_seconds: int = 60
    scan_timeout_seconds: int = 180

    @property
    def ui_origin(self) -> str:
        return f"http://{self.ui_host}:{self.ui_port}"

    @property
    def api_origin(self) -> str:
        return f"http://{self.api_host}:{self.api_port}"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> WebSettings:
        return cls(
            ui_host=_loopback_host(env.get("WEBSCAN_UI_HOST") or "127.0.0.1", "WEBSCAN_UI_HOST"),
            ui_port=int(_number(env, "WEBSCAN_UI_PORT", 5500, 1024, 65535)),
            api_host=_loopback_host(env.get("WEBSCAN_API_HOST") or "127.0.0.1", "WEBSCAN_API_HOST"),
            api_port=int(_number(env, "WEBSCAN_API_PORT", 8000, 1024, 65535)),
            verification_ttl_days=int(_number(env, "WEBSCAN_VERIFICATION_TTL_DAYS", 30, 1, 365)),
            max_requests_per_second=_number(env, "WEBSCAN_MAX_REQUESTS_PER_SECOND", 2.0, 0.1, 5.0),
            max_concurrent_scans=int(_number(env, "WEBSCAN_MAX_CONCURRENT_SCANS", 2, 1, 8)),
            scan_cooldown_seconds=int(_number(env, "WEBSCAN_SCAN_COOLDOWN_SECONDS", 60, 0, 86400)),
            scan_timeout_seconds=int(_number(env, "WEBSCAN_SCAN_TIMEOUT_SECONDS", 180, 10, 3600)),
        )
