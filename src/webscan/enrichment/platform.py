"""Detect the website platform from HTTP header and HTML signals (no extra requests)."""

from __future__ import annotations

from collections.abc import Mapping

PLATFORM_LABELS = {
    "wordpress": "WordPress",
    "wix": "Wix",
    "squarespace": "Squarespace",
    "google_sites": "Google Sites",
    "custom": "Custom / self-hosted",
}

_HEADER_SIGNALS: list[tuple[str, str, str]] = [
    # (header name, substring in value or "" for presence, platform)
    ("x-wix-request-id", "", "wix"),
    ("server", "pepyaka", "wix"),
    ("server", "squarespace", "squarespace"),
    ("x-powered-by", "wordpress", "wordpress"),
    ("x-powered-by", "wp engine", "wordpress"),
    ("link", "api.w.org", "wordpress"),
    ("x-pingback", "xmlrpc.php", "wordpress"),
]
_BODY_SIGNALS: list[tuple[str, str]] = [
    ("/wp-content/", "wordpress"),
    ("/wp-includes/", "wordpress"),
    ('name="generator" content="wordpress', "wordpress"),
    ("static.wixstatic.com", "wix"),
    ("static.parastorage.com", "wix"),
    ("static1.squarespace.com", "squarespace"),
    ("squarespace-cdn.com", "squarespace"),
    ("sites.google.com", "google_sites"),
    ('content="google sites"', "google_sites"),
]


def detect_platform(headers: Mapping[str, str] | None = None, body: str = "") -> str | None:
    """Return a platform key, or None when there is no clear signal."""
    lowered = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    for name, needle, platform in _HEADER_SIGNALS:
        if name in lowered and needle in lowered[name]:
            return platform
    text = (body or "").lower()
    for needle, platform in _BODY_SIGNALS:
        if needle in text:
            return platform
    return None
