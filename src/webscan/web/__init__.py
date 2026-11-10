"""Local web UI: a static front end plus a JSON API, both bound to loopback only.

The UI reuses the existing scanner (local passive checks, scoring, knowledge base, reports).
This package adds only what a browser-driven scan needs: domain ownership verification,
SSRF protection, rate limiting, cancellation, and a scan/audit store.
"""
