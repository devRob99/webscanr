"""Static front end server. Serves files from ./static with a strict Content Security Policy."""

from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from webscan.web.settings import WebSettings

STATIC_DIR = Path(__file__).resolve().parent / "static"


def security_headers(web: WebSettings) -> dict[str, str]:
    csp = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        f"connect-src 'self' {web.api_origin}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "no-cache",
    }


def create_ui(web: WebSettings) -> Starlette:
    headers = security_headers(web)
    canonical = f"{web.ui_host}:{web.ui_port}"
    aliases = {f"localhost:{web.ui_port}", f"127.0.0.1:{web.ui_port}"} - {canonical}

    async def runtime_config(_request: Request) -> JSONResponse:
        # Not a secret: only tells the page where the local API listens.
        return JSONResponse({"apiBase": f"{web.api_origin}/api"})

    async def guard(request: Request, call_next):
        host = request.headers.get("host", "")
        if host in aliases:  # the API only accepts the canonical origin, so send the browser there
            response: Response = RedirectResponse(f"{web.ui_origin}{request.url.path}", status_code=307)
        elif host != canonical:
            response = Response("Unknown host.", status_code=400, media_type="text/plain")
        else:
            response = await call_next(request)
        for name, value in headers.items():
            response.headers[name] = value
        return response

    return Starlette(
        routes=[
            Route("/config.json", runtime_config),
            Mount("/", app=StaticFiles(directory=STATIC_DIR, html=True), name="static"),
        ],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=guard)],
    )
