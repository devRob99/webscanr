"""Starts the UI server and the API server together, both on loopback."""

from __future__ import annotations

import socket
import threading

from webscan.config import Settings, load_settings
from webscan.web.settings import WebSettings


class PortInUseError(RuntimeError):
    pass


def _check_free(host: str, port: int, label: str, env_key: str) -> None:
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError as exc:
            raise PortInUseError(
                f"{label} cannot start: {host}:{port} is already in use. Stop the other program or set {env_key} in .env."
            ) from exc


def serve(settings: Settings | None = None, web: WebSettings | None = None) -> None:
    import uvicorn

    from webscan.web.api import create_api
    from webscan.web.ui import create_ui

    settings = settings or load_settings()
    web = web or WebSettings.from_env(settings.env)
    _check_free(web.ui_host, web.ui_port, "The UI", "WEBSCAN_UI_PORT")
    _check_free(web.api_host, web.api_port, "The API", "WEBSCAN_API_PORT")

    api = uvicorn.Server(
        uvicorn.Config(create_api(settings, web), host=web.api_host, port=web.api_port, log_level="warning")
    )
    ui = uvicorn.Server(uvicorn.Config(create_ui(web), host=web.ui_host, port=web.ui_port, log_level="warning"))
    api_thread = threading.Thread(target=api.run, name="webscan-api", daemon=True)
    api_thread.start()
    try:
        ui.run()
    finally:
        api.should_exit = True
        api_thread.join(timeout=5)
