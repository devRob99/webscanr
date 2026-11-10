"""Shared fixtures. All tests run offline: any real socket connection fails the test."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from webscan.context import build_context

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = ROOT / "config"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_args, **_kwargs):
        raise AssertionError("Network access attempted during tests")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture
def example_whitelist() -> dict:
    return json.loads((EXAMPLE_CONFIG / "allowed_targets.example.json").read_text())


@pytest.fixture
def make_ctx(tmp_path):
    def _make(**kwargs):
        kwargs.setdefault("demo", True)
        kwargs.setdefault("output_dir", tmp_path / "output")
        kwargs.setdefault("log_dir", tmp_path / "logs")
        kwargs.setdefault("env", {})
        return build_context("test", **kwargs)

    return _make


@pytest.fixture
def ctx(make_ctx):
    return make_ctx()


def read_audit(ctx) -> list[dict]:
    path = ctx.audit.path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
