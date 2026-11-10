"""Run context: everything a command needs, built once and passed around explicitly."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from webscan.audit.logger import AuditLogger
from webscan.config import AssetRegistry, ConfigError, Settings, load_providers, load_scoring, load_settings
from webscan.providers.guard import ExternalCallGuard
from webscan.sanitize.redact import Redactor, redact_always, set_active_redactor
from webscan.scope.enforcer import ScopeEnforcer, ScopeError

log = logging.getLogger("webscan")


class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_always(record.getMessage())
        record.args = ()
        return True


def setup_logging(log_dir: Path) -> None:
    """File logging for diagnostics. Every message is redacted before it is written."""
    if any(getattr(h, "_webscan", False) for h in log.handlers):
        return
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.FileHandler(log_dir / "webscan.log", encoding="utf-8")
    except OSError:
        handler = logging.NullHandler()
    handler._webscan = True  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler.addFilter(_RedactingFilter())
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


@dataclass
class RunContext:
    settings: Settings
    scoring_cfg: dict[str, Any]
    providers_cfg: dict[str, Any]
    scope: ScopeEnforcer
    assets: AssetRegistry
    redactor: Redactor
    audit: AuditLogger
    guard: ExternalCallGuard
    lang: str = "en"
    demo: bool = False
    live_requested: bool = False
    no_redact: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def output_dir(self) -> Path:
        base = self.settings.output_dir
        if self.no_redact:
            base = base / "unredacted"
        return base / "demo" if self.demo else base

    @property
    def state_dir(self) -> Path:
        return self.output_dir / "state"

    @property
    def mode_label(self) -> str:
        return "live" if (self.live_requested and self.settings.live_mode_env and not self.demo) else "mock"

    def warn(self, message: str) -> None:
        clean = redact_always(message)
        if clean not in self.warnings:
            self.warnings.append(clean)
        log.warning(clean)


def build_context(
    command: str,
    *,
    operator: str | None = None,
    demo: bool = False,
    use_examples: bool = False,
    config_dir: Path | None = None,
    output_dir: Path | None = None,
    log_dir: Path | None = None,
    live: bool = False,
    no_redact: bool = False,
    lang: str = "en",
    env: Mapping[str, str] | None = None,
    root: Path | None = None,
) -> RunContext:
    """Load config, enforce the fail-safe whitelist check, and wire up shared services.

    Raises ScopeError when the whitelist is missing or malformed, and ConfigError for any
    other invalid config file. Nothing touches the network here.
    """
    settings = load_settings(
        config_dir=config_dir, use_examples=use_examples or demo, output_dir=output_dir, log_dir=log_dir,
        env=env, root=root,
    )
    setup_logging(settings.log_dir)
    audit = AuditLogger(settings.log_dir / "audit.jsonl", operator=operator, command=command)
    mode = "live" if (live and not demo and settings.live_mode_env) else "mock"

    try:
        scope = ScopeEnforcer.from_file(settings.config_path("allowed_targets"))
    except ScopeError as exc:
        audit.log("scope_halt", status="halted", mode=mode, detail=str(exc))
        raise
    try:
        scoring_cfg = load_scoring(settings)
        providers_cfg = load_providers(settings)
        assets = AssetRegistry.from_file(
            settings.config_path("assets_metadata"), scoring_cfg["unknown_asset_defaults"]
        )
    except ConfigError as exc:
        audit.log("config_error", status="halted", mode=mode, detail=str(exc))
        raise

    redactor = Redactor(
        alias_map=assets.alias_map(),
        org_domains=[*assets.org_domains(), *scope.listed_domains()],
        enabled=not no_redact,
    )
    set_active_redactor(redactor)
    audit.redactor = redactor
    guard = ExternalCallGuard(settings, providers_cfg, scope, audit, live_requested=live, demo=demo)
    ctx = RunContext(
        settings=settings, scoring_cfg=scoring_cfg, providers_cfg=providers_cfg, scope=scope, assets=assets,
        redactor=redactor, audit=audit, guard=guard, lang=lang, demo=demo, live_requested=live,
        no_redact=no_redact,
    )
    if no_redact:
        audit.log("no_redact_enabled", status="warning", mode=mode, detail="Unredacted local output requested")
    return ctx
