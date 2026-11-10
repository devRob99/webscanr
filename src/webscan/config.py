"""Loads .env and config/*.json, and validates them.

Real organization data lives only in config/*.json (gitignored). The committed
config/*.example.json files hold placeholder data and are used by ``webscan demo`` and by
any command run with ``--example-config``.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

from webscan.models import EXPOSURE_TIERS, PRIORITIES

ROOT = Path(os.environ.get("WEBSCAN_HOME") or Path(__file__).resolve().parents[2])
CONFIG_NAMES = ("allowed_targets", "assets_metadata", "scoring", "providers")
PLATFORMS = ("wordpress", "wix", "squarespace", "google_sites", "custom")


class ConfigError(Exception):
    """A config file is missing, unreadable, or invalid."""


DEFAULT_SCORING: dict[str, Any] = {
    "exposure_multipliers": {"public": 1.5, "staging": 1.0, "internal": 0.8},
    "criticality_weights": {"1": 1.0, "2": 1.5, "3": 2.0},
    "exploit_factors": {"known_exploit": 1.5, "epss_high": 1.3, "none": 1.0},
    "epss_threshold": 0.10,
    "bands": {"Critical": 60, "High": 40, "Medium": 20, "Low": 5, "Info": 0},
    "exploit_override_min_priority": "High",
    "grade": {
        "penalties": {"Critical": 15, "High": 7, "Medium": 3, "Low": 1, "Info": 0},
        "thresholds": {"A": 90, "B": 80, "C": 70, "D": 60},
        "critical_caps_at": "D",
    },
    "unknown_asset_defaults": {"exposure_tier": "public", "asset_criticality": 2},
}

DEFAULT_PROVIDERS: dict[str, Any] = {
    "approved_providers": [],
    "enabled_providers": ["hackertarget", "quantro", "local"],
    "hackertarget": {
        "base_url": "https://api.hackertarget.com",
        "endpoints": ["nmap", "httpheaders", "dnslookup", "hostsearch", "reverseiplookup"],
        "wip_endpoints_in_mock": ["nikto", "openvas"],
        "min_delay_seconds": 2.0,
        "max_concurrent": 1,
        "daily_quota": 50,
        "timeout_seconds": 30,
        "max_retries": 4,
        "backoff_base_seconds": 2.0,
        "backoff_max_seconds": 60.0,
    },
    "local": {
        "checks": ["headers", "tls", "cookies", "email", "donation", "privacy", "exposed_files"],
        "request_delay_seconds": 1.0,
        "timeout_seconds": 10,
        "cert_expiry_warning_days": 30,
        "dkim_selectors": ["default", "google", "selector1", "selector2", "k1", "mail"],
        "exposed_paths": ["/.git/HEAD", "/.env", "/backup.zip", "/backup.sql", "/wp-config.php.bak"],
    },
    "quantro": {
        "field_mapping": {
            "findings_path": "findings",
            "fields": {
                "vulnerability_name": "title",
                "cve_id": "cve",
                "base_severity": "cvss",
                "severity_label": "severity",
                "host": "host",
                "evidence": "url",
                "description": "description",
                "has_known_exploit": "exploit_available",
                "references": "references",
            },
            "severity_label_scores": {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0},
        }
    },
    "stubs": {"lookalike_max_variants": 40},
}


def _strip_comments(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_comments(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [_strip_comments(v) for v in obj]
    return obj


def load_json(path: Path) -> Any:
    try:
        with Path(path).open(encoding="utf-8") as fh:
            return _strip_comments(json.load(fh))
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {Path(path).name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Config file {Path(path).name} is not readable JSON: {exc}") from exc


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


@dataclass
class Settings:
    root: Path
    config_dir: Path
    output_dir: Path
    log_dir: Path
    data_dir: Path
    use_examples: bool = False
    env: Mapping[str, str] = field(default_factory=dict)

    @property
    def live_mode_env(self) -> bool:
        return str(self.env.get("WEBSCAN_LIVE_MODE", "")).strip().lower() in ("1", "true", "yes", "on")

    def config_path(self, name: str) -> Path:
        suffix = ".example.json" if self.use_examples else ".json"
        return self.config_dir / f"{name}{suffix}"

    def get_env(self, key: str) -> str | None:
        value = self.env.get(key)
        return value.strip() if value and value.strip() else None


def load_settings(
    config_dir: Path | None = None,
    use_examples: bool = False,
    output_dir: Path | None = None,
    log_dir: Path | None = None,
    env: Mapping[str, str] | None = None,
    root: Path | None = None,
) -> Settings:
    root = Path(root or ROOT)
    if env is None:
        merged: dict[str, str] = {k: v for k, v in dotenv_values(root / ".env").items() if v is not None}
        merged.update(os.environ)  # real environment wins over .env
        env = merged

    def pick(explicit: Path | None, env_key: str, default: str) -> Path:
        raw = explicit or env.get(env_key) or default
        path = Path(raw)
        return path if path.is_absolute() else root / path

    return Settings(
        root=root,
        config_dir=pick(config_dir, "WEBSCAN_CONFIG_DIR", "config"),
        output_dir=pick(output_dir, "WEBSCAN_OUTPUT_DIR", "output"),
        log_dir=pick(log_dir, "WEBSCAN_LOG_DIR", "logs"),
        data_dir=root / "data",
        use_examples=use_examples,
        env=env,
    )


# --------------------------------------------------------------------------- scoring / providers


def validate_scoring(cfg: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(cfg, dict):
        return ["scoring config must be a JSON object"]

    def positive_numbers(section: str, keys: tuple[str, ...]) -> None:
        block = cfg.get(section)
        if not isinstance(block, dict):
            errors.append(f"'{section}' must be an object")
            return
        for key in keys:
            value = block.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                errors.append(f"'{section}.{key}' must be a positive number")

    positive_numbers("exposure_multipliers", EXPOSURE_TIERS)
    positive_numbers("criticality_weights", ("1", "2", "3"))
    positive_numbers("exploit_factors", ("known_exploit", "epss_high", "none"))
    threshold = cfg.get("epss_threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
        errors.append("'epss_threshold' must be between 0 and 1")
    bands = cfg.get("bands")
    if not isinstance(bands, dict) or any(p not in bands for p in PRIORITIES):
        errors.append(f"'bands' must define a threshold for each of {PRIORITIES}")
    else:
        values = [bands[p] for p in PRIORITIES]
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in values):
            errors.append("'bands' thresholds must be numbers")
        elif values != sorted(values, reverse=True) or not all(0 <= v <= 100 for v in values):
            errors.append("'bands' thresholds must fall from Critical to Info within 0-100")
    if cfg.get("exploit_override_min_priority") not in PRIORITIES:
        errors.append(f"'exploit_override_min_priority' must be one of {PRIORITIES}")
    grade = cfg.get("grade")
    if not isinstance(grade, dict) or not isinstance(grade.get("penalties"), dict) or not isinstance(
        grade.get("thresholds"), dict
    ):
        errors.append("'grade' must define 'penalties' and 'thresholds'")
    defaults = cfg.get("unknown_asset_defaults", {})
    if defaults.get("exposure_tier") not in EXPOSURE_TIERS or defaults.get("asset_criticality") not in (1, 2, 3):
        errors.append("'unknown_asset_defaults' needs a valid exposure_tier and asset_criticality")
    return errors


def validate_providers(cfg: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(cfg, dict):
        return ["providers config must be a JSON object"]
    for key in ("approved_providers", "enabled_providers"):
        value = cfg.get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            errors.append(f"'{key}' must be a list of provider names")
    ht = cfg.get("hackertarget")
    if not isinstance(ht, dict):
        errors.append("'hackertarget' must be an object")
    else:
        if not str(ht.get("base_url", "")).startswith("https://"):
            errors.append("'hackertarget.base_url' must use https://")
        for key in ("min_delay_seconds", "timeout_seconds", "backoff_base_seconds", "backoff_max_seconds"):
            value = ht.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                errors.append(f"'hackertarget.{key}' must be a non-negative number")
        for key in ("max_concurrent", "daily_quota", "max_retries"):
            value = ht.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(f"'hackertarget.{key}' must be a non-negative integer")
        if isinstance(ht.get("max_concurrent"), int) and ht["max_concurrent"] < 1:
            errors.append("'hackertarget.max_concurrent' must be at least 1")
    mapping = cfg.get("quantro", {}).get("field_mapping") if isinstance(cfg.get("quantro"), dict) else None
    if not isinstance(mapping, dict) or not isinstance(mapping.get("fields"), dict):
        errors.append("'quantro.field_mapping.fields' must be an object")
    else:
        for required in ("vulnerability_name", "host"):
            if required not in mapping["fields"]:
                errors.append(f"'quantro.field_mapping.fields' must map '{required}'")
    return errors


def _load_with_defaults(settings: Settings, name: str, defaults: dict[str, Any], validator) -> dict[str, Any]:
    path = settings.config_path(name)
    cfg = _deep_merge(defaults, load_json(path)) if path.exists() else copy.deepcopy(defaults)
    errors = validator(cfg)
    if errors:
        raise ConfigError(f"{path.name}: " + "; ".join(errors))
    return cfg


def load_scoring(settings: Settings) -> dict[str, Any]:
    """Scoring config; falls back to the documented defaults when the file is absent."""
    return _load_with_defaults(settings, "scoring", DEFAULT_SCORING, validate_scoring)


def load_providers(settings: Settings) -> dict[str, Any]:
    """Provider config; the built-in defaults approve no external provider."""
    return _load_with_defaults(settings, "providers", DEFAULT_PROVIDERS, validate_providers)


# --------------------------------------------------------------------------- asset metadata


@dataclass
class Asset:
    alias: str
    description: str = ""
    hostnames: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    exposure_tier: str = "public"
    asset_criticality: int = 2
    platform: str | None = None
    donation_paths: list[str] = field(default_factory=list)
    email_domain: str | None = None

    @property
    def targets(self) -> list[str]:
        return [*self.hostnames, *self.ips]


@dataclass
class ResolvedAsset:
    alias: str
    exposure_tier: str
    asset_criticality: int
    platform: str | None
    known: bool


def validate_assets(cfg: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(cfg, dict) or not isinstance(cfg.get("assets"), list):
        return ["assets_metadata must be an object with an 'assets' list"]
    seen_alias: set[str] = set()
    seen_target: dict[str, str] = {}
    for index, raw in enumerate(cfg["assets"]):
        label = f"assets[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{label} must be an object")
            continue
        alias = raw.get("alias")
        if not isinstance(alias, str) or not alias.strip():
            errors.append(f"{label}.alias is required")
            continue
        label = f"asset '{alias}'"
        if alias in seen_alias:
            errors.append(f"{label}: duplicate alias")
        seen_alias.add(alias)
        if raw.get("exposure_tier") not in EXPOSURE_TIERS:
            errors.append(f"{label}: exposure_tier must be one of {EXPOSURE_TIERS}")
        if raw.get("asset_criticality") not in (1, 2, 3) or isinstance(raw.get("asset_criticality"), bool):
            errors.append(f"{label}: asset_criticality must be 1, 2, or 3")
        if raw.get("platform") not in (None, *PLATFORMS):
            errors.append(f"{label}: platform must be one of {PLATFORMS} or omitted")
        hostnames, ips = raw.get("hostnames", []), raw.get("ips", [])
        if not isinstance(hostnames, list) or not isinstance(ips, list):
            errors.append(f"{label}: hostnames and ips must be lists")
            continue
        if not hostnames and not ips:
            errors.append(f"{label}: needs at least one hostname or IP")
        for ip in ips:
            try:
                ipaddress.ip_address(str(ip))
            except ValueError:
                errors.append(f"{label}: an entry in 'ips' is not a valid IP address")
        for target in [*hostnames, *ips]:
            key = str(target).lower()
            if key in seen_target and seen_target[key] != alias:
                errors.append(f"{label}: a hostname or IP is also listed under '{seen_target[key]}'")
            seen_target[key] = alias
    return errors


class AssetRegistry:
    def __init__(self, data: dict[str, Any], unknown_defaults: dict[str, Any] | None = None) -> None:
        errors = validate_assets(data)
        if errors:
            raise ConfigError("assets_metadata: " + "; ".join(errors))
        self.organization_alias: str = data.get("organization_alias") or "the organization"
        self.assets: list[Asset] = [
            Asset(
                alias=a["alias"],
                description=a.get("description", ""),
                hostnames=[str(h).lower().rstrip(".") for h in a.get("hostnames", [])],
                ips=[str(i) for i in a.get("ips", [])],
                exposure_tier=a["exposure_tier"],
                asset_criticality=a["asset_criticality"],
                platform=a.get("platform"),
                donation_paths=list(a.get("donation_paths", [])),
                email_domain=a.get("email_domain"),
            )
            for a in data["assets"]
        ]
        self.unknown_defaults = unknown_defaults or DEFAULT_SCORING["unknown_asset_defaults"]
        self._by_alias = {a.alias: a for a in self.assets}
        self._by_target: dict[str, Asset] = {}
        for asset in self.assets:
            for target in asset.targets:
                self._by_target[target.lower()] = asset
        self.unknown_seen: dict[str, str] = {}  # generated alias -> first reason seen

    @classmethod
    def from_file(cls, path: Path, unknown_defaults: dict[str, Any] | None = None) -> AssetRegistry:
        return cls(load_json(path), unknown_defaults)

    def get(self, alias: str) -> Asset | None:
        return self._by_alias.get(alias)

    def lookup(self, target: str) -> Asset | None:
        return self._by_target.get(str(target).lower().rstrip("."))

    def resolve(self, target: str) -> ResolvedAsset:
        """Asset context for a target; unknown targets get conservative defaults and a flag."""
        asset = self.lookup(target)
        if asset:
            return ResolvedAsset(asset.alias, asset.exposure_tier, asset.asset_criticality, asset.platform, True)
        digest = hashlib.sha256(str(target).lower().encode()).hexdigest()[:6]
        alias = f"unlisted-asset-{digest}"
        self.unknown_seen.setdefault(alias, "not in assets_metadata")
        return ResolvedAsset(
            alias,
            self.unknown_defaults["exposure_tier"],
            self.unknown_defaults["asset_criticality"],
            None,
            False,
        )

    def alias_map(self) -> dict[str, str]:
        return {target: asset.alias for target, asset in self._by_target.items()}

    def org_domains(self) -> list[str]:
        """Registrable-looking parents of every known hostname (last two labels)."""
        domains: set[str] = set()
        for asset in self.assets:
            for host in [*asset.hostnames, asset.email_domain or ""]:
                labels = host.split(".")
                if len(labels) >= 2:
                    domains.add(".".join(labels[-2:]))
        return sorted(domains)
