"""Models, config validation, redaction, and audit logging."""

import copy
import json

import pytest

from tests.conftest import EXAMPLE_CONFIG, read_audit
from webscan.config import (
    DEFAULT_PROVIDERS,
    DEFAULT_SCORING,
    AssetRegistry,
    ConfigError,
    load_json,
    validate_assets,
    validate_providers,
    validate_scoring,
)
from webscan.models import Finding, FindingValidationError
from webscan.sanitize.redact import Redactor, redact, redact_always


def make_finding(**overrides):
    base = dict(
        vulnerability_name="Test finding", cve_id=None, base_severity=5.0, asset_name="donor-portal",
        exposure_tier="public", asset_criticality=3, has_known_exploit=False,
    )
    base.update(overrides)
    return Finding(**base)


# ------------------------------------------------------------------ Finding contract


def test_finding_accepts_valid_values_and_normalizes_cve():
    finding = make_finding(cve_id="cve-2020-11023", base_severity=6)
    assert finding.cve_id == "CVE-2020-11023"
    assert finding.base_severity == 6.0
    assert finding.finding_id.startswith("F-")
    assert Finding.from_dict(finding.to_dict()) == finding


@pytest.mark.parametrize(
    "overrides",
    [
        {"base_severity": -0.1},
        {"base_severity": 10.1},
        {"base_severity": "high"},
        {"base_severity": True},
        {"exposure_tier": "dmz"},
        {"asset_criticality": 0},
        {"asset_criticality": 4},
        {"asset_criticality": True},
        {"cve_id": "CVE-20-1"},
        {"cve_id": "2020-11023"},
        {"cve_id": "CVE-2020-11023; DROP"},
        {"vulnerability_name": "  "},
        {"asset_name": ""},
        {"epss_score": 1.5},
        {"data_source": "prod"},
        {"priority": "Urgent"},
    ],
)
def test_finding_rejects_invalid_values(overrides):
    with pytest.raises(FindingValidationError):
        make_finding(**overrides)


def test_dedup_key_prefers_cve_then_knowledge_id():
    assert make_finding(cve_id="CVE-2020-11023").dedup_key == ("donor-portal", "CVE-2020-11023")
    assert make_finding(knowledge_id="missing-hsts").dedup_key == ("donor-portal", "missing-hsts")
    assert make_finding(vulnerability_name="Some Odd Thing!").dedup_key == ("donor-portal", "some-odd-thing")


# ------------------------------------------------------------------ config


def test_example_configs_match_built_in_defaults_and_validate():
    assert load_json(EXAMPLE_CONFIG / "scoring.example.json") == DEFAULT_SCORING
    assert load_json(EXAMPLE_CONFIG / "providers.example.json") == DEFAULT_PROVIDERS
    assert validate_scoring(DEFAULT_SCORING) == []
    assert validate_providers(DEFAULT_PROVIDERS) == []
    assert validate_assets(load_json(EXAMPLE_CONFIG / "assets_metadata.example.json")) == []
    assert DEFAULT_PROVIDERS["approved_providers"] == []  # nothing external is approved by default


def test_invalid_scoring_config_is_reported():
    bad = copy.deepcopy(DEFAULT_SCORING)
    bad["exposure_multipliers"]["public"] = -1
    bad["bands"]["High"] = 90  # no longer descending
    bad["epss_threshold"] = 2
    errors = validate_scoring(bad)
    assert len(errors) == 3


def test_invalid_providers_config_is_reported():
    bad = copy.deepcopy(DEFAULT_PROVIDERS)
    bad["hackertarget"]["base_url"] = "http://api.hackertarget.com"
    bad["hackertarget"]["max_concurrent"] = 0
    bad["approved_providers"] = "hackertarget"
    assert len(validate_providers(bad)) == 3


def test_invalid_assets_metadata_is_rejected():
    bad = {
        "assets": [
            {"alias": "a", "hostnames": ["a.example.org"], "exposure_tier": "public", "asset_criticality": 5},
            {"alias": "a", "hostnames": ["a.example.org"], "exposure_tier": "moon", "asset_criticality": 1},
            {"alias": "b", "hostnames": [], "ips": ["not-an-ip"], "exposure_tier": "public", "asset_criticality": 1},
        ]
    }
    assert len(validate_assets(bad)) >= 4
    with pytest.raises(ConfigError):
        AssetRegistry(bad)


def test_unknown_asset_gets_conservative_defaults(ctx):
    resolved = ctx.assets.resolve("events.example.org")
    assert not resolved.known
    assert resolved.exposure_tier == "public" and resolved.asset_criticality == 2
    assert resolved.alias.startswith("unlisted-asset-")
    assert "example" not in resolved.alias
    known = ctx.assets.resolve("DONATE.example.org")
    assert known.known and known.alias == "donor-portal" and known.asset_criticality == 3


def test_real_config_is_required_outside_demo(tmp_path, make_ctx):
    from webscan.scope.enforcer import ScopeError

    empty = tmp_path / "config"
    empty.mkdir()
    with pytest.raises(ScopeError):
        make_ctx(demo=False, config_dir=empty)


# ------------------------------------------------------------------ redaction


@pytest.fixture
def redactor():
    return Redactor(
        alias_map={"donate.example.org": "donor-portal", "203.0.113.10": "donor-portal", "example.org": "main-website"},
        org_domains=["example.org"],
    )


def test_known_hosts_and_ips_become_aliases(redactor):
    out = redactor("GET https://donate.example.org/donate/ (203.0.113.10) and example.org")
    assert out == "GET https://donor-portal/donate/ (donor-portal) and main-website"


def test_unknown_org_hosts_ips_emails_and_internal_names_are_masked(redactor):
    text = (
        "events.example.org 198.51.100.7 10.0.0.5/24 2001:db8::10 jane.doe@example.org "
        "files.target.local printer.lan MAIL.EXAMPLE.ORG"
    )
    out = redactor(text)
    for raw in ("events", "198.51", "10.0.0.5", "2001:db8", "jane", "target.local", "printer", "MAIL."):
        assert raw not in out
    assert out.count("[REDACTED-HOST]") == 4
    assert out.count("[REDACTED-IP]") == 3
    assert "[REDACTED-EMAIL]" in out


@pytest.mark.parametrize(
    "secret",
    [
        "https://api.hackertarget.com/nmap/?q=x&apikey=abc123def456ghi789",
        "Authorization: Bearer abcdef1234567890abcdef",
        "password: hunter2hunter2",
        "API_KEY='s3cr3t-value-here'",
        "token=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "key sk_live_abcdefghijklmnop1234",
        "AKIAABCDEFGHIJKLMNOP",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456",
    ],
)
def test_secrets_are_masked(redactor, secret):
    out = redactor(secret)
    assert "[REDACTED-SECRET]" in out
    for raw in ("abc123def456", "hunter2", "s3cr3t", "9f86d081", "abcdefghijklmnop", "AKIAABCDEFGH", "eyJzdWIi"):
        assert raw not in out


def test_version_numbers_and_plain_text_survive(redactor):
    text = "OpenSSH 8.9p1 and Apache httpd 2.4.49 on port 443/tcp; upgrade jQuery to 3.5.0 (CVE-2020-11023)"
    assert redactor(text) == text


def test_redaction_can_be_disabled_but_audit_path_stays_redacted(redactor):
    redactor.enabled = False
    assert redactor("donate.example.org") == "donate.example.org"
    assert redactor.redact("donate.example.org") == "donor-portal"


def test_redact_obj_walks_nested_structures(redactor):
    out = redactor.redact_obj({"a": ["203.0.113.10", {"b": "x@example.org"}], "n": 5})
    assert out == {"a": ["donor-portal", {"b": "[REDACTED-EMAIL]"}], "n": 5}


def test_module_level_redact_uses_context_redactor(ctx):
    assert redact("staging.example.org") == "staging-site"
    assert redact_always("10.0.0.5") == "file-server"


# ------------------------------------------------------------------ audit log


def test_audit_log_is_append_only_jsonl_with_aliases(ctx):
    ctx.audit.operator = "tester"
    ctx.audit.log("scan", provider="hackertarget", targets=["donate.example.org", "198.51.100.9"], status="ok",
                  duration_ms=12.345, detail="called https://donate.example.org/?apikey=supersecretkey1")
    ctx.audit.log("scan", provider="local", targets=["10.0.0.5"])
    records = read_audit(ctx)
    assert len(records) == 2
    first = records[0]
    assert first["operator"] == "tester"
    assert first["targets"][0] == "donor-portal"
    assert first["targets"][1].startswith("unlisted:")
    assert first["mode"] == "mock" and first["status"] == "ok" and first["duration_ms"] == 12.3
    assert "timestamp" in first and first["command"] == "test"
    raw = ctx.audit.path.read_text()
    for sensitive in ("example.org", "198.51.100.9", "10.0.0.5", "supersecretkey1"):
        assert sensitive not in raw


def test_no_redact_is_recorded_and_audit_stays_redacted(make_ctx):
    ctx = make_ctx(no_redact=True)
    assert "unredacted" in ctx.output_dir.parts
    ctx.audit.log("scan", targets=["donate.example.org"], detail="raw donate.example.org")
    records = read_audit(ctx)
    assert records[0]["event"] == "no_redact_enabled"
    assert "example.org" not in json.dumps(records)


def test_timed_audit_records_errors(ctx):
    with pytest.raises(RuntimeError), ctx.audit.timed("api_call", provider="x"):
        raise RuntimeError("boom")
    record = read_audit(ctx)[-1]
    assert record["status"] == "error" and "boom" in record["detail"] and record["duration_ms"] >= 0
