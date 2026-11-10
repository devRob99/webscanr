"""End-to-end: `webscan demo` and the other CLI commands, fully offline."""

import csv
import json
import re
import shutil

import pytest
from typer.testing import CliRunner

from tests.conftest import EXAMPLE_CONFIG, ROOT
from webscan.cli import app

runner = CliRunner()
SENSITIVE = re.compile(r"example\.org|target\.local|203\.0\.113\.\d+|10\.0\.0\.\d+")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBSCAN_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setenv("WEBSCAN_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("WEBSCAN_LIVE_MODE", "false")
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.delenv("WEBSCAN_CONFIG_DIR", raising=False)
    monkeypatch.delenv("HACKERTARGET_API_KEY", raising=False)
    return tmp_path


def audit(env):
    return [json.loads(line) for line in (env / "logs" / "audit.jsonl").read_text().splitlines()]


def run(*args):
    return runner.invoke(app, list(args))


# ------------------------------------------------------------------ demo


def test_demo_runs_offline_and_writes_redacted_outputs(env):
    result = run("demo", "--no-pdf", "--operator", "capstone-tester")
    assert result.exit_code == 0, result.output
    out = env / "output" / "demo"
    for name in ("webscan_findings.json", "webscan_findings.csv", "webscan_batches.csv", "webscan_report_en.html",
                 "webscan_report_es.html"):
        assert (out / name).is_file(), name
        assert not SENSITIVE.search((out / name).read_text()), f"{name} leaks a raw hostname or IP"
    assert not SENSITIVE.search(result.output)
    assert "DEMO / MOCK DATA" in result.output and "Fix these 3 things first" in result.output
    assert "Critical" in result.output and "Upgrade jQuery" in result.output

    data = json.loads((out / "webscan_findings.json").read_text())
    findings = data["findings"]
    assert data["meta"]["data_mode"] == "mock" and data["meta"]["redacted"] is True
    assert all(f["data_source"] == "mock" for f in findings)
    assert [f["risk_score"] for f in findings] == sorted((f["risk_score"] for f in findings), reverse=True)

    # Spec scenario: medium-CVSS KEV finding on the donor portal outranks 9.8s on staging.
    rank = {(f["asset_name"], f["cve_id"] or f["knowledge_id"]): i for i, f in enumerate(findings)}
    jquery = findings[rank[("donor-portal", "CVE-2020-11023")]]
    openssh = findings[rank[("staging-site", "CVE-2023-38408")]]
    assert jquery["base_severity"] == 6.1 and jquery["in_cisa_kev"] and jquery["priority"] == "Critical"
    assert openssh["base_severity"] == 9.8 and openssh["priority"] == "Medium"
    assert rank[("donor-portal", "CVE-2020-11023")] < rank[("staging-site", "CVE-2023-38408")]
    assert rank[("donor-portal", "CVE-2020-11023")] < rank[("staging-site", "default-credentials")]
    assert jquery["score_breakdown"]["formula"].startswith("6.1 x 1.5 x 2 x 1.5")

    # Several findings collapse into one batch, ranked first.
    top = data["batches"][0]
    assert top["key"] == "upgrade:jquery>=3.5.0" and top["finding_count"] >= 5 and len(top["assets"]) >= 2
    assert len(data["summary"]["top_batches"]) == 3 and data["summary"]["grade"] in "ABCDF"

    # Deduplication across sources, override, unknown asset handling.
    hsts = findings[rank[("donor-portal", "missing-hsts")]]
    assert hsts["sources"] == ["hackertarget", "local", "quantro"]
    apache = findings[rank[("archived-brochure-site", "CVE-2021-41773")]]
    assert apache["priority"] == "High" and apache["score_breakdown"]["override_applied"]
    assert any(not f["asset_known"] and f["asset_name"].startswith("unlisted-asset-") for f in findings)
    assert any(f["asset_name"] == "file-server" and f["sources"] == ["quantro"] for f in findings)

    rows = list(csv.DictReader((out / "webscan_findings.csv").open()))
    assert len(rows) == len(findings) and rows[0]["rank"] == "1" and rows[0]["priority"] == "Critical"
    batches = list(csv.DictReader((out / "webscan_batches.csv").open()))
    assert batches[0]["remediation_key"] == "upgrade:jquery>=3.5.0"

    records = audit(env)
    events = {r["event"] for r in records}
    assert {"provider_run", "mock_response", "quantro_ingest", "prioritize", "report", "demo", "provider_skipped"} <= events
    assert all(r["operator"] == "capstone-tester" and r["mode"] == "mock" for r in records)
    assert not SENSITIVE.search((env / "logs" / "audit.jsonl").read_text())
    assert not SENSITIVE.search((env / "logs" / "webscan.log").read_text())


def test_demo_in_spanish(env):
    result = run("demo", "--lang", "es", "--no-pdf")
    assert result.exit_code == 0, result.output
    assert "Corrija primero estas 3 cosas" in result.output and "Actualizar jQuery" in result.output
    assert "DATOS SIMULADOS" in result.output
    html = (env / "output" / "demo" / "webscan_report_es.html").read_text()
    for text in ("Informe de evaluación de seguridad", "Qué significa", "Cómo corregirlo", "Controles CIS v8",
                 "Marco de Ciberseguridad del NIST", "Lo controla la plataforma", 'lang="es"'):
        assert text in html, text
    en = (env / "output" / "demo" / "webscan_report_en.html").read_text()
    for text in ("Security Assessment Report", "Fix these 3 things first", "Technical details", "<details>",
                 "CIS Controls v8", "NIST Cybersecurity Framework 2.0", "Overall security grade", "KEV",
                 "Wix controls this setting", "demonstration (mock) data"):
        assert text in en, text
    assert "<script" not in en and "http://" not in en.split("</style>")[0]  # self-contained, no external assets
    data = json.loads((env / "output" / "demo" / "webscan_findings.json").read_text())
    assert data["meta"]["language"] == "es" and "hallazgos" in data["summary"]["paragraph"]


def test_demo_with_wip_stubs_adds_mock_findings(env):
    assert run("demo", "--no-pdf", "--include-wip").exit_code == 0
    data = json.loads((env / "output" / "demo" / "webscan_findings.json").read_text())
    sources = {s for f in data["findings"] for s in f["sources"]}
    assert {"rdap", "hibp", "shodan", "reputation", "lookalike", "geoip"} <= sources
    assert all(f["data_source"] == "mock" for f in data["findings"])


def test_demo_no_redact_goes_to_unredacted_folder_and_is_audited(env):
    result = run("demo", "--no-pdf", "--no-redact")
    assert result.exit_code == 0 and "redaction is OFF" in result.output
    out = env / "output" / "unredacted" / "demo"
    assert "example.org" in (out / "webscan_findings.json").read_text()
    assert not (env / "output" / "demo").exists()
    records = audit(env)
    assert records[0]["event"] == "no_redact_enabled"
    assert not SENSITIVE.search((env / "logs" / "audit.jsonl").read_text())  # the audit log stays redacted


def test_mock_results_dataset_matches_the_pipeline_and_shows_the_scenario(env):
    dataset = json.loads((ROOT / "data" / "mock_results.json").read_text())
    assert not SENSITIVE.search(json.dumps(dataset))
    result = run("prioritize", "--input", str(ROOT / "data" / "mock_results.json"), "--example-config")
    assert result.exit_code == 0, result.output
    run("demo", "--no-pdf")
    demo = json.loads((env / "output" / "demo" / "webscan_findings.json").read_text())
    assert demo["meta"]["raw_finding_count"] == len(dataset["findings"])


# ------------------------------------------------------------------ fail-safe behaviour without config


def test_commands_halt_without_a_whitelist(env, tmp_path, monkeypatch):
    empty = tmp_path / "empty-config"
    empty.mkdir()
    for args in (["scan", "--all"], ["scope-check", "example.org"], ["prioritize"], ["report"],
                 ["ingest-quantro", str(ROOT / "data" / "mock" / "quantro_report.json")]):
        result = run(*args, "--config-dir", str(empty))
        assert result.exit_code == 2, args
        assert "SCOPE HALT" in result.output
    assert audit(env)[-1]["event"] == "scope_halt"
    assert run("validate", "--config-dir", str(empty)).exit_code == 1


def test_malformed_whitelist_halts(env, tmp_path):
    config = tmp_path / "config"
    shutil.copytree(EXAMPLE_CONFIG, config)
    for path in config.glob("*.example.json"):
        path.rename(config / path.name.replace(".example", ""))
    (config / "allowed_targets.json").write_text('{"domains": ["not a domain!"]}')
    assert run("scan", "--all", "--config-dir", str(config)).exit_code == 2


# ------------------------------------------------------------------ individual commands


def test_validate_example_config(env):
    result = run("validate", "--example-config")
    assert result.exit_code == 0, result.output
    assert "Configuration is valid" in result.output and "approved external providers: none" in result.output


def test_validate_reports_assets_outside_the_whitelist(env, tmp_path):
    config = tmp_path / "config"
    shutil.copytree(EXAMPLE_CONFIG, config)
    for path in config.glob("*.example.json"):
        path.rename(config / path.name.replace(".example", ""))
    assets = json.loads((config / "assets_metadata.json").read_text())
    assets["assets"][0]["hostnames"].append("shadow.example.com")
    (config / "assets_metadata.json").write_text(json.dumps(assets))
    result = run("validate", "--config-dir", str(config))
    assert result.exit_code == 1 and "missing from the whitelist" in result.output
    scan = run("scan", "--all", "--config-dir", str(config))
    assert scan.exit_code == 2 and "Nothing was scanned" in scan.output


@pytest.mark.parametrize(
    "target,code,text",
    [
        ("donate.example.org", 0, "IN SCOPE"),
        ("10.0.0.5", 0, "never"),
        ("evil.example.com", 2, "OUT OF SCOPE"),
        ("example.org;id", 2, "shell metacharacters"),
        ("203.0.113.0/24", 2, "partially overlaps"),
    ],
)
def test_scope_check(env, target, code, text):
    result = run("scope-check", target, "--example-config")
    assert result.exit_code == code and text in result.output
    assert "example.org" not in result.output.replace("evil.example.com", "")
    last = audit(env)[-1]
    assert last["event"] == ("scope_check" if code == 0 else "scope_rejection")


def test_scan_ingest_prioritize_report_flow(env):
    scan = run("scan", "--asset", "archived-brochure-site", "--example-config")
    assert scan.exit_code == 0, scan.output
    assert "mock" in scan.output and "live mode was not requested" in scan.output
    assert run("scan", "--asset", "nope", "--example-config").exit_code == 1
    assert run("scan", "--example-config").exit_code == 1  # neither --asset nor --all
    assert run("scan", "--all", "--asset", "donor-portal", "--example-config").exit_code == 1

    ingest = run("ingest-quantro", str(ROOT / "data" / "mock" / "quantro_report.json"), "--example-config")
    assert ingest.exit_code == 0 and "Ingested" in ingest.output and "13" in ingest.output

    prioritized = run("prioritize", "--example-config")
    assert prioritized.exit_code == 0 and "Remediation batches" in prioritized.output
    assert (env / "output" / "state" / "prioritized.json").is_file()

    for fmt, name in (("json", "webscan_findings.json"), ("csv", "webscan_findings.csv"), ("html", "webscan_report_es.html")):
        result = run("report", "--format", fmt, "--lang", "es", "--example-config")
        assert result.exit_code == 0, result.output
        assert (env / "output" / name).is_file()
    terminal = run("report", "--example-config")
    assert terminal.exit_code == 0 and "Top findings" in terminal.output
    data = json.loads((env / "output" / "webscan_findings.json").read_text())
    assets = {f["asset_name"] for f in data["findings"]}
    assert "archived-brochure-site" in assets and "file-server" in assets

    # Re-scanning the same asset replaces its findings instead of duplicating them.
    before = len(json.loads((env / "output" / "state" / "findings_raw.json").read_text()))
    run("scan", "--asset", "archived-brochure-site", "--example-config")
    assert len(json.loads((env / "output" / "state" / "findings_raw.json").read_text())) == before

    events = [r["event"] for r in audit(env)]
    assert "scan" in events and "quantro_ingest" in events and "report" in events


def test_live_flag_alone_does_not_go_live(env):
    result = run("scan", "--asset", "donor-portal", "--live", "--example-config")
    assert result.exit_code == 0, result.output
    assert "WEBSCAN_LIVE_MODE is not set" in result.output
    raw = json.loads((env / "output" / "state" / "findings_raw.json").read_text())
    assert raw and all(f["data_source"] == "mock" for f in raw)


def test_live_env_without_approval_still_uses_mock(env, monkeypatch):
    monkeypatch.setenv("WEBSCAN_LIVE_MODE", "true")
    monkeypatch.setenv("HACKERTARGET_API_KEY", "placeholder-key-000000")
    result = run("scan", "--asset", "archived-brochure-site", "--live", "--example-config")
    assert result.exit_code == 0, result.output  # the autouse fixture would fail on any socket use
    assert "not listed in approved_providers" in result.output
    assert "placeholder-key" not in (env / "logs" / "audit.jsonl").read_text()


def test_bad_quantro_file_gives_a_clear_error(env, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    result = run("ingest-quantro", str(bad), "--example-config")
    assert result.exit_code == 1 and "Could not read the Quantro report" in result.output


def test_prioritize_without_findings_explains_what_to_do(env):
    result = run("prioritize", "--example-config")
    assert result.exit_code == 1 and "No findings yet" in result.output


def test_changes_between_runs(env):
    assert run("changes", "--demo").exit_code == 1  # no history yet
    run("demo", "--no-pdf")
    run("demo", "--no-pdf", "--include-wip")
    result = run("changes", "--demo")
    assert result.exit_code == 0 and "New findings" in result.output
    alerts = (env / "output" / "demo" / "alerts.jsonl").read_text().splitlines()
    assert json.loads(alerts[-1])["new_findings"] >= 5
    run("demo", "--no-pdf", "--include-wip")
    assert "No changes" in run("changes", "--demo").output


def test_refresh_reference_data_failure_keeps_snapshots(env, monkeypatch):
    from webscan.enrichment import reference

    def no_network(url):
        raise OSError("offline")

    monkeypatch.setattr(reference, "_download", no_network)
    monkeypatch.setattr(reference.refresh, "__defaults__", (no_network,))
    result = run("refresh-reference-data")
    assert result.exit_code == 1 and "existing snapshots were kept" in result.output
    assert audit(env)[-1]["status"] == "error"


def test_help_lists_every_command():
    result = run("--help")
    for command in ("validate", "scope-check", "scan", "ingest-quantro", "prioritize", "report", "demo",
                    "refresh-reference-data"):
        assert command in result.output
    for command in ("validate", "scope-check", "scan", "ingest-quantro", "prioritize", "report", "demo",
                    "refresh-reference-data"):
        assert "--operator" in run(command, "--help").output
