"""WIP third-party provider stubs: mock by default, gated when live, never crash a run."""

import json

import pytest

from tests.conftest import ROOT
from webscan.models import Finding
from webscan.providers.guard import LiveModeError
from webscan.providers.stubs import STUB_PROVIDERS
from webscan.providers.stubs.local_llm import LocalLlmError, LocalLlmProvider
from webscan.providers.stubs.lookalike import LookalikeProvider, generate_variants
from webscan.providers.stubs.nvd import NvdProvider
from webscan.providers.stubs.rdap import RdapProvider
from webscan.providers.stubs.reputation import ReputationProvider

EXPECTED = {"nvd", "rdap", "geoip", "hibp", "shodan", "reputation", "lookalike", "local_llm"}


def by_name(ctx, name):
    return next(cls for cls in STUB_PROVIDERS if cls.name == name)(ctx)


def test_every_stub_has_mock_data_doc_env_entry_and_status_header(ctx):
    assert {cls.name for cls in STUB_PROVIDERS} == EXPECTED
    env_example = (ROOT / ".env.example").read_text()
    for cls in STUB_PROVIDERS:
        assert cls.wip and cls.data_sent
        assert (ROOT / "data" / "mock" / f"{cls.name}.json").is_file(), cls.name
        assert (ROOT / "docs" / "providers" / f"{cls.name}.md").is_file(), cls.name
        source = (ROOT / "src" / "webscan" / "providers" / "stubs" / f"{cls.name}.py").read_text()
        assert "STATUS: 🚧 WIP" in source and "TODO" in source and "Data that would leave the org" in source
        for var in cls.env_vars:
            assert var in env_example, var
        provider = cls(ctx)
        assert not provider.is_enabled() and not provider.is_live()


@pytest.mark.parametrize(
    "name,target,knowledge_id",
    [
        ("rdap", "example.org", "domain-expiring"),
        ("hibp", "example.org", "breach-exposure"),
        ("shodan", "203.0.113.12", "open-ftp"),
        ("reputation", "archive.example.org", "site-flagged-malicious"),
        ("lookalike", "example.org", "lookalike-domain"),
    ],
)
def test_stubs_return_mock_findings_marked_as_mock(ctx, name, target, knowledge_id):
    findings = by_name(ctx, name).run(target)
    assert findings and all(f.data_source == "mock" and f.sources == [name] for f in findings)
    assert knowledge_id in {f.knowledge_id for f in findings}


def test_stub_details(ctx):
    rdap = by_name(ctx, "rdap").run("example.org")[0]
    assert "21 day" in rdap.vulnerability_name
    assert by_name(ctx, "rdap").run("www.example.org") == []  # apex domains only
    hibp = by_name(ctx, "hibp").run("example.org")[0]
    assert hibp.vulnerability_name.startswith("3 ") and "alias1" not in hibp.evidence  # no individual addresses
    shodan = by_name(ctx, "shodan").run("203.0.113.12")
    assert any(f.cve_id == "CVE-2021-41773" for f in shodan)
    assert by_name(ctx, "shodan").run("donate.example.org") == []  # IP targets only
    assert by_name(ctx, "reputation").run("donate.example.org") == []  # clean site
    geo = by_name(ctx, "geoip").run("203.0.113.10")[0]
    assert geo.base_severity == 0.0 and geo.remediation_key.startswith("info:")
    lookalike = by_name(ctx, "lookalike").run("example.org")[0]
    assert "examp1e" not in lookalike.evidence and lookalike.vulnerability_name.startswith("3 ")


def test_lookalike_names_only_with_no_redact(make_ctx):
    ctx = make_ctx(no_redact=True)
    assert "examp1e.org" in LookalikeProvider(ctx).run("example.org")[0].evidence


def test_variant_generation_is_local_and_deterministic():
    variants = generate_variants("example.org", limit=500)
    assert variants == generate_variants("example.org", limit=500)
    assert "example.org" not in variants and len(set(variants)) == len(variants)
    for expected in ("exmaple.org", "examp1e.org", "exampl.org", "example.com", "donate-example.org", "exa-mple.org"):
        assert expected in variants
    assert len(generate_variants("example.org", limit=10)) == 10


def test_external_stubs_never_touch_internal_targets(ctx):
    from webscan.scope.enforcer import ScopeError

    with pytest.raises(ScopeError):
        by_name(ctx, "shodan").run("10.0.0.5")


def test_live_calls_are_blocked_without_approval(make_ctx):
    ctx = make_ctx(demo=False, use_examples=True, live=True, env={"WEBSCAN_LIVE_MODE": "true"})
    for name in ("rdap", "shodan", "hibp", "reputation", "lookalike"):
        provider = by_name(ctx, name)
        assert not provider.is_live()  # not in approved_providers
        with pytest.raises(LiveModeError):
            provider.guarded_get("example.org", "https://example.invalid/")
    with pytest.raises(LiveModeError):
        ctx.guard.authorize_provider("nvd")


def test_approved_stub_failure_is_contained(make_ctx, monkeypatch):
    ctx = make_ctx(demo=False, use_examples=True, live=True, env={"WEBSCAN_LIVE_MODE": "true"})
    ctx.providers_cfg["approved_providers"] = ["rdap"]
    provider = RdapProvider(ctx)
    assert provider.is_live()

    def explode(self, target):
        raise ConnectionError("network unreachable")

    monkeypatch.setattr(RdapProvider, "_fetch_live", explode)
    assert provider.run("example.org") == []  # no crash
    assert any("rdap" in w for w in ctx.warnings)


def test_rdap_parse_handles_far_and_missing_dates(ctx):
    provider = RdapProvider(ctx)
    far = {"_mock_today": "2026-01-01T00:00:00Z", "events": [{"eventAction": "expiration", "eventDate": "2027-06-01T00:00:00Z"}]}
    assert provider._parse("example.org", far) == []
    assert provider._parse("example.org", {"events": []}) == []
    soon = {"_mock_today": "2026-01-01T00:00:00Z", "events": [{"eventAction": "expiration", "eventDate": "2026-01-05T00:00:00Z"}]}
    assert provider._parse("example.org", soon)[0].severity == 8.0


def test_reputation_ignores_a_single_vendor_flag(ctx):
    payload = {"virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}}}
    assert ReputationProvider(ctx)._parse("donate.example.org", payload) == []


def test_nvd_lookup_and_enrich_use_mock_and_send_no_targets(ctx):
    nvd = NvdProvider(ctx)
    assert nvd.lookup("cve-2020-11023")["cvss"] == 6.1
    assert nvd.lookup("CVE-1999-0001") is None and nvd.lookup("not a cve; rm") is None
    finding = Finding(vulnerability_name="jq", cve_id="CVE-2020-11023", base_severity=6.1, asset_name="donor-portal",
                      exposure_tier="public", asset_criticality=3, has_known_exploit=False)
    assert nvd.enrich([finding]) == 1
    assert "jQuery" in finding.description and finding.references
    assert nvd.run("donate.example.org") == []
    parsed = NvdProvider.parse_response(
        {"vulnerabilities": [{"cve": {"descriptions": [{"lang": "en", "value": "d"}], "metrics": {"cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "vectorString": "V"}}]}, "references": [{"url": "https://example.com/r"}]}}]}
    )
    assert parsed == {"description": "d", "cvss": 9.8, "vector": "V", "references": ["https://example.com/r"]}
    assert NvdProvider.parse_response({"vulnerabilities": []}) is None


def test_local_llm_is_mock_by_default_and_refuses_remote_hosts(ctx, make_ctx):
    finding = Finding(vulnerability_name="Odd thing", cve_id=None, base_severity=3.0, asset_name="donor-portal",
                      exposure_tier="public", asset_criticality=3, has_known_exploit=False)
    llm = LocalLlmProvider(ctx)
    assert "Mock" in llm.explain(finding, "en") and "simulada" in llm.explain(finding, "es")
    prompt = llm.build_prompt(finding, "es")
    assert "usted" in prompt and "Odd thing" in prompt
    assert llm.endpoint() == "http://localhost:11434"
    for url in ("https://api.openai.com/v1", "http://198.51.100.5:11434", "ftp://localhost", "http://localhost.evil.example.com"):
        remote = make_ctx(env={"LOCAL_LLM_URL": url})
        with pytest.raises(LocalLlmError):
            LocalLlmProvider(remote).endpoint()
    assert LocalLlmProvider(make_ctx(env={"LOCAL_LLM_URL": "http://127.0.0.1:1234/"})).endpoint() == "http://127.0.0.1:1234"


def test_mock_files_use_placeholder_data_only():
    for cls in STUB_PROVIDERS:
        text = (ROOT / "data" / "mock" / f"{cls.name}.json").read_text()
        data = json.loads(text)
        assert data["provider"] == cls.name and "MOCK" in data["_comment"]
