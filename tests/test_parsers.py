"""HackerTarget and Quantro parsers, normalization, dedup, and the knowledge base."""

import copy
import json
from pathlib import Path

import pytest

from webscan.config import DEFAULT_PROVIDERS
from webscan.ingest.normalize import build_finding, build_findings, dedupe
from webscan.knowledge import base as kb
from webscan.models import Issue
from webscan.providers.hackertarget import parser
from webscan.providers.quantro.parser import QuantroFormatError, dig, load_report, parse_report

ROOT = Path(__file__).resolve().parents[1]
MOCK = ROOT / "data" / "mock"
HT = MOCK / "hackertarget"
MAPPING = DEFAULT_PROVIDERS["quantro"]["field_mapping"]


def mock(endpoint: str, target: str) -> str:
    return (HT / endpoint / f"{target}.txt").read_text()


def ids(issues: list[Issue]) -> list[str]:
    return [i.cve_id or i.knowledge_id or i.name for i in issues]


# ------------------------------------------------------------------ nmap


def test_nmap_reports_risky_open_services_only():
    issues = parser.parse_nmap(mock("nmap", "donate.example.org"))
    assert ids(issues) == ["open-database-port"]
    assert "3306/tcp" in issues[0].evidence
    assert parser.parse_nmap(mock("nmap", "www.example.org")) == []


def test_nmap_detects_vulnerable_versions():
    archive = ids(parser.parse_nmap(mock("nmap", "archive.example.org")))
    assert archive == ["open-ftp", "CVE-2021-41773"]
    staging = ids(parser.parse_nmap(mock("nmap", "staging.example.org")))
    assert staging == ["CVE-2023-38408", "open-telnet"]


def test_nmap_ignores_closed_filtered_and_garbage_lines():
    text = "PORT STATE SERVICE\n23/tcp closed telnet\n21/tcp filtered ftp\nnot a port line\n99999/tcp open telnet\n\x00\n"
    warnings: list[str] = []
    assert parser.parse_nmap(text, warnings.append) == []
    assert len(warnings) == 1  # the impossible port number
    assert parser.parse_nmap("") == []


@pytest.mark.parametrize(
    "banner,expected",
    [
        ("OpenSSH 8.9p1 Ubuntu", ["CVE-2023-38408"]),
        ("OpenSSH 9.3p1", ["CVE-2023-38408"]),
        ("OpenSSH 9.3p2", []),
        ("OpenSSH 9.6p1 Ubuntu", []),
        ("Apache httpd 2.4.49 ((Unix))", ["CVE-2021-41773"]),
        ("Apache/2.4.50 (Unix)", ["CVE-2021-42013"]),
        ("Apache/2.4.62", []),
        ("vsftpd 2.3.4", ["CVE-2011-2523"]),
        ("vsftpd 3.0.3", []),
        ("PHP/7.4.33", ["outdated-php"]),
        ("PHP/8.3.1", []),
        ("nginx", []),
    ],
)
def test_banner_version_rules(banner, expected):
    assert ids(parser.banner_issues(banner)) == expected


# ------------------------------------------------------------------ headers / dns / hosts


def test_httpheaders_uses_final_response_and_detects_https():
    issues = ids(parser.parse_httpheaders(mock("httpheaders", "donate.example.org")))
    assert "missing-hsts" in issues and "missing-csp" in issues and "missing-x-frame-options" in issues
    assert "missing-x-content-type-options" not in issues  # header is present
    assert "server-version-disclosure" in issues and "outdated-php" in issues
    wix = ids(parser.parse_httpheaders(mock("httpheaders", "www.example.org")))
    assert "missing-hsts" not in wix and "server-version-disclosure" not in wix


def test_httpheaders_skips_hsts_on_plain_http_and_flags_vulnerable_server():
    issues = ids(parser.parse_httpheaders(mock("httpheaders", "archive.example.org")))
    assert "missing-hsts" not in issues
    assert "CVE-2021-41773" in issues
    staging = ids(parser.parse_httpheaders(mock("httpheaders", "staging.example.org")))
    assert "missing-x-frame-options" not in staging


def test_httpheaders_handles_empty_output():
    warnings: list[str] = []
    assert parser.parse_httpheaders("garbage without headers", warnings.append) == []
    assert warnings


def test_dnslookup_spf_rules():
    assert parser.parse_dnslookup(mock("dnslookup", "example.org")) == []
    no_spf = parser.parse_dnslookup('A : 203.0.113.11\nMX : 10 mail.example.org.\nTXT : "other=1"\n')
    assert ids(no_spf) == ["missing-spf"]
    open_spf = parser.parse_dnslookup('MX : 10 mail.example.org.\nTXT : "v=spf1 +all"\n')
    assert ids(open_spf) == ["missing-spf"] and "+all" in open_spf[0].evidence
    assert parser.parse_dnslookup("A : 203.0.113.11\n") == []  # no mail, no SPF needed


def test_hostsearch_flags_hosts_missing_from_inventory():
    known = {"example.org", "www.example.org", "donate.example.org", "archive.example.org", "staging.example.org"}
    issues = parser.parse_hostsearch(mock("hostsearch", "example.org"), known)
    assert len(issues) == 1 and issues[0].knowledge_id == "unknown-public-host"
    assert "events.example.org" in issues[0].evidence and "old-intranet.example.org" in issues[0].evidence
    assert issues[0].name.startswith("2 ")
    everything = known | {"events.example.org", "old-intranet.example.org"}
    assert parser.parse_hostsearch(mock("hostsearch", "example.org"), everything) == []


def test_reverseip_reports_count_without_naming_neighbours():
    issues = parser.parse_reverseip(mock("reverseiplookup", "203.0.113.12"))
    assert len(issues) == 1 and issues[0].knowledge_id == "shared-hosting"
    assert "example.com" not in issues[0].evidence and "5 other" in issues[0].name
    assert parser.parse_reverseip("archive.example.org\n") == []


def test_subnetcalc_returns_facts_not_findings():
    facts = parser.parse_subnetcalc(mock("subnetcalc", "203.0.113.0_27"))
    assert facts["netmask"] == "255.255.255.224"


# ------------------------------------------------------------------ WIP endpoints


def test_nikto_maps_known_lines_and_keeps_unknown_ones():
    issues = parser.parse_nikto(mock("nikto", "archive.example.org"))
    found = ids(issues)
    for expected in ("missing-x-frame-options", "missing-x-content-type-options", "outdated-apache",
                     "directory-listing", "exposed-backup", "admin-interface-exposed", "outdated-jquery"):
        assert expected in found
    fallback = [i for i in issues if i.knowledge_id is None]
    assert len(fallback) == 1 and "README" in fallback[0].name and fallback[0].severity == 3.0
    assert not any("Target IP" in i.evidence or "Start Time" in i.evidence for i in issues)


def test_openvas_parses_rows_and_skips_malformed_ones():
    warnings: list[str] = []
    issues = parser.parse_openvas(mock("openvas", "staging.example.org"), warnings.append)
    assert [i.cve_id for i in issues] == ["CVE-2023-38408", "CVE-2020-11022", "CVE-2020-11023", None]
    assert issues[0].severity == 9.8 and issues[3].name.startswith("Telnet")
    assert len(warnings) == 1 and "row 5" in warnings[0]


def test_openvas_survives_garbage():
    assert parser.parse_openvas("") == []
    assert parser.parse_openvas("totally,unrelated\n1,2\n", lambda _m: None) == []


# ------------------------------------------------------------------ Quantro


def test_quantro_mock_report_parses_with_default_mapping():
    warnings: list[str] = []
    issues = parse_report(load_report(MOCK / "quantro_report.json"), MAPPING, warnings.append)
    assert len(issues) == 13
    assert len(warnings) == 2 and "#14" in warnings[0] and "#15" in warnings[1]
    first = issues[0]
    assert first.cve_id == "CVE-2020-25213" and first.severity == 9.8 and first.has_known_exploit
    assert first.host == "donate.example.org"
    hsts = next(i for i in issues if "HSTS" in i.name)
    assert hsts.severity == 5.5  # "N/A" score fell back to the Medium label


def test_quantro_mapping_is_configurable_without_code_changes():
    report = {
        "scan": {
            "results": [
                {
                    "name": "Outdated thing", "ids": {"cve": ["CVE-2021-41773"]}, "score": {"base": "7.5"},
                    "target": {"hostname": "Archive.Example.org"}, "exploited": "yes", "links": "https://example.com/a",
                },
                {"name": "Label only", "risk": "LOW", "target": {"hostname": "archive.example.org"}},
                {"name": "No score at all", "target": {"hostname": "archive.example.org"}},
            ]
        }
    }
    mapping = {
        "findings_path": "scan.results",
        "fields": {
            "vulnerability_name": "name", "cve_id": "ids.cve", "base_severity": "score.base", "severity_label": "risk",
            "host": "target.hostname", "has_known_exploit": "exploited", "references": "links",
        },
        "severity_label_scores": {"low": 2.5},
    }
    warnings: list[str] = []
    issues = parse_report(report, mapping, warnings.append)
    assert len(issues) == 2 and len(warnings) == 1
    assert issues[0].cve_id == "CVE-2021-41773" and issues[0].severity == 7.5 and issues[0].has_known_exploit
    assert issues[0].host == "archive.example.org" and issues[0].references == ["https://example.com/a"]
    assert issues[1].severity == 2.5


def test_quantro_unusable_reports_raise_a_clear_error(tmp_path):
    with pytest.raises(QuantroFormatError, match="findings_path"):
        parse_report({"other": []}, MAPPING)
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    with pytest.raises(QuantroFormatError):
        load_report(bad)
    with pytest.raises(QuantroFormatError):
        load_report(tmp_path / "missing.json")


def test_dig_follows_dotted_paths():
    data = {"a": {"b": [{"c": 5}]}}
    assert dig(data, "a.b.0.c") == 5
    assert dig(data, "a.x.c") is None and dig(data, "a.b.3") is None and dig(data, None) is None


# ------------------------------------------------------------------ normalization and dedup


def test_build_finding_attaches_asset_context_and_knowledge(ctx):
    finding = build_finding(
        ctx, "donate.example.org",
        Issue(name="jQuery old", cve_id="cve-2020-11023", severity=6.1, evidence="seen at https://donate.example.org/x"),
        "quantro", "mock",
    )
    assert finding.asset_name == "donor-portal" and finding.exposure_tier == "public"
    assert finding.asset_criticality == 3 and finding.platform == "wordpress"
    assert finding.knowledge_id == "outdated-jquery" and finding.remediation_key == "upgrade:jquery>=3.5.0"
    assert finding.cis_ig1 and finding.nist_csf
    assert "example.org" not in finding.evidence and "donor-portal" in finding.evidence
    assert finding.sources == ["quantro"] and finding.data_source == "mock"


def test_build_finding_flags_unknown_assets_and_skips_invalid_records(ctx):
    unknown = build_finding(ctx, "events.example.org", Issue(name="Directory listing enabled", severity=5.3), "x", "mock")
    assert not unknown.asset_known and unknown.asset_criticality == 2 and unknown.exposure_tier == "public"
    assert any("not in assets_metadata" in w for w in ctx.warnings)
    assert build_finding(ctx, "donate.example.org", Issue(name="Bad", severity=42), "x", "mock") is None
    assert build_finding(ctx, "donate.example.org", Issue(name="Bad", cve_id="CVE-oops", severity=1), "x", "mock") is None
    assert build_finding(ctx, "", Issue(name="No host", severity=1), "x", "mock") is None
    assert sum("Skipped a malformed record" in w for w in ctx.warnings) == 3


def test_default_severity_comes_from_the_catalog(ctx):
    finding = build_finding(ctx, "donate.example.org", Issue(name="x", knowledge_id="missing-hsts"), "local", "mock")
    assert finding.base_severity == kb.get_entry("missing-hsts").default_severity


def test_dedupe_merges_sources_and_keeps_the_higher_severity(ctx):
    host = "donate.example.org"
    a = build_findings(ctx, host, [Issue(name="HSTS missing", knowledge_id="missing-hsts", evidence="a")], "local", "mock")
    b = build_findings(ctx, host, [Issue(name="Missing HSTS header", severity=5.5, evidence="b")], "quantro", "mock")
    c = build_findings(ctx, "www.example.org", [Issue(name="x", knowledge_id="missing-hsts")], "local", "mock")
    merged = dedupe([*a, *b, *c])
    assert len(merged) == 2
    donor = next(f for f in merged if f.asset_name == "donor-portal")
    assert donor.sources == ["local", "quantro"] and donor.base_severity == 5.5
    assert "a" in donor.evidence and "b" in donor.evidence


# ------------------------------------------------------------------ knowledge base


def test_keyword_matching_uses_whole_words():
    assert kb.match("WordPress admin page") is None  # "rdp" inside "wordpress" must not match
    assert kb.match("Remote Desktop (RDP) open").id == "open-rdp"
    assert kb.match("SFTP is enabled") is None or kb.match("SFTP is enabled").id != "open-ftp"
    assert kb.match("Default administrator credentials accepted").id == "default-credentials"
    assert kb.match("something nobody has seen before") is None
    assert kb.match("x", cve_id="cve-2017-0144").id == "smbv1-enabled"
    assert kb.match("x", knowledge_id="missing-dmarc").id == "missing-dmarc"


def test_every_catalog_entry_has_complete_english_and_spanish_text():
    catalog = kb.catalog()
    assert len(catalog) >= 40
    for lang in kb.LANGS:
        data = kb._load(lang)
        assert set(data["entries"]) == set(catalog), f"{lang}: entries do not match the catalog"
        for entry_id, text in data["entries"].items():
            assert text["title"] and text["what"] and text["why"] and text["fix"], f"{lang}:{entry_id}"
        for entry in catalog.values():
            assert entry.remediation_key in data["batch_titles"] or entry.remediation_key.startswith("info:")
            assert entry.effort in kb.EFFORTS
    assert set(kb._load("en")["ui"]) == set(kb._load("es")["ui"])
    assert set(kb._load("en")["batch_titles"]) == set(kb._load("es")["batch_titles"])
    assert kb._load("en")["platform_guidance"].keys() == kb._load("es")["platform_guidance"].keys()


def test_spanish_text_is_not_a_copy_of_english():
    en, es = kb._load("en"), kb._load("es")
    for entry_id in en["entries"]:
        assert en["entries"][entry_id]["what"] != es["entries"][entry_id]["what"]
    assert "usted" in json.dumps(es, ensure_ascii=False).lower()


def test_framework_ids_all_have_titles_in_both_languages():
    for lang in kb.LANGS:
        names = kb.frameworks(lang)
        for entry in kb.catalog().values():
            assert set(entry.cis_ig1) <= set(names["cis_ig1"]), entry.id
            assert set(entry.nist_csf) <= set(names["nist_csf"]), entry.id


def test_platform_aware_fix_instructions():
    wix = kb.explain("missing-hsts", "en", "wix")
    assert wix.platform_controlled and "Wix" in wix.platform_note and len(wix.fix) == 1
    wordpress = kb.explain("missing-hsts", "en", "wordpress")
    assert not wordpress.platform_controlled and "plugin" in wordpress.fix[0] and len(wordpress.fix) == 2
    custom_es = kb.explain("missing-hsts", "es", "custom")
    assert "servidor" in custom_es.fix[0]
    override = kb.explain("outdated-jquery", "en", "wordpress")
    assert "Dashboard > Updates" in override.fix[0]
    plain = kb.explain("sql-injection", "es", "wordpress")
    assert plain.platform_note is None and plain.title.startswith("Un formulario")


def test_unknown_findings_fall_back_to_scanner_description():
    out = kb.explain(None, "es", fallback_title="Weird thing", fallback_description="Scanner said so")
    assert out.title == "Weird thing" and out.what == "Scanner said so" and not out.from_knowledge_base
    assert out.fix


def test_mapping_default_is_not_mutated_by_parsing():
    before = copy.deepcopy(MAPPING)
    parse_report(load_report(MOCK / "quantro_report.json"), MAPPING)
    assert before == MAPPING
