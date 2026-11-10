"""Scoring math, exploitability override, sort order, batching, grade, and enrichment."""

import copy
import gzip

import pytest

from webscan.batching.engine import build_batches
from webscan.config import DEFAULT_SCORING
from webscan.enrichment.reference import (
    ReferenceData,
    ReferenceDataError,
    enrich,
    load_reference,
    parse_epss,
    parse_kev,
    refresh,
)
from webscan.models import Finding
from webscan.scoring.engine import band_for, max_raw_score, score_all, score_finding
from webscan.summary import build_summary, compute_grade, pick_fix_first

CFG = DEFAULT_SCORING


def finding(name="Test", cvss=5.0, tier="public", crit=2, **kw):
    return Finding(
        vulnerability_name=name, cve_id=kw.pop("cve", None), base_severity=cvss, asset_name=kw.pop("asset", "asset-a"),
        exposure_tier=tier, asset_criticality=crit, has_known_exploit=kw.pop("exploit", False), **kw,
    )


# ------------------------------------------------------------------ formula


def test_default_multipliers_match_the_spec():
    assert CFG["exposure_multipliers"] == {"public": 1.5, "staging": 1.0, "internal": 0.8}
    assert CFG["criticality_weights"] == {"1": 1.0, "2": 1.5, "3": 2.0}
    assert CFG["exploit_factors"] == {"known_exploit": 1.5, "epss_high": 1.3, "none": 1.0}
    assert CFG["epss_threshold"] == 0.10
    assert max_raw_score(CFG) == 45.0


@pytest.mark.parametrize("tier,multiplier", [("public", 1.5), ("staging", 1.0), ("internal", 0.8)])
def test_exposure_multiplier(tier, multiplier):
    f = score_finding(finding(cvss=5.0, tier=tier, crit=1), CFG)
    assert f.score_breakdown["exposure_multiplier"] == multiplier
    assert f.score_breakdown["raw_score"] == pytest.approx(5.0 * multiplier)


@pytest.mark.parametrize("crit,weight", [(1, 1.0), (2, 1.5), (3, 2.0)])
def test_criticality_weight(crit, weight):
    f = score_finding(finding(cvss=4.0, tier="staging", crit=crit), CFG)
    assert f.score_breakdown["criticality_weight"] == weight
    assert f.score_breakdown["raw_score"] == pytest.approx(4.0 * weight)


@pytest.mark.parametrize(
    "kwargs,factor,reason",
    [
        ({"in_cisa_kev": True}, 1.5, "cisa_kev"),
        ({"exploit": True}, 1.5, "known_exploit"),
        ({"epss_score": 0.10}, 1.3, "epss_high"),
        ({"epss_score": 0.5}, 1.3, "epss_high"),
        ({"epss_score": 0.0999}, 1.0, "none"),
        ({}, 1.0, "none"),
        ({"in_cisa_kev": True, "epss_score": 0.9}, 1.5, "cisa_kev"),  # factors do not stack
    ],
)
def test_exploit_factor(kwargs, factor, reason):
    f = score_finding(finding(cvss=10.0, tier="staging", crit=1, **kwargs), CFG)
    assert f.score_breakdown["exploit_factor"] == factor
    assert f.score_breakdown["exploit_reason"] == reason


def test_normalization_to_0_100():
    worst = score_finding(finding(cvss=10.0, tier="public", crit=3, in_cisa_kev=True), CFG)
    assert worst.risk_score == 100.0 and worst.priority == "Critical"
    none = score_finding(finding(cvss=0.0), CFG)
    assert none.risk_score == 0.0 and none.priority == "Info"
    mid = score_finding(finding(cvss=6.1, tier="public", crit=3, in_cisa_kev=True), CFG)
    assert mid.risk_score == pytest.approx(61.0)  # 6.1 x 1.5 x 2 x 1.5 = 27.45 -> / 45
    assert "27.45" in mid.score_breakdown["formula"] and "61.0" in mid.score_breakdown["formula"]


@pytest.mark.parametrize(
    "score,band", [(100, "Critical"), (60, "Critical"), (59.9, "High"), (40, "High"), (39.9, "Medium"),
                   (20, "Medium"), (19.9, "Low"), (5, "Low"), (4.9, "Info"), (0, "Info")],
)
def test_bands(score, band):
    assert band_for(score, CFG) == band


def test_thresholds_and_multipliers_come_from_config():
    cfg = copy.deepcopy(CFG)
    cfg["exposure_multipliers"]["public"] = 3.0
    cfg["bands"].update({"Critical": 90, "High": 10})
    f = score_finding(finding(cvss=5.0, tier="public", crit=1), cfg)
    assert f.score_breakdown["exposure_multiplier"] == 3.0
    assert f.risk_score == pytest.approx(5 * 3 / (10 * 3 * 2 * 1.5) * 100, abs=0.05)
    assert f.priority == "High"


# ------------------------------------------------------------------ override and ordering


def test_known_exploited_findings_are_never_below_high():
    low_cvss_kev = score_finding(finding(cvss=2.0, tier="internal", crit=1, in_cisa_kev=True), CFG)
    assert low_cvss_kev.priority == "High" and low_cvss_kev.risk_score == 40.0
    assert low_cvss_kev.score_breakdown["override_applied"] is True
    assert low_cvss_kev.score_breakdown["normalized_before_override"] < 40
    exploit = score_finding(finding(cvss=3.0, tier="staging", crit=1, exploit=True), CFG)
    assert exploit.priority == "High"
    not_exploited = score_finding(finding(cvss=2.0, tier="internal", crit=1, epss_score=0.9), CFG)
    assert not_exploited.priority in ("Low", "Info") and not not_exploited.score_breakdown["override_applied"]
    already_critical = score_finding(finding(cvss=9.8, tier="public", crit=3, in_cisa_kev=True), CFG)
    assert already_critical.priority == "Critical" and not already_critical.score_breakdown["override_applied"]


def test_spec_scenario_medium_cvss_kev_on_donor_portal_outranks_high_cvss_on_staging():
    staging = finding("RCE on staging", cvss=9.8, tier="staging", crit=1, asset="staging-site")
    donor = finding("jQuery XSS", cvss=6.1, tier="public", crit=3, asset="donor-portal", cve="CVE-2020-11023")
    enrich([staging, donor], ReferenceData(kev={"CVE-2020-11023"}, epss={"CVE-2020-11023": 0.25}))
    ranked = score_all([staging, donor], CFG)
    assert [f.asset_name for f in ranked] == ["donor-portal", "staging-site"]
    assert ranked[0].priority == "Critical" and ranked[1].priority in ("Medium", "Low")
    assert ranked[0].base_severity < ranked[1].base_severity


def test_sort_order_risk_then_epss_then_cvss():
    a = finding("a", cvss=5.0, tier="public", crit=2)  # 11.25 -> 25.0
    b = finding("b", cvss=7.5, tier="staging", crit=2)  # 11.25 -> 25.0, higher CVSS
    c = finding("c", cvss=7.5, tier="staging", crit=2, epss_score=0.05)  # same score, has EPSS
    d = finding("d", cvss=9.0, tier="public", crit=3)  # 60
    ranked = score_all([a, b, c, d], CFG)
    assert [f.vulnerability_name for f in ranked] == ["d", "c", "b", "a"]
    assert ranked[1].risk_score == ranked[2].risk_score == ranked[3].risk_score


# ------------------------------------------------------------------ enrichment


def test_enrich_sets_kev_exploit_and_epss():
    f1, f2, f3 = finding(cve="CVE-2020-11023"), finding(cve="CVE-2019-11358"), finding()
    enrich([f1, f2, f3], ReferenceData(kev={"CVE-2020-11023"}, epss={"CVE-2020-11023": 0.25, "CVE-2019-11358": 0.02}))
    assert f1.in_cisa_kev and f1.has_known_exploit and f1.epss_score == 0.25
    assert not f2.in_cisa_kev and not f2.has_known_exploit and f2.epss_score == 0.02
    assert f3.epss_score is None and not f3.in_cisa_kev


def test_bundled_snapshots_load_offline(tmp_path):
    from tests.conftest import ROOT

    ref = load_reference(ROOT / "data" / "reference", bundled_only=True)
    assert "CVE-2020-11023" in ref.kev and "CVE-2023-38408" not in ref.kev
    assert ref.epss["CVE-2020-25213"] > 0.5 and ref.kev_source == "kev_snapshot.json"
    empty = load_reference(tmp_path)
    assert empty.kev == set() and empty.epss == {}


def test_parsers_reject_bad_reference_files():
    with pytest.raises(ReferenceDataError):
        parse_kev('{"vulnerabilities": []}')
    with pytest.raises(ReferenceDataError):
        parse_kev('{"nope": 1}')
    with pytest.raises(ReferenceDataError):
        parse_epss("#comment\ncve,epss\nnot-a-cve,2\n")
    assert parse_epss("#c\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\nCVE-2024-0002,bad,0\n") == {"CVE-2024-0001": 0.5}


def test_refresh_downloads_only_the_two_public_files_and_prefers_them(tmp_path):
    requested: list[str] = []
    kev = b'{"vulnerabilities": [{"cveID": "CVE-2024-0001"}, {"cveID": "CVE-2024-0002"}]}'
    epss = gzip.compress(b"#model\ncve,epss,percentile\nCVE-2024-0001,0.77,0.99\n")

    def fake_download(url: str) -> bytes:
        requested.append(url)
        return kev if "cisa.gov" in url else epss

    counts = refresh(tmp_path, fake_download)
    assert counts == {"kev": 2, "epss": 1}
    assert len(requested) == 2 and all(u.startswith("https://") and "?" not in u for u in requested)
    ref = load_reference(tmp_path)
    assert ref.kev == {"CVE-2024-0001", "CVE-2024-0002"} and ref.epss == {"CVE-2024-0001": 0.77}
    assert ref.kev_source == "kev_full.json"


def test_refresh_keeps_old_files_when_download_is_bad(tmp_path):
    (tmp_path / "kev_full.json").write_text('{"vulnerabilities": [{"cveID": "CVE-2024-0009"}]}')
    with pytest.raises(ReferenceDataError):
        refresh(tmp_path, lambda url: b'{"vulnerabilities": []}')
    assert load_reference(tmp_path).kev == {"CVE-2024-0009"}


# ------------------------------------------------------------------ batching


def scored(items):
    return score_all(items, CFG)


def test_findings_sharing_a_fix_collapse_into_one_batch():
    items = scored(
        [
            finding("jq1", 6.1, crit=3, asset="donor-portal", cve="CVE-2020-11023", remediation_key="upgrade:jquery>=3.5.0"),
            finding("jq2", 6.1, crit=3, asset="donor-portal", cve="CVE-2020-11022", remediation_key="upgrade:jquery>=3.5.0"),
            finding("jq3", 6.1, crit=1, asset="archive", cve="CVE-2020-11023", remediation_key="upgrade:jquery>=3.5.0"),
            finding("sqli", 8.6, crit=3, asset="donor-portal", remediation_key="code:fix-sql-injection"),
        ]
    )
    batches = build_batches(items)
    assert len(batches) == 2
    jquery = batches[0]
    assert jquery.key == "upgrade:jquery>=3.5.0" and jquery.finding_count == 3
    assert jquery.assets == ["archive", "donor-portal"]
    assert jquery.cves == ["CVE-2020-11022", "CVE-2020-11023"]
    assert jquery.total_risk == pytest.approx(sum(f.risk_score for f in items if "jq" in f.vulnerability_name), abs=0.1)
    assert jquery.max_risk_score == max(f.risk_score for f in items if "jq" in f.vulnerability_name)
    assert jquery.effort == "moderate" and "jQuery" in jquery.title
    assert batches[1].effort == "involved"


def test_identical_findings_across_assets_batch_even_without_a_key():
    items = scored([finding("Weird Thing!", 5.0, asset="a"), finding("weird thing", 5.0, asset="b"),
                    finding("Other", 5.0, asset="a")])
    batches = build_batches(items)
    assert sorted(b.finding_count for b in batches) == [1, 2]
    two = next(b for b in batches if b.finding_count == 2)
    assert two.key == "fix:weird-thing" and two.assets == ["a", "b"] and two.effort == "moderate"


def test_batches_are_ranked_by_total_risk_removed_and_skip_info_notes():
    items = scored(
        [finding("big", 9.8, crit=3, remediation_key="k:big")]
        + [finding(f"small{i}", 4.0, crit=3, asset=f"a{i}", remediation_key="k:many") for i in range(6)]
        + [finding("note", 0.0, remediation_key="info:shared-hosting")]
    )
    batches = build_batches(items)
    assert [b.key for b in batches] == ["k:many", "k:big"]
    assert batches[0].total_risk > batches[1].total_risk
    assert batches[1].top_priority == "Critical"
    assert pick_fix_first(batches)[0].key == "k:big"  # urgent batches lead the "fix first" list


def test_batch_titles_are_translated():
    items = scored([finding("x", 6.1, remediation_key="upgrade:jquery>=3.5.0")])
    assert build_batches(items, "es")[0].title.startswith("Actualizar jQuery")


# ------------------------------------------------------------------ grade and summary


def with_priorities(*priorities):
    out = []
    for i, p in enumerate(priorities):
        f = finding(f"f{i}", asset=f"a{i % 3}")
        f.priority = p
        f.risk_score = {"Critical": 80, "High": 50, "Medium": 30, "Low": 10, "Info": 0}[p]
        out.append(f)
    return out


def test_grade_thresholds():
    assert compute_grade([], CFG) == ("A", 100.0, False)
    assert compute_grade(with_priorities("High", "Medium", "Low"), CFG)[0] == "A"  # 100 - 6.75
    assert compute_grade(with_priorities(*["High"] * 3), CFG)[0] == "B"  # 85
    assert compute_grade(with_priorities(*["High"] * 5), CFG)[0] == "C"  # 75
    assert compute_grade(with_priorities(*["High"] * 7), CFG)[0] == "D"  # 65
    assert compute_grade(with_priorities(*["High"] * 9), CFG)[0] == "F"  # 55
    assert compute_grade(with_priorities(*["Info"] * 50), CFG)[0] == "A"


def test_any_critical_caps_the_grade_at_d():
    letter, score, capped = compute_grade(with_priorities("Critical"), CFG)
    assert (letter, score, capped) == ("D", 85.0, True)
    letter, _, capped = compute_grade(with_priorities(*["Critical"] * 5), CFG)
    assert letter == "F" and not capped


def test_summary_counts_fix_first_and_paragraph_in_both_languages():
    items = scored(
        [
            finding("jq", 6.1, crit=3, asset="donor-portal", cve="CVE-2020-11023", in_cisa_kev=True,
                    remediation_key="upgrade:jquery>=3.5.0"),
            finding("sqli", 8.6, crit=3, asset="donor-portal", remediation_key="code:fix-sql-injection"),
            finding("hdr", 2.0, crit=1, asset="archive", remediation_key="config:add-csp-header"),
        ]
    )
    batches = build_batches(items)
    en = build_summary(items, batches, CFG, "en", "Example Org")
    assert en.total_findings == 3 and en.assets_affected == 2 and en.kev_count == 1
    assert en.counts["Critical"] == 1 and en.grade == "D" and len(en.top_batches) == 3
    assert "Example Org has 3 open security findings" in en.paragraph and "100%" in en.paragraph
    es = build_summary(items, build_batches(items, "es"), CFG, "es", "Example Org")
    assert "hallazgos de seguridad" in es.paragraph and es.grade == en.grade
    empty = build_summary([], [], CFG, "es")
    assert empty.grade == "A" and "no tiene hallazgos" in empty.paragraph
