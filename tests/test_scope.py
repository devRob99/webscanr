import json

import pytest

from webscan.scope.enforcer import ScopeEnforcer, ScopeError, parse_target


@pytest.fixture
def scope(example_whitelist):
    return ScopeEnforcer(example_whitelist)


# ------------------------------------------------------------------ valid targets


@pytest.mark.parametrize(
    "target,kind",
    [
        ("donate.example.org", "domain"),
        ("DONATE.Example.ORG", "domain"),
        ("example.org.", "domain"),
        ("203.0.113.10", "ip"),
        ("203.0.113.0/27", "cidr"),
        ("203.0.113.8/29", "cidr"),
    ],
)
def test_valid_in_scope_targets(scope, target, kind):
    decision = scope.require(target, external=True)
    assert decision.in_scope and decision.external_ok
    assert decision.kind == kind


def test_ip_inside_allowed_cidr_is_in_scope(scope):
    assert scope.check("203.0.113.30").in_scope


# ------------------------------------------------------------------ out of scope


@pytest.mark.parametrize(
    "target",
    [
        "evil.example.com",
        "sub.donate.example.org",  # subdomains are not implied
        "example.com",
        "198.51.100.7",
        "203.0.113.40",  # just outside the /27
        "198.51.100.0/24",
        "2001:db8::1",
    ],
)
def test_out_of_scope_targets_are_rejected(scope, target):
    decision = scope.check(target)
    assert not decision.in_scope
    with pytest.raises(ScopeError):
        scope.require(target, external=False)


@pytest.mark.parametrize("target", ["203.0.113.0/24", "203.0.112.0/23", "0.0.0.0/0"])
def test_partially_overlapping_cidr_is_rejected(scope, target):
    decision = scope.check(target)
    assert not decision.in_scope
    assert "partially overlaps" in decision.reason


def test_cidr_with_host_bits_is_ambiguous_and_rejected(scope):
    assert not scope.check("203.0.113.5/27").in_scope


# ------------------------------------------------------------------ private / reserved


@pytest.mark.parametrize("target", ["10.0.0.5", "10.0.0.0/29", "files.target.local"])
def test_whitelisted_internal_targets_are_local_only(scope, target):
    decision = scope.check(target)
    assert decision.in_scope and not decision.external_ok
    assert scope.require(target, external=False).in_scope
    with pytest.raises(ScopeError, match="external provider"):
        scope.require(target, external=True)


@pytest.mark.parametrize(
    "address",
    [
        "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1", "127.0.0.1", "169.254.169.254",
        "224.0.0.1", "240.0.0.1", "255.255.255.255", "0.0.0.0", "100.64.0.1", "::1", "fe80::1",
        "fc00::1", "ff02::1", "::ffff:10.0.0.1",
    ],
)
def test_non_public_addresses_never_reach_external_even_if_whitelisted(address):
    scope = ScopeEnforcer({"ips": [address]})  # listed in the PUBLIC section on purpose
    decision = scope.check(address)
    assert decision.in_scope
    assert not decision.external_ok
    with pytest.raises(ScopeError):
        scope.require(address, external=True)


def test_cidr_spanning_private_space_is_blocked_externally():
    scope = ScopeEnforcer({"cidrs": ["192.168.0.0/16", "8.0.0.0/6"]})
    assert not scope.check("192.168.4.0/24").external_ok
    assert not scope.check("10.0.0.0/8").external_ok  # inside 8.0.0.0/6 but private


def test_internal_suffix_hostname_is_local_only_even_in_public_section():
    scope = ScopeEnforcer({"domains": ["intranet.example.internal", "printer.lan"]})
    for host in ("intranet.example.internal", "printer.lan"):
        assert scope.check(host).in_scope
        assert not scope.check(host).external_ok


# ------------------------------------------------------------------ injection / malformed input


@pytest.mark.parametrize(
    "target",
    [
        "example.org; rm -rf /",
        "example.org;id",
        "example.org|cat",
        "example.org&&whoami",
        "$(whoami).example.org",
        "`id`.example.org",
        "example.org\nexample.com",
        "example.org\x00",
        " example.org",
        "example.org ",
        "exa mple.org",
        "http://example.org",
        "https://donate.example.org/path",
        "user:pass@example.org",
        "admin@example.org",
        "example.org/../../etc/passwd",
        "example.org:443",
        "*.example.org",
        "example.*",
        "-oProxyCommand=evil.example.org",
        "--script=evil",
        "exämple.org",
        "example。org",
        "example..org",
        ".example.org",
        "-bad.example.org",
        "bad-.example.org",
        "under_score.example.org",
        "localhost",
        "example",
        "1.2.3",
        "127.1",
        "0x7f.0.0.1",
        "999.1.1.1",
        "203.0.113.10/33",
        "203.0.113.10/",
        "fe80::1%eth0",
        "a" * 64 + ".example.org",
        "a." * 130 + "org",
        "",
    ],
)
def test_malicious_or_malformed_input_is_rejected(scope, target):
    with pytest.raises(ScopeError):
        parse_target(target)
    decision = scope.check(target)
    assert not decision.in_scope and not decision.external_ok
    with pytest.raises(ScopeError):
        scope.require(target, external=False)


@pytest.mark.parametrize("target", [None, 123, ["example.org"], b"example.org"])
def test_non_string_targets_are_rejected(scope, target):
    assert not scope.check(target).in_scope
    with pytest.raises(ScopeError):
        scope.require(target, external=False)


# ------------------------------------------------------------------ fail-safe whitelist handling


def test_missing_whitelist_halts(tmp_path):
    with pytest.raises(ScopeError, match="missing"):
        ScopeEnforcer.from_file(tmp_path / "allowed_targets.json")


def test_unparseable_whitelist_halts(tmp_path):
    path = tmp_path / "allowed_targets.json"
    path.write_text("{not json")
    with pytest.raises(ScopeError, match="malformed"):
        ScopeEnforcer.from_file(path)


@pytest.mark.parametrize(
    "data",
    [
        [],
        "example.org",
        {},
        {"domains": [], "ips": [], "cidrs": []},
        {"domains": "example.org"},
        {"domains": [42]},
        {"domains": ["not a domain"]},
        {"domains": ["*.example.org"]},  # wildcard without opt-in
        {"ips": ["300.1.1.1"]},
        {"cidrs": ["203.0.113.5/24"]},
        {"cidrs": ["nonsense"]},
        {"domains": ["example.org"], "local_only": []},
        {"domains": ["example.org"], "allow_wildcard_entries": "yes"},
    ],
)
def test_malformed_or_empty_whitelist_halts(tmp_path, data):
    with pytest.raises(ScopeError):
        ScopeEnforcer(data)
    path = tmp_path / "allowed_targets.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ScopeError):
        ScopeEnforcer.from_file(path)


def test_wildcard_entries_work_only_when_explicitly_enabled():
    scope = ScopeEnforcer({"allow_wildcard_entries": True, "domains": ["*.example.org"]})
    assert scope.check("donate.example.org").in_scope
    assert scope.check("a.b.example.org").in_scope
    assert not scope.check("example.org").in_scope  # the apex is not a subdomain
    assert not scope.check("badexample.org").in_scope
    assert not scope.check("example.org.evil.example.com").in_scope
    # Even then, a target itself may never contain a wildcard.
    assert not scope.check("*.example.org").in_scope


def test_build_context_halts_and_audits_when_whitelist_missing(tmp_path):
    from webscan.context import build_context

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    with pytest.raises(ScopeError):
        build_context("test", config_dir=config_dir, output_dir=tmp_path / "o", log_dir=tmp_path / "l", env={})
    records = [json.loads(line) for line in (tmp_path / "l" / "audit.jsonl").read_text().splitlines()]
    assert records[-1]["event"] == "scope_halt"
    assert records[-1]["status"] == "halted"
