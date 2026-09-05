"""Tests for the parser and the check engine.

Run with:  python -m pytest -q
"""

from pathlib import Path

import pytest

from netcompliance.engine import Benchmark, Check, Engine, Severity, Status
from netcompliance.parser import IOSConfig
from netcompliance.report import score

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
CHECKS = Path(__file__).resolve().parent.parent / "checks"

SNIPPET = """
hostname TEST-RTR
!
no aaa new-model
!
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no ip proxy-arp
!
interface GigabitEthernet0/1
 ip address 192.168.2.1 255.255.255.0
!
line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
line vty 5 15
 transport input telnet
!
"""


# -- parser -----------------------------------------------------------------


def test_parser_builds_hierarchy():
    config = IOSConfig(SNIPPET)
    interfaces = config.blocks(r"^interface ")
    assert len(interfaces) == 2
    assert interfaces[0].text == "interface GigabitEthernet0/0"
    assert len(interfaces[0].children) == 2


def test_parser_ignores_comments_and_blanks():
    config = IOSConfig("!\n\nhostname X\n! a comment\n")
    assert [line.text for line in config.lines] == ["hostname X"]


def test_parser_extracts_hostname():
    assert IOSConfig(SNIPPET).hostname == "TEST-RTR"


def test_nested_line_is_not_a_global_line():
    """An ip address inside an interface must not match a global search."""
    config = IOSConfig(SNIPPET)
    assert config.find_global(r"^ip address") == []
    assert len(config.find(r"^ip address")) == 2


def test_path_shows_position():
    config = IOSConfig(SNIPPET)
    line = config.find(r"^no ip proxy-arp")[0]
    assert line.path == "interface GigabitEthernet0/0 > no ip proxy-arp"


# -- engine -----------------------------------------------------------------


def _check(match_type, pattern, block_pattern=""):
    return Check(
        id="T-1",
        title="test",
        severity=Severity.MEDIUM,
        match_type=match_type,
        pattern=pattern,
        block_pattern=block_pattern,
    )


def test_global_present_fails_when_missing():
    engine = Engine(IOSConfig(SNIPPET))
    result = engine._run_one(_check("global_present", r"^aaa new-model$"))
    assert result.status is Status.FAIL


def test_global_absent_passes_when_missing():
    engine = Engine(IOSConfig(SNIPPET))
    result = engine._run_one(_check("global_absent", r"^enable password"))
    assert result.status is Status.PASS


def test_block_present_fails_if_one_block_misses_it():
    """Gi0/0 has no ip proxy-arp, Gi0/1 does not. One offender is enough to fail."""
    engine = Engine(IOSConfig(SNIPPET))
    result = engine._run_one(
        _check("block_present", r"^no ip proxy-arp$", r"^interface Gigabit")
    )
    assert result.status is Status.FAIL
    assert "GigabitEthernet0/1" in result.evidence


def test_block_present_is_not_applicable_when_no_block_matches():
    """A router-only control must not mark a switch non-compliant."""
    engine = Engine(IOSConfig(SNIPPET))
    result = engine._run_one(_check("block_present", r"^anything$", r"^router bgp"))
    assert result.status is Status.NOT_APPLICABLE


def test_vty_telnet_is_caught():
    engine = Engine(IOSConfig(SNIPPET))
    result = engine._run_one(
        _check("block_present", r"^transport input ssh$", r"^line vty")
    )
    assert result.status is Status.FAIL
    assert "line vty 5 15" in result.evidence


def test_unknown_match_type_is_an_error_not_a_pass():
    engine = Engine(IOSConfig(SNIPPET))
    result = engine._run_one(_check("does_not_exist", r"^x$"))
    assert result.status is Status.ERROR


def test_invalid_regex_is_an_error_not_a_pass():
    engine = Engine(IOSConfig(SNIPPET))
    result = engine._run_one(_check("global_present", r"^([unclosed"))
    assert result.status is Status.ERROR


# -- scoring ----------------------------------------------------------------


def test_na_is_excluded_from_the_score():
    config = IOSConfig(SNIPPET)
    engine = Engine(config)
    results = [
        engine._run_one(_check("global_absent", r"^enable password")),      # PASS
        engine._run_one(_check("global_present", r"^aaa new-model$")),      # FAIL
        engine._run_one(_check("block_present", r"^x$", r"^router bgp")),   # N/A
    ]
    assert score(results) == 50.0


# -- end to end on the sample configurations ---------------------------------


@pytest.mark.parametrize("benchmark_file", ["cis-cisco-ios-l1.yaml", "disa-stig-ndm.yaml"])
def test_hardened_sample_scores_better_than_the_bad_one(benchmark_file):
    benchmark = Benchmark.from_file(CHECKS / benchmark_file)

    bad = Engine(IOSConfig.from_file(SAMPLES / "non-compliant-router.cfg")).run(benchmark)
    good = Engine(IOSConfig.from_file(SAMPLES / "hardened-router.cfg")).run(benchmark)

    assert score(bad) < score(good)
    assert any(r.failed for r in bad)


def test_no_check_errors_in_the_shipped_benchmarks():
    """A typo in a shipped YAML rule must fail the build, not silently pass."""
    config = IOSConfig.from_file(SAMPLES / "hardened-router.cfg")
    for benchmark_file in CHECKS.glob("*.yaml"):
        results = Engine(config).run(Benchmark.from_file(benchmark_file))
        errors = [r for r in results if r.status is Status.ERROR]
        assert not errors, [(r.check.id, r.evidence) for r in errors]
