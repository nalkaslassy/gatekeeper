from __future__ import annotations

from gatekeeper_cli.models import Finding, Severity, verdict


def _finding(**overrides) -> Finding:
    defaults = dict(
        category="supply_chain",
        rule_id="gk:npm-install-script",
        severity=Severity.MEDIUM,
        title="Dependency 'x' declares lifecycle install scripts",
        file_path="package-lock.json",
        detail={"context": "x@1.0.0"},
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_fingerprint_stable_across_line_number_changes():
    a = _finding(line=10)
    b = _finding(line=99)
    assert a.fingerprint == b.fingerprint


def test_fingerprint_changes_with_rule_id():
    a = _finding(rule_id="gk:npm-install-script")
    b = _finding(rule_id="gk:npm-missing-lockfile")
    assert a.fingerprint != b.fingerprint


def test_fingerprint_changes_with_context():
    a = _finding(detail={"context": "x@1.0.0"})
    b = _finding(detail={"context": "x@1.0.1"})
    assert a.fingerprint != b.fingerprint


def test_fingerprint_changes_with_title():
    a = _finding(title="first title")
    b = _finding(title="second title")
    assert a.fingerprint != b.fingerprint


def test_verdict_fails_on_error_finding_regardless_of_threshold():
    findings = [_finding(category="error", severity=Severity.INFO, is_new=True)]
    v, blocking = verdict(findings, fail_on=Severity.CRITICAL, new_only=True)
    assert v == "failed"
    assert len(blocking) == 1


def test_verdict_passes_when_nothing_meets_threshold():
    findings = [_finding(severity=Severity.LOW, is_new=True)]
    v, blocking = verdict(findings, fail_on=Severity.HIGH, new_only=True)
    assert v == "passed"
    assert blocking == []


def test_verdict_new_only_ignores_baselined_findings():
    findings = [_finding(severity=Severity.CRITICAL, is_new=False)]
    v, blocking = verdict(findings, fail_on=Severity.HIGH, new_only=True)
    assert v == "passed"


def test_verdict_all_findings_mode_blocks_on_baselined_too():
    findings = [_finding(severity=Severity.CRITICAL, is_new=False)]
    v, blocking = verdict(findings, fail_on=Severity.HIGH, new_only=False)
    assert v == "failed"
    assert len(blocking) == 1


def test_severity_parse_rejects_unknown_value():
    import pytest

    with pytest.raises(ValueError):
        Severity.parse("nonsense")


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
