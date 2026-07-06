from __future__ import annotations

import json

from gatekeeper_cli.models import AnalyzerResult
from gatekeeper_cli.policy import Policy
from gatekeeper_cli.runner import BASELINE_FILENAME, run_scan, write_baseline


def test_baseline_write_and_apply_cycle(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    pol = Policy()

    first = run_scan(repo, pol, only=["typosquat"])
    assert first["counts"]["new"] > 0
    write_baseline(repo, first)
    assert (repo / BASELINE_FILENAME).exists()

    second = run_scan(repo, pol, only=["typosquat"])
    assert second["counts"]["new"] == 0
    assert all(not f["is_new"] for f in second["findings"])


def test_unreadable_baseline_treats_everything_as_new(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    (repo / BASELINE_FILENAME).write_text("{not valid json")
    result = run_scan(repo, Policy(), only=["typosquat"])
    assert all(f["is_new"] for f in result["findings"])


def test_baseline_excludes_error_category(tmp_path):
    scan_result = {
        "findings": [
            {"fingerprint": "abc123", "category": "supply_chain"},
            {"fingerprint": "shouldnotpersist", "category": "error"},
        ]
    }
    out = write_baseline(tmp_path, scan_result)
    data = json.loads(out.read_text())
    assert "abc123" in data["fingerprints"]
    assert "shouldnotpersist" not in data["fingerprints"]


def test_required_missing_analyzer_produces_error_finding(monkeypatch, tmp_path):
    import gatekeeper_cli.runner as runner_mod

    def fake_skipped(repo, policy):
        return AnalyzerResult("ruff", ok=True, findings=[], skipped=True)

    monkeypatch.setitem(runner_mod.ALL_ANALYZERS, "ruff", fake_skipped)
    pol = Policy(analyzers={"ruff": {"enabled": True, "required": True}})
    result = run_scan(tmp_path, pol, only=["ruff"])
    assert result["verdict"] == "failed"
    assert any(f["category"] == "error" for f in result["findings"])


def test_required_false_skip_does_not_error(monkeypatch, tmp_path):
    import gatekeeper_cli.runner as runner_mod

    def fake_skipped(repo, policy):
        return AnalyzerResult("gitleaks", ok=True, findings=[], skipped=True)

    monkeypatch.setitem(runner_mod.ALL_ANALYZERS, "gitleaks", fake_skipped)
    pol = Policy(analyzers={"gitleaks": {"enabled": True, "required": False}})
    result = run_scan(tmp_path, pol, only=["gitleaks"])
    assert result["verdict"] == "passed"
    assert not any(f["category"] == "error" for f in result["findings"])


def test_analyzer_crash_yields_error_finding_fail_closed(monkeypatch, tmp_path):
    import gatekeeper_cli.runner as runner_mod

    def fake_crash(repo, policy):
        return AnalyzerResult("lockfile", ok=False, findings=[], error="boom")

    monkeypatch.setitem(runner_mod.ALL_ANALYZERS, "lockfile", fake_crash)
    pol = Policy(analyzers={"lockfile": {"enabled": True}})
    result = run_scan(tmp_path, pol, only=["lockfile"])
    assert result["verdict"] == "failed"
    error_findings = [f for f in result["findings"] if f["category"] == "error"]
    assert len(error_findings) == 1
    assert "boom" in error_findings[0]["title"]


def test_disabled_analyzer_is_skipped_entirely(tmp_path):
    pol = Policy(analyzers={"typosquat": {"enabled": False}})
    result = run_scan(tmp_path, pol, only=["typosquat"])
    meta = next(a for a in result["analyzers"] if a["analyzer"] == "typosquat")
    assert meta["status"] == "disabled"


def test_analyzer_meta_and_findings_ordered_by_analyzer_name(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    pol = Policy(analyzers={
        "ruff": {"enabled": False}, "bandit": {"enabled": False},
        "gitleaks": {"enabled": False},
    })
    result = run_scan(repo, pol, only=["lockfile", "typosquat"])
    names = [a["analyzer"] for a in result["analyzers"]]
    assert names == sorted(names)
    finding_analyzers = [f["analyzer"] for f in result["findings"]]
    assert finding_analyzers == sorted(finding_analyzers)


def test_run_scan_is_deterministic_across_repeated_runs(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    pol = Policy()
    first = run_scan(repo, pol)
    second = run_scan(repo, pol)
    assert [a["analyzer"] for a in first["analyzers"]] == \
           [a["analyzer"] for a in second["analyzers"]]
    assert [f["fingerprint"] for f in first["findings"]] == \
           [f["fingerprint"] for f in second["findings"]]


def test_only_filter_restricts_analyzers(tmp_path):
    result = run_scan(tmp_path, Policy(), only=["lockfile"])
    names = {a["analyzer"] for a in result["analyzers"]}
    assert names == {"lockfile"}
