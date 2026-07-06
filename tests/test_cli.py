from __future__ import annotations

import json

from typer.testing import CliRunner

from gatekeeper_cli.main import app

runner = CliRunner()


def test_scan_clean_fixture_exits_zero(fixture_repo):
    repo = fixture_repo("clean")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 0, result.output


def test_scan_bad_fixture_exits_one(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 1, result.output


def test_scan_invalid_policy_exits_two(fixture_repo):
    repo = fixture_repo("invalid_policy")
    result = runner.invoke(app, ["scan", str(repo)])
    assert result.exit_code == 2


def test_scan_json_format_parses(fixture_repo):
    repo = fixture_repo("clean")
    result = runner.invoke(app, ["scan", str(repo), "--format", "json"])
    data = json.loads(result.output)
    assert data["verdict"] == "passed"
    assert "findings" in data


def test_scan_sarif_format_has_valid_basic_shape(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    result = runner.invoke(app, ["scan", str(repo), "--format", "sarif"])
    data = json.loads(result.output)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Gatekeeper"
    assert driver["informationUri"] == "https://github.com/nalkaslassy/gatekeeper"
    assert "version" in driver and driver["version"]
    assert isinstance(run["results"], list)
    assert len(run["results"]) > 0
    for entry in run["results"]:
        assert "ruleId" in entry
        assert "level" in entry
        assert "message" in entry and "text" in entry["message"]
        assert "gatekeeperFingerprint/v1" in entry["partialFingerprints"]

    rule_ids_in_results = {entry["ruleId"] for entry in run["results"]}
    rule_ids_in_catalog = {rule["id"] for rule in driver["rules"]}
    assert rule_ids_in_results <= rule_ids_in_catalog
    for rule in driver["rules"]:
        assert "shortDescription" in rule and rule["shortDescription"]["text"]


def test_scan_fail_on_override(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    # bad_typosquat's finding is HIGH severity; overriding to critical should pass
    result = runner.invoke(app, ["scan", str(repo), "--fail-on", "critical"])
    assert result.exit_code == 0, result.output


def test_scan_analyzers_subset(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    result = runner.invoke(
        app, ["scan", str(repo), "--format", "json", "--analyzers", "lockfile"]
    )
    data = json.loads(result.output)
    names = {a["analyzer"] for a in data["analyzers"]}
    assert names == {"lockfile"}


def test_baseline_then_scan_passes(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    baseline_result = runner.invoke(app, ["baseline", str(repo)])
    assert baseline_result.exit_code == 0, baseline_result.output
    assert (repo / ".gatekeeper-baseline.json").exists()

    scan_result = runner.invoke(app, ["scan", str(repo)])
    assert scan_result.exit_code == 0, scan_result.output


def test_policy_init_writes_starter(tmp_path):
    result = runner.invoke(app, ["policy", "init", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "gatekeeper.yaml").exists()


def test_policy_init_refuses_to_overwrite(tmp_path):
    (tmp_path / "gatekeeper.yaml").write_text("version: 1\n")
    result = runner.invoke(app, ["policy", "init", str(tmp_path)])
    assert result.exit_code == 2


def test_policy_validate_ok(fixture_repo):
    repo = fixture_repo("clean")
    result = runner.invoke(app, ["policy", "validate", str(repo)])
    assert result.exit_code == 0
    assert "Policy OK" in result.output


def test_policy_validate_invalid(fixture_repo):
    repo = fixture_repo("invalid_policy")
    result = runner.invoke(app, ["policy", "validate", str(repo)])
    assert result.exit_code == 2


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "gatekeeper-cli" in result.output
