from __future__ import annotations

import pytest

from gatekeeper_cli.models import Severity
from gatekeeper_cli.policy import POLICY_FILENAME, STARTER_POLICY, Policy, load_policy


def test_defaults_with_no_file(tmp_path):
    pol = load_policy(tmp_path)
    assert pol.fail_on == Severity.HIGH
    assert pol.new_findings_only is True
    assert pol.require_lockfile == Severity.HIGH
    assert pol.install_scripts == "warn"
    assert pol.unpinned_python_deps == Severity.MEDIUM
    assert pol.typosquat == Severity.HIGH
    assert pol.source_path is None


def test_starter_policy_round_trips(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text(STARTER_POLICY)
    pol = load_policy(tmp_path)
    assert pol.fail_on == Severity.HIGH
    assert pol.analyzer_enabled("ruff")
    assert pol.analyzer_enabled("typosquat")
    assert not pol.analyzer_enabled("osv")  # explicitly enabled: false in starter
    assert pol.analyzer_required("gitleaks") is False
    assert pol.analyzer_required("osv") is False


def test_invalid_yaml_raises(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text("fail_on: [this is not valid: yaml")
    with pytest.raises(ValueError):
        load_policy(tmp_path)


def test_invalid_install_scripts_mode_raises(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text(
        "version: 1\nsupply_chain:\n  install_scripts: nonsense\n"
    )
    with pytest.raises(ValueError):
        load_policy(tmp_path)


def test_explicit_policy_path_missing_raises(tmp_path):
    with pytest.raises(ValueError):
        load_policy(tmp_path, explicit=tmp_path / "does-not-exist.yaml")


def test_non_mapping_policy_raises(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text("- just\n- a\n- list\n")
    with pytest.raises(ValueError):
        load_policy(tmp_path)


def test_osv_disabled_when_policy_omits_analyzers_entirely(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text("version: 1\nfail_on: high\n")
    pol = load_policy(tmp_path)
    assert pol.analyzer_enabled("osv") is False
    # every other analyzer defaults to enabled
    assert pol.analyzer_enabled("ruff") is True
    assert pol.analyzer_enabled("typosquat") is True


def test_osv_disabled_when_analyzers_block_exists_but_omits_osv(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text(
        "version: 1\nanalyzers:\n  ruff: { enabled: false }\n"
    )
    pol = load_policy(tmp_path)
    assert pol.analyzer_enabled("osv") is False
    assert pol.analyzer_enabled("ruff") is False
    assert pol.analyzer_enabled("bandit") is True  # untouched analyzer still defaults on


def test_osv_can_be_explicitly_enabled(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text(
        "version: 1\nanalyzers:\n  osv: { enabled: true }\n"
    )
    pol = load_policy(tmp_path)
    assert pol.analyzer_enabled("osv") is True


@pytest.mark.parametrize("value", ["off", "none", "disabled", "OFF", False])
def test_off_values_disable_severity_checks(tmp_path, value):
    yaml_value = str(value).lower() if not isinstance(value, bool) else str(value).lower()
    (tmp_path / POLICY_FILENAME).write_text(
        f"version: 1\nsupply_chain:\n  typosquat: {yaml_value}\n"
    )
    pol = load_policy(tmp_path)
    assert pol.typosquat is None


def test_require_lockfile_can_be_disabled(tmp_path):
    (tmp_path / POLICY_FILENAME).write_text(
        "version: 1\nsupply_chain:\n  require_lockfile: off\n"
    )
    pol = load_policy(tmp_path)
    assert pol.require_lockfile is None


def test_analyzer_required_defaults_true(tmp_path):
    pol = Policy()
    assert pol.analyzer_required("ruff") is True
    assert pol.analyzer_required("bandit") is True
