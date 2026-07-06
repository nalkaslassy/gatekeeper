from __future__ import annotations

import json
import subprocess
from pathlib import Path

import gatekeeper_cli.analyzers as analyzers_mod
from gatekeeper_cli.models import Severity
from gatekeeper_cli.policy import Policy


def test_gitleaks_skips_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(analyzers_mod.shutil, "which", lambda _name: None)
    result = analyzers_mod.run_gitleaks(tmp_path, Policy())
    assert result.skipped is True


def test_gitleaks_report_written_outside_repo_and_cleaned_up(tmp_path, monkeypatch):
    monkeypatch.setattr(
        analyzers_mod.shutil, "which",
        lambda n: "/usr/bin/gitleaks" if n == "gitleaks" else None,
    )

    captured = {}

    def fake_run(cmd, cwd):
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        captured["path"] = report_path
        report_path.write_text(json.dumps([{
            "RuleID": "aws-key",
            "Description": "AWS Key",
            "File": "config.py",
            "StartLine": 3,
            "Commit": "abcdef1234567890",
        }]))
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="")

    monkeypatch.setattr(analyzers_mod, "_run", fake_run)

    result = analyzers_mod.run_gitleaks(tmp_path, Policy())
    assert result.ok
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "gitleaks:aws-key"
    assert f.severity == Severity.CRITICAL
    assert f.detail["commit"] == "abcdef1234567890"[:12]

    report_path = captured["path"]
    assert tmp_path not in report_path.parents  # never written into the scanned repo
    assert not report_path.exists()  # TemporaryDirectory cleaned it up


def test_gitleaks_tool_crash_yields_ok_false(tmp_path, monkeypatch):
    monkeypatch.setattr(
        analyzers_mod.shutil, "which",
        lambda n: "/usr/bin/gitleaks" if n == "gitleaks" else None,
    )

    def fake_run(cmd, cwd):
        return subprocess.CompletedProcess(cmd, returncode=2, stdout="", stderr="fatal error")

    monkeypatch.setattr(analyzers_mod, "_run", fake_run)

    result = analyzers_mod.run_gitleaks(tmp_path, Policy())
    assert result.ok is False
    assert "fatal error" in result.error
