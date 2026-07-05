"""Analyzers: each wraps one tool (or pure-Python logic) and emits Findings.

Design rules:
- Parse structured tool output (JSON) only. Never scrape human-readable text.
- A tool that crashes yields ok=False -> the runner converts that into an
  'error' finding. Fail closed, never open.
- A tool that is enabled but not installed is 'skipped'; whether that is an
  error is decided by policy (analyzer_required).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..models import AnalyzerResult, Finding, Severity
from ..policy import Policy

ANALYZER_TIMEOUT_SECONDS = 300


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=ANALYZER_TIMEOUT_SECONDS,
    )


# --------------------------------------------------------------------------
# ruff — Python lint
# --------------------------------------------------------------------------

def run_ruff(repo: Path, policy: Policy) -> AnalyzerResult:
    name = "ruff"
    if shutil.which("ruff") is None:
        return AnalyzerResult(name, ok=True, findings=[], skipped=True)
    try:
        proc = _run(["ruff", "check", ".", "--output-format", "json"], repo)
        # ruff exits 1 when findings exist; that is not a tool failure.
        if proc.returncode not in (0, 1):
            return AnalyzerResult(name, ok=False, findings=[], error=proc.stderr[-2000:])
        items = json.loads(proc.stdout or "[]")
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return AnalyzerResult(name, ok=False, findings=[], error=str(exc))

    findings = [
        Finding(
            category="lint",
            rule_id=f"ruff:{item.get('code') or 'unknown'}",
            severity=Severity.LOW,
            title=item.get("message", "lint finding"),
            file_path=_rel(item.get("filename"), repo),
            line=(item.get("location") or {}).get("row"),
            analyzer=name,
        )
        for item in items
    ]
    return AnalyzerResult(name, ok=True, findings=findings)


# --------------------------------------------------------------------------
# bandit — Python SAST
# --------------------------------------------------------------------------

_BANDIT_SEVERITY = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}


def run_bandit(repo: Path, policy: Policy) -> AnalyzerResult:
    name = "bandit"
    if shutil.which("bandit") is None:
        return AnalyzerResult(name, ok=True, findings=[], skipped=True)
    try:
        proc = _run(
            ["bandit", "-r", ".", "-f", "json", "-q", "-x", "./.venv,./node_modules"],
            repo,
        )
        if proc.returncode not in (0, 1):
            return AnalyzerResult(name, ok=False, findings=[], error=proc.stderr[-2000:])
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return AnalyzerResult(name, ok=False, findings=[], error=str(exc))

    findings = [
        Finding(
            category="sast",
            rule_id=f"bandit:{item.get('test_id', 'unknown')}",
            severity=_BANDIT_SEVERITY.get(
                str(item.get("issue_severity", "LOW")).upper(), Severity.LOW
            ),
            title=item.get("issue_text", "SAST finding"),
            file_path=_rel(item.get("filename"), repo),
            line=item.get("line_number"),
            detail={"context": item.get("code", "")[:120]},
            analyzer=name,
        )
        for item in data.get("results", [])
    ]
    return AnalyzerResult(name, ok=True, findings=findings)


# --------------------------------------------------------------------------
# gitleaks — secret scanning (optional external binary)
# --------------------------------------------------------------------------

def run_gitleaks(repo: Path, policy: Policy) -> AnalyzerResult:
    name = "gitleaks"
    if shutil.which("gitleaks") is None:
        return AnalyzerResult(name, ok=True, findings=[], skipped=True)
    report = repo / ".gatekeeper-gitleaks.json"
    try:
        proc = _run(
            [
                "gitleaks", "detect", "--source", ".", "--no-banner",
                "--report-format", "json", "--report-path", str(report),
            ],
            repo,
        )
        # gitleaks exits 1 when leaks are found; not a tool failure.
        if proc.returncode not in (0, 1):
            return AnalyzerResult(name, ok=False, findings=[], error=proc.stderr[-2000:])
        items = json.loads(report.read_text() or "[]") if report.exists() else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        return AnalyzerResult(name, ok=False, findings=[], error=str(exc))
    finally:
        report.unlink(missing_ok=True)

    findings = [
        Finding(
            category="secret",
            rule_id=f"gitleaks:{item.get('RuleID', 'unknown')}",
            severity=Severity.CRITICAL,   # a committed secret is always critical
            title=f"Potential secret detected ({item.get('Description', 'secret')})",
            file_path=item.get("File"),
            line=item.get("StartLine"),
            # NOTE: never include the matched secret itself in the finding.
            detail={"commit": item.get("Commit", "")[:12]},
            analyzer=name,
        )
        for item in items
    ]
    return AnalyzerResult(name, ok=True, findings=findings)


# --------------------------------------------------------------------------
# lockfile — pure-Python dependency & supply-chain checks (no network)
# --------------------------------------------------------------------------

def run_lockfile(repo: Path, policy: Policy) -> AnalyzerResult:
    """Static supply-chain checks that require zero network and zero execution.

    - package.json without package-lock.json  -> missing-lockfile finding
    - lockfile entries declaring install scripts (npm records hasInstallScript)
    - requirements.txt lines without exact pins ('==')
    """
    name = "lockfile"
    findings: list[Finding] = []

    pkg_json = repo / "package.json"
    lock = repo / "package-lock.json"

    if pkg_json.exists() and not lock.exists() and policy.require_lockfile:
        findings.append(
            Finding(
                category="supply_chain",
                rule_id="gk:npm-missing-lockfile",
                severity=policy.require_lockfile,
                title="package.json present but no package-lock.json — "
                      "installs are not reproducible or integrity-verifiable",
                file_path="package.json",
                analyzer=name,
            )
        )

    if lock.exists() and policy.install_scripts != "allow":
        try:
            data = json.loads(lock.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            return AnalyzerResult(name, ok=False, findings=findings, error=str(exc))
        sev = Severity.HIGH if policy.install_scripts == "block" else Severity.MEDIUM
        packages = data.get("packages", {})  # lockfile v2/v3
        for pkg_path, meta in packages.items():
            if not pkg_path or not isinstance(meta, dict):
                continue
            if meta.get("hasInstallScript"):
                pkg_name = pkg_path.split("node_modules/")[-1]
                findings.append(
                    Finding(
                        category="supply_chain",
                        rule_id="gk:npm-install-script",
                        severity=sev,
                        title=f"Dependency '{pkg_name}' declares lifecycle "
                              f"install scripts (runs code at install time)",
                        file_path="package-lock.json",
                        detail={"package": pkg_name,
                                "version": meta.get("version", "?"),
                                "context": pkg_name},
                        analyzer=name,
                    )
                )

    req = repo / "requirements.txt"
    if req.exists() and policy.unpinned_python_deps:
        try:
            lines = req.read_text().splitlines()
        except OSError as exc:
            return AnalyzerResult(name, ok=False, findings=findings, error=str(exc))
        for i, raw in enumerate(lines, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "--")):
                continue
            if "==" not in line and "@" not in line:
                findings.append(
                    Finding(
                        category="supply_chain",
                        rule_id="gk:py-unpinned-dependency",
                        severity=policy.unpinned_python_deps,
                        title=f"Unpinned Python dependency '{line}' — "
                              f"pin exact versions for reproducible installs",
                        file_path="requirements.txt",
                        line=i,
                        detail={"context": line},
                        analyzer=name,
                    )
                )

    return AnalyzerResult(name, ok=True, findings=findings)


def _rel(path: str | None, repo: Path) -> str | None:
    if path is None:
        return None
    try:
        return str(Path(path).resolve().relative_to(repo.resolve()))
    except ValueError:
        return path


ALL_ANALYZERS = {
    "ruff": run_ruff,
    "bandit": run_bandit,
    "gitleaks": run_gitleaks,
    "lockfile": run_lockfile,
}
