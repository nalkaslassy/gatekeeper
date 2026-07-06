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
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml

from ..models import AnalyzerResult, Finding, Severity
from ..policy import Policy
from .osv import run_osv
from .python_manifests import (
    normalize_pypi_name,
    parse_pyproject_dependencies,
    pep508_name,
    requirement_line_name,
    resolved_versions,
)
from .typosquat import run_typosquat

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
            ["bandit", "-r", ".", "-f", "json", "-q",
             "-x", "./.venv,./node_modules,./tests"],
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
    try:
        # The report is written outside the scanned repo entirely — never
        # into the untrusted tree itself, and automatically cleaned up
        # (including on a crash/timeout) rather than relying on a
        # try/finally unlink that a hard kill could skip.
        with tempfile.TemporaryDirectory(prefix="gatekeeper-gitleaks-") as tmp_dir:
            report = Path(tmp_dir) / "report.json"
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

_PNPM_KEY_RE = re.compile(r"^/?(?P<name>@[^/@]+/[^@]+|[^@]+)@(?P<version>[^()]+)")


def _parse_pnpm_key(key: str) -> tuple[str, str] | None:
    m = _PNPM_KEY_RE.match(key)
    if not m:
        return None
    return m.group("name"), m.group("version")


def _pnpm_install_script_packages(repo: Path) -> list[tuple[str, str]]:
    """Best-effort: pnpm's lockfile schema has changed across pnpm versions
    (v6 keeps per-package metadata under `packages:`; v9 splits it between
    `packages:` and `snapshots:`). Check both known locations for the
    `requiresBuild` flag pnpm sets on packages with install/build scripts.
    """
    path = repo / "pnpm-lock.yaml"
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (yaml.YAMLError, OSError):
        return []
    if not isinstance(data, dict):
        return []

    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for section in ("packages", "snapshots"):
        for key, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict) or not meta.get("requiresBuild"):
                continue
            parsed = _parse_pnpm_key(key)
            if parsed and parsed not in seen:
                seen.add(parsed)
                out.append(parsed)
    return out


def run_lockfile(repo: Path, policy: Policy) -> AnalyzerResult:
    """Static supply-chain checks that require zero network and zero execution.

    - package.json without any lockfile           -> missing-lockfile finding
    - package-lock.json / pnpm-lock.yaml entries declaring install scripts
      (npm records `hasInstallScript`; pnpm records `requiresBuild`)
    - requirements.txt lines without exact pins ('==')

    yarn.lock satisfies the missing-lockfile check but, unlike npm/pnpm,
    classic yarn.lock carries no install-script metadata at all — detecting
    install scripts for yarn-only projects would require a registry lookup
    (network), which this analyzer deliberately does not do. Use the
    (opt-in, networked) `osv` analyzer if you need coverage there.
    """
    name = "lockfile"
    findings: list[Finding] = []

    pkg_json = repo / "package.json"
    npm_lock = repo / "package-lock.json"
    yarn_lock = repo / "yarn.lock"
    pnpm_lock = repo / "pnpm-lock.yaml"
    has_any_lock = npm_lock.exists() or yarn_lock.exists() or pnpm_lock.exists()

    if pkg_json.exists() and not has_any_lock and policy.require_lockfile:
        findings.append(
            Finding(
                category="supply_chain",
                rule_id="gk:npm-missing-lockfile",
                severity=policy.require_lockfile,
                title="package.json present but no lockfile "
                      "(package-lock.json / yarn.lock / pnpm-lock.yaml) — "
                      "installs are not reproducible or integrity-verifiable",
                file_path="package.json",
                analyzer=name,
            )
        )

    if npm_lock.exists():
        try:
            data = json.loads(npm_lock.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            return AnalyzerResult(name, ok=False, findings=findings, error=str(exc))

        if data.get("lockfileVersion") == 1:
            # v1 (pre-npm-7) has no per-package "packages" map at all — just
            # a nested "dependencies" tree with no hasInstallScript/integrity
            # metadata. Every check below that relies on that metadata is
            # silently blind on a v1 lockfile; surface that gap explicitly
            # rather than let it look like a clean scan.
            findings.append(
                Finding(
                    category="supply_chain",
                    rule_id="gk:npm-lockfile-v1",
                    severity=Severity.LOW,
                    title="package-lock.json uses lockfileVersion 1, which lacks "
                          "the per-package metadata (hasInstallScript, integrity) "
                          "this analyzer relies on — upgrade to npm >=7 and "
                          "regenerate the lockfile for full install-script coverage",
                    file_path="package-lock.json",
                    analyzer=name,
                )
            )

        if policy.install_scripts != "allow":
            sev = Severity.HIGH if policy.install_scripts == "block" else Severity.MEDIUM
            packages = data.get("packages", {})  # lockfile v2/v3 only
            for pkg_path, meta in packages.items():
                if not pkg_path or not isinstance(meta, dict):
                    continue
                if meta.get("hasInstallScript"):
                    pkg_name = pkg_path.split("node_modules/")[-1]
                    version = meta.get("version", "?")
                    findings.append(
                        Finding(
                            category="supply_chain",
                            rule_id="gk:npm-install-script",
                            severity=sev,
                            title=f"Dependency '{pkg_name}' declares lifecycle "
                                  f"install scripts (runs code at install time)",
                            file_path="package-lock.json",
                            detail={
                                "package": pkg_name,
                                "version": version,
                                # Version is deliberately part of the
                                # fingerprint: if this package is compromised
                                # in-place (same name, bumped version, still
                                # hasInstallScript), it must resurface as a
                                # NEW finding even though an earlier version
                                # was already baselined.
                                "context": f"{pkg_name}@{version}",
                            },
                            analyzer=name,
                        )
                    )

    if pnpm_lock.exists() and policy.install_scripts != "allow":
        sev = Severity.HIGH if policy.install_scripts == "block" else Severity.MEDIUM
        for pkg_name, version in _pnpm_install_script_packages(repo):
            findings.append(
                Finding(
                    category="supply_chain",
                    rule_id="gk:npm-install-script",
                    severity=sev,
                    title=f"Dependency '{pkg_name}' declares lifecycle "
                          f"install scripts (runs code at install time)",
                    file_path="pnpm-lock.yaml",
                    detail={"package": pkg_name, "version": version,
                            "context": f"{pkg_name}@{version}"},
                    analyzer=name,
                )
            )

    if policy.unpinned_python_deps:
        # poetry.lock / uv.lock resolve a range specifier to one exact,
        # reproducible version even though the manifest itself never pins
        # it — that satisfies the same reproducibility goal an explicit
        # '==' does, so deps resolved there must not also be flagged.
        resolved = resolved_versions(repo)

        req = repo / "requirements.txt"
        if req.exists():
            try:
                lines = req.read_text().splitlines()
            except OSError as exc:
                return AnalyzerResult(name, ok=False, findings=findings, error=str(exc))
            for i, raw in enumerate(lines, start=1):
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith(("-", "--")):
                    continue
                if "==" in line or "@" in line:
                    continue
                if normalize_pypi_name(requirement_line_name(line)) in resolved:
                    continue
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

        for raw_spec in parse_pyproject_dependencies(repo):
            spec_no_marker = raw_spec.split(";", 1)[0]
            if "==" in spec_no_marker:
                continue
            if normalize_pypi_name(pep508_name(raw_spec)) in resolved:
                continue
            findings.append(
                Finding(
                    category="supply_chain",
                    rule_id="gk:py-unpinned-dependency",
                    severity=policy.unpinned_python_deps,
                    title=f"Unpinned Python dependency '{raw_spec}' — pin exact "
                          f"versions or add a poetry.lock/uv.lock for "
                          f"reproducible installs",
                    file_path="pyproject.toml",
                    detail={"context": raw_spec},
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
    "typosquat": run_typosquat,
    "osv": run_osv,
}
