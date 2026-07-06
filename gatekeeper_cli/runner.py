"""Scan orchestration: run enabled analyzers, apply baseline, compute verdict,
and render output (text / json / sarif)."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzers import ALL_ANALYZERS
from .models import AnalyzerResult, Finding, Severity, verdict
from .policy import Policy

BASELINE_FILENAME = ".gatekeeper-baseline.json"


def run_scan(repo: Path, policy: Policy, only: list[str] | None = None) -> dict:
    """Run all enabled analyzers and return a scan result dict.

    Analyzers are independent (each reads the repo and returns its own
    result; none shares mutable state with another) and are I/O-bound —
    subprocess calls for ruff/bandit/gitleaks, network for osv — so they run
    concurrently. Thread scheduling order isn't deterministic, so both the
    analyzer-status list and the aggregated findings are sorted by analyzer
    name afterward: same output every run regardless of which one finishes
    first.
    """
    findings: list[Finding] = []
    analyzer_meta: dict[str, dict] = {}
    to_run: list[tuple[str, object]] = []

    for name, fn in ALL_ANALYZERS.items():
        if only and name not in only:
            continue
        if not policy.analyzer_enabled(name):
            analyzer_meta[name] = {"analyzer": name, "status": "disabled"}
            continue
        to_run.append((name, fn))

    results: dict[str, AnalyzerResult] = {}
    if to_run:
        with ThreadPoolExecutor(max_workers=len(to_run)) as pool:
            future_to_name = {pool.submit(fn, repo, policy): name for name, fn in to_run}
            for future in future_to_name:
                results[future_to_name[future]] = future.result()

    for name, _fn in to_run:
        result = results[name]

        if result.skipped:
            status = "skipped (tool not installed)"
            if policy.analyzer_required(name):
                # Fail closed: a required analyzer that can't run is an error.
                findings.append(_error_finding(
                    name, f"Required analyzer '{name}' is not installed"))
                status = "error (required but not installed)"
            analyzer_meta[name] = {"analyzer": name, "status": status}
            continue

        if not result.ok:
            findings.append(_error_finding(
                name, f"Analyzer '{name}' failed: {result.error or 'unknown error'}"))
            analyzer_meta[name] = {"analyzer": name, "status": "error"}
            continue

        findings.extend(result.findings)
        analyzer_meta[name] = {
            "analyzer": name, "status": "ok", "findings": len(result.findings)
        }

    ordered_meta = [analyzer_meta[name] for name in sorted(analyzer_meta)]
    findings.sort(key=lambda f: f.analyzer)  # stable: preserves each analyzer's own order

    _apply_baseline(repo, findings)
    v, blocking = verdict(findings, policy.fail_on, policy.new_findings_only)

    return {
        "verdict": v,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "repo": str(repo),
        "policy": str(policy.source_path) if policy.source_path else "(defaults)",
        "fail_on": str(policy.fail_on),
        "analyzers": ordered_meta,
        "counts": _counts(findings),
        "blocking": [f.to_dict() for f in blocking],
        "findings": [f.to_dict() for f in findings],
    }


def _error_finding(analyzer: str, message: str) -> Finding:
    return Finding(
        category="error",
        rule_id=f"gk:analyzer-error:{analyzer}",
        severity=Severity.HIGH,
        title=message,
        analyzer=analyzer,
    )


def _counts(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    counts["total"] = len(findings)
    counts["new"] = sum(1 for f in findings if f.is_new)
    return counts


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------

def _apply_baseline(repo: Path, findings: list[Finding]) -> None:
    path = repo / BASELINE_FILENAME
    if not path.exists():
        return
    try:
        known = set(json.loads(path.read_text()).get("fingerprints", []))
    except (json.JSONDecodeError, OSError):
        return  # unreadable baseline: treat everything as new (safer)
    for f in findings:
        if f.fingerprint in known:
            f.is_new = False


def write_baseline(repo: Path, scan_result: dict) -> Path:
    path = repo / BASELINE_FILENAME
    path.write_text(json.dumps(
        {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "fingerprints": sorted(
                {f["fingerprint"] for f in scan_result["findings"]
                 if f["category"] != "error"}
            ),
        },
        indent=2,
    ))
    return path


# --------------------------------------------------------------------------
# SARIF output (renders in the GitHub Security tab via upload-sarif)
# --------------------------------------------------------------------------

_SARIF_LEVEL = {
    "info": "note", "low": "note",
    "medium": "warning",
    "high": "error", "critical": "error",
}


def to_sarif(scan_result: dict) -> dict:
    results = []
    rules: dict[str, dict] = {}  # ruleId -> reportingDescriptor, first-seen wins

    for f in scan_result["findings"]:
        rule_id = f["rule_id"]
        level = _SARIF_LEVEL.get(f["severity"], "warning")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f["title"][:200]},
                "defaultConfiguration": {"level": level},
            }

        entry = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f["title"]},
            # Lets code-scanning match the same finding across scans even
            # if GitHub's own line-based fingerprinting would otherwise
            # treat it as new — reuses the same fingerprint the baseline
            # mechanism keys on.
            "partialFingerprints": {"gatekeeperFingerprint/v1": f["fingerprint"]},
        }
        if f.get("file_path"):
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file_path"]},
                    "region": {"startLine": max(1, f.get("line") or 1)},
                }
            }]
        results.append(entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Gatekeeper",
                "informationUri": "https://github.com/nalkaslassy/gatekeeper",
                "version": __version__,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
