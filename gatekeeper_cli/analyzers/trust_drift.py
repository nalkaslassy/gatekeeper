"""Analyzer adapter for Gatekeeper's change-aware trust-drift engine."""

from __future__ import annotations

from pathlib import Path

from ..models import AnalyzerResult, Finding, Severity
from ..policy import Policy
from ..trust import TRUST_FILENAME, compare_repo_to_baseline

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def run_trust_drift(repo: Path, policy: Policy) -> AnalyzerResult:
    name = "trust_drift"
    if not (repo / TRUST_FILENAME).exists():
        return AnalyzerResult(name, ok=True, findings=[])

    try:
        diff = compare_repo_to_baseline(repo)
    except ValueError as exc:
        return AnalyzerResult(name, ok=False, findings=[], error=str(exc))

    findings: list[Finding] = []
    for event in (diff or {}).get("risk_events", []):
        package = event.get("package")
        ecosystem = event.get("ecosystem")
        version = event.get("version")
        context = ":".join(
            str(part) for part in (ecosystem, package, version, event.get("rule"))
            if part is not None
        )
        findings.append(
            Finding(
                category="supply_chain",
                rule_id=f"gk:trust-drift:{event['rule']}",
                severity=_SEVERITY.get(event["severity"], Severity.MEDIUM),
                title=(
                    f"Trust drift for {ecosystem}:{package}: {event['message']}"
                    if package else f"Trust drift: {event['message']}"
                ),
                file_path=TRUST_FILENAME,
                detail={
                    "package": package,
                    "ecosystem": ecosystem,
                    "version": version,
                    "context": context,
                },
                analyzer=name,
            )
        )
    return AnalyzerResult(name, ok=True, findings=findings)
