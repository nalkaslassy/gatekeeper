"""Run Gatekeeper's deterministic trust-drift benchmark corpus."""

from __future__ import annotations

import json
from gatekeeper_cli.trust import compare_trust_snapshots

from .cases import benchmark_cases


def run_benchmarks() -> dict:
    results = []
    benign = detected = missed = false_positive = 0
    security_cases = 0
    historical_cases = historical_detected = historical_missed = 0

    for case in benchmark_cases():
        diff = compare_trust_snapshots(case["baseline"], case["current"])
        observed = sorted({event["rule"] for event in diff["risk_events"]})
        expected = sorted(case["expected_rules"])
        passed = observed == expected

        if case["kind"] == "benign":
            benign += 1
            if observed:
                false_positive += 1
        elif case["kind"] == "controlled-security-drift":
            security_cases += 1
            if all(rule in observed for rule in expected) and expected:
                detected += 1
            else:
                missed += 1
        elif case["kind"] == "historical-security-incident":
            historical_cases += 1
            was_detected = bool(observed)
            if was_detected:
                historical_detected += 1
            else:
                historical_missed += 1

        result = {
            "id": case["id"],
            "kind": case["kind"],
            "source": case["source"],
            "expected_rules": expected,
            "observed_rules": observed,
            "passed": passed,
        }
        if case["kind"] == "historical-security-incident":
            result["expected_detected"] = case["expected_detected"]
            result["observed_detected"] = bool(observed)
        results.append(result)

    total = len(results)
    precision_denominator = detected + false_positive
    precision = detected / precision_denominator if precision_denominator else 1.0
    recall = detected / security_cases if security_cases else 1.0
    historical_recall = (
        historical_detected / historical_cases if historical_cases else 1.0
    )

    return {
        "schema_version": 1,
        "summary": {
            "cases": total,
            "benign_cases": benign,
            "controlled_security_cases": security_cases,
            "controlled_security_cases_detected": detected,
            "missed_controlled_security_cases": missed,
            "benign_cases_with_high_signal_alerts": false_positive,
            "case_precision": precision,
            "controlled_case_recall": recall,
            "historical_incident_cases": historical_cases,
            "historical_incidents_detected": historical_detected,
            "historical_incidents_missed": historical_missed,
            "historical_incident_recall": historical_recall,
            "all_cases_passed": all(r["passed"] for r in results),
        },
        "results": results,
        "limitations": [
            "Controlled security-drift cases are mutations of public lockfile data, not historical compromises.",
            "Historical cases are compact reconstructions from public incident evidence and encode only fields Gatekeeper currently models.",
            "Benign cases are compact reproductions of real public release transitions, not full vendored repositories.",
            "Historical misses are retained deliberately to document detection gaps rather than tune the corpus to a perfect score.",
            "These metrics describe only this benchmark corpus and must not be generalized to all software supply-chain attacks.",
        ],
    }


def main() -> int:
    result = run_benchmarks()
    print(json.dumps(result, indent=2))
    return 0 if result["summary"]["all_cases_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
