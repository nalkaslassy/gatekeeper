"""Run Gatekeeper's deterministic trust-drift benchmark corpus."""

from __future__ import annotations

import json
from gatekeeper_cli.trust import compare_trust_snapshots

from benchmarks.cases import benchmark_cases


def run_benchmarks() -> dict:
    results = []
    benign = detected = missed = false_positive = 0
    security_cases = 0

    for case in benchmark_cases():
        diff = compare_trust_snapshots(case["baseline"], case["current"])
        observed = sorted({event["rule"] for event in diff["risk_events"]})
        expected = sorted(case["expected_rules"])
        passed = observed == expected

        if case["kind"] == "benign":
            benign += 1
            if observed:
                false_positive += 1
        else:
            security_cases += 1
            if all(rule in observed for rule in expected) and expected:
                detected += 1
            else:
                missed += 1

        results.append({
            "id": case["id"],
            "kind": case["kind"],
            "source": case["source"],
            "expected_rules": expected,
            "observed_rules": observed,
            "passed": passed,
        })

    total = len(results)
    precision_denominator = detected + false_positive
    precision = detected / precision_denominator if precision_denominator else 1.0
    recall = detected / security_cases if security_cases else 1.0

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
            "all_cases_passed": all(r["passed"] for r in results),
        },
        "results": results,
        "limitations": [
            "Controlled security-drift cases are mutations of public lockfile data, not historical compromises.",
            "Benign cases are compact reproductions of real public release transitions, not full vendored repositories.",
            "These metrics describe only this benchmark corpus and must not be generalized to all software supply-chain attacks.",
        ],
    }


def main() -> int:
    result = run_benchmarks()
    print(json.dumps(result, indent=2))
    return 0 if result["summary"]["all_cases_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
