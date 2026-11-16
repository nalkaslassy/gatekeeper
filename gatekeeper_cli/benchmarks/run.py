"""Run Gatekeeper's deterministic trust-drift benchmark corpus."""

from __future__ import annotations

import json
from gatekeeper_cli.content import compare_content_snapshots
from gatekeeper_cli.trust import compare_trust_snapshots

from .cases import benchmark_cases


_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _decision(events: list[dict]) -> str:
    highest = max(
        (_SEVERITY_ORDER.get(str(event.get("severity")), 0) for event in events),
        default=0,
    )
    if highest >= _SEVERITY_ORDER["high"]:
        return "block"
    if highest >= _SEVERITY_ORDER["low"]:
        return "review"
    return "pass"


def run_benchmarks() -> dict:
    results = []
    benign = detected = missed = false_positive = 0
    benign_pass = benign_review = benign_block = 0
    security_cases = 0
    historical_cases = historical_detected = historical_missed = 0
    historical_pass = historical_review = historical_block = 0

    for case in benchmark_cases():
        diff = compare_trust_snapshots(case["baseline"], case["current"])
        events = list(diff["risk_events"])
        observed_rules = {event["rule"] for event in events}
        if "content_baseline" in case and "content_current" in case:
            content_diff = compare_content_snapshots(
                case["content_baseline"], case["content_current"]
            )
            events.extend(content_diff["risk_events"])
            observed_rules.update(
                event["rule"] for event in content_diff["risk_events"]
            )
        observed = sorted(observed_rules)
        decision = _decision(events)
        expected = sorted(case["expected_rules"])
        passed = observed == expected

        if case["kind"] == "benign":
            benign += 1
            if observed:
                false_positive += 1
            if decision == "pass":
                benign_pass += 1
            elif decision == "review":
                benign_review += 1
            else:
                benign_block += 1
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
            if decision == "pass":
                historical_pass += 1
            elif decision == "review":
                historical_review += 1
            else:
                historical_block += 1

        result = {
            "id": case["id"],
            "kind": case["kind"],
            "source": case["source"],
            "expected_rules": expected,
            "observed_rules": observed,
            "observed_decision": decision,
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
    benign_alert_rate = (
        (benign_review + benign_block) / benign if benign else 0.0
    )
    benign_block_rate = benign_block / benign if benign else 0.0
    historical_block_rate = (
        historical_block / historical_cases if historical_cases else 0.0
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
            "benign_passes": benign_pass,
            "benign_reviews": benign_review,
            "benign_blocks": benign_block,
            "benign_alert_rate": benign_alert_rate,
            "benign_block_rate": benign_block_rate,
            "case_precision": precision,
            "controlled_vs_benign_precision_proxy": precision,
            "controlled_case_recall": recall,
            "historical_incident_cases": historical_cases,
            "historical_incidents_detected": historical_detected,
            "historical_incidents_missed": historical_missed,
            "historical_passes": historical_pass,
            "historical_reviews": historical_review,
            "historical_blocks": historical_block,
            "historical_incident_recall": historical_recall,
            "historical_block_rate": historical_block_rate,
            "all_cases_passed": all(r["passed"] for r in results),
        },
        "results": results,
        "limitations": [
            "Controlled security-drift cases are mutations of public lockfile data, not historical compromises.",
            "Historical cases are compact reconstructions from public incident evidence and encode only fields Gatekeeper currently models.",
            "Two benign cases are compact public-repository lockfile transitions; the additional benign cases are minimal package-level models of verified public release pairs, not full lockfile graphs.",
            "The precision field is a controlled-vs-benign corpus proxy, not a population precision estimate.",
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
