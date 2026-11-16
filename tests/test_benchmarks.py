from gatekeeper_cli.benchmarks.run import run_benchmarks


def test_public_benchmark_suite_passes():
    result = run_benchmarks()
    summary = result["summary"]

    assert summary["cases"] == 40
    assert summary["benign_cases"] == 25
    assert summary["controlled_security_cases"] == 5
    assert summary["controlled_security_cases_detected"] == 5
    assert summary["missed_controlled_security_cases"] == 0

    assert summary["benign_cases_with_high_signal_alerts"] == 0
    assert summary["benign_lockfile_transition_cases"] == 2
    assert summary["benign_package_release_transition_cases"] == 23
    assert summary["benign_passes"] == 25
    assert summary["benign_reviews"] == 0
    assert summary["benign_blocks"] == 0
    assert summary["benign_alert_rate"] == 0.0
    assert summary["benign_block_rate"] == 0.0

    assert summary["case_precision"] == 1.0
    assert summary["controlled_vs_benign_precision_proxy"] == 1.0
    assert summary["controlled_case_recall"] == 1.0

    assert summary["historical_incident_cases"] == 10
    assert summary["historical_incidents_detected"] == 9
    assert summary["historical_incidents_missed"] == 1
    assert summary["historical_passes"] == 1
    assert summary["historical_reviews"] == 4
    assert summary["historical_blocks"] == 5
    assert summary["historical_incident_recall"] == 0.9
    assert summary["historical_block_rate"] == 0.5
    assert summary["all_cases_passed"] is True


def test_benchmark_documents_scope_limitations():
    result = run_benchmarks()
    text = " ".join(result["limitations"]).lower()
    assert "not historical compromises" in text
    assert "historical misses are retained deliberately" in text
    assert "minimal package-level models" in text
    assert "not a population precision estimate" in text
    assert "must not be generalized" in text


def test_historical_cases_include_expected_hits_and_misses():
    result = run_benchmarks()
    historical = [r for r in result["results"] if r["kind"] == "historical-security-incident"]
    by_id = {r["id"]: r for r in historical}

    assert by_id["historical-eslint-scope-3.7.2"]["observed_detected"] is True
    assert by_id["historical-ua-parser-js-0.7.29"]["observed_detected"] is True
    assert by_id["historical-event-stream-3.3.6"]["observed_detected"] is True
    assert by_id["historical-event-stream-3.3.6"]["observed_decision"] == "review"
    assert by_id["historical-colors-1.4.1"]["observed_detected"] is True
    assert by_id["historical-coa-2.0.3"]["observed_detected"] is True
    assert by_id["historical-rc-1.2.9"]["observed_detected"] is True
    assert by_id["historical-node-ipc-10.1.1"]["observed_detected"] is True
    assert by_id["historical-browserift-16.3.3"]["observed_detected"] is True
    assert by_id["historical-common-array-token-1.0.0"]["observed_detected"] is True
    assert by_id["historical-data-value-45.0.0"]["observed_detected"] is False
    assert by_id["historical-data-value-45.0.0"]["observed_decision"] == "pass"


def test_benign_corpus_includes_multiple_real_projects():
    result = run_benchmarks()
    benign = [r for r in result["results"] if r["kind"] == "benign"]
    repositories = {
        r["source"].get("repository")
        for r in benign
        if r["source"].get("repository")
    }
    assert len(repositories) >= 10


def test_historical_corpus_contains_block_review_and_documented_miss():
    result = run_benchmarks()
    historical = [
        r for r in result["results"]
        if r["kind"] == "historical-security-incident"
    ]
    decisions = {r["observed_decision"] for r in historical}
    assert decisions == {"pass", "review", "block"}
