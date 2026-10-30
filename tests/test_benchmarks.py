from gatekeeper_cli.benchmarks.run import run_benchmarks


def test_public_benchmark_suite_passes():
    result = run_benchmarks()
    summary = result["summary"]

    assert summary["cases"] == 11
    assert summary["benign_cases"] == 2
    assert summary["controlled_security_cases"] == 5
    assert summary["controlled_security_cases_detected"] == 5
    assert summary["missed_controlled_security_cases"] == 0
    assert summary["benign_cases_with_high_signal_alerts"] == 0
    assert summary["case_precision"] == 1.0
    assert summary["controlled_case_recall"] == 1.0
    assert summary["historical_incident_cases"] == 4
    assert summary["historical_incidents_detected"] == 2
    assert summary["historical_incidents_missed"] == 2
    assert summary["historical_incident_recall"] == 0.5
    assert summary["all_cases_passed"] is True


def test_benchmark_documents_scope_limitations():
    result = run_benchmarks()
    text = " ".join(result["limitations"]).lower()
    assert "not historical compromises" in text
    assert "historical misses are retained deliberately" in text
    assert "must not be generalized" in text


def test_historical_cases_include_expected_hits_and_misses():
    result = run_benchmarks()
    historical = [r for r in result["results"] if r["kind"] == "historical-security-incident"]
    by_id = {r["id"]: r for r in historical}

    assert by_id["historical-eslint-scope-3.7.2"]["observed_detected"] is True
    assert by_id["historical-ua-parser-js-0.7.29"]["observed_detected"] is True
    assert by_id["historical-event-stream-3.3.6"]["observed_detected"] is False
    assert by_id["historical-colors-1.4.1"]["observed_detected"] is False
