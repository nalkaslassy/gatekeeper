from benchmarks.run import run_benchmarks


def test_public_benchmark_suite_passes():
    result = run_benchmarks()
    summary = result["summary"]

    assert summary["cases"] == 7
    assert summary["benign_cases"] == 2
    assert summary["controlled_security_cases"] == 5
    assert summary["controlled_security_cases_detected"] == 5
    assert summary["missed_controlled_security_cases"] == 0
    assert summary["benign_cases_with_high_signal_alerts"] == 0
    assert summary["case_precision"] == 1.0
    assert summary["controlled_case_recall"] == 1.0
    assert summary["all_cases_passed"] is True


def test_benchmark_documents_scope_limitations():
    result = run_benchmarks()
    text = " ".join(result["limitations"]).lower()
    assert "not historical compromises" in text
    assert "must not be generalized" in text
