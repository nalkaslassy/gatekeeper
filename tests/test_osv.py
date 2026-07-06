from __future__ import annotations

import json

import gatekeeper_cli.analyzers.osv as osv_mod
from gatekeeper_cli.models import Severity
from gatekeeper_cli.policy import Policy


def _write_npm_lock(repo, packages: dict[str, str]):
    data = {
        "name": "fixture",
        "lockfileVersion": 3,
        "packages": {"": {"name": "fixture"}},
    }
    for name, version in packages.items():
        data["packages"][f"node_modules/{name}"] = {"version": version}
    (repo / "package-lock.json").write_text(json.dumps(data))


def test_no_manifests_returns_empty_ok(tmp_path):
    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.ok
    assert result.findings == []


def test_malicious_advisory_becomes_critical_supply_chain_finding(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"evil-pkg": "1.0.0"})

    def fake_post_json(url, payload):
        return {"results": [{"vulns": [{"id": "MAL-2024-1234"}]}]}

    def fake_get_json(url):
        return {"id": "MAL-2024-1234", "summary": "malicious code"}

    monkeypatch.setattr(osv_mod, "_post_json", fake_post_json)
    monkeypatch.setattr(osv_mod, "_get_json", fake_get_json)

    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.ok
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "gk:osv-malicious-package"
    assert f.severity == Severity.CRITICAL
    assert f.category == "supply_chain"
    assert "evil-pkg" in f.title


def test_malicious_detected_via_alias_not_just_id(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"evil-pkg": "1.0.0"})

    monkeypatch.setattr(
        osv_mod, "_post_json",
        lambda url, payload: {"results": [{"vulns": [{"id": "GHSA-xxxx-xxxx-xxxx"}]}]},
    )
    monkeypatch.setattr(
        osv_mod, "_get_json",
        lambda url: {"id": "GHSA-xxxx-xxxx-xxxx", "aliases": ["MAL-2024-9999"]},
    )

    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.findings[0].rule_id == "gk:osv-malicious-package"
    assert result.findings[0].severity == Severity.CRITICAL


def test_ordinary_advisory_becomes_vuln_finding_with_mapped_severity(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"some-pkg": "2.0.0"})

    monkeypatch.setattr(
        osv_mod, "_post_json",
        lambda url, payload: {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]},
    )
    monkeypatch.setattr(
        osv_mod, "_get_json",
        lambda url: {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "Something bad",
            "database_specific": {"severity": "HIGH"},
        },
    )

    result = osv_mod.run_osv(tmp_path, Policy())
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.rule_id == "osv:GHSA-aaaa-bbbb-cccc"
    assert f.category == "vuln"
    assert f.severity == Severity.HIGH


def test_advisory_without_parseable_severity_defaults_high(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"some-pkg": "2.0.0"})

    monkeypatch.setattr(
        osv_mod, "_post_json",
        lambda url, payload: {"results": [{"vulns": [{"id": "GHSA-zzzz-zzzz-zzzz"}]}]},
    )
    monkeypatch.setattr(
        osv_mod, "_get_json",
        lambda url: {"id": "GHSA-zzzz-zzzz-zzzz"},  # no severity info at all
    )

    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.findings[0].severity == Severity.HIGH


def test_network_error_on_batch_query_yields_ok_false(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"some-pkg": "2.0.0"})

    def raise_error(url, payload):
        raise TimeoutError("simulated network failure")

    monkeypatch.setattr(osv_mod, "_post_json", raise_error)

    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.ok is False
    assert result.error is not None


def test_runner_converts_osv_network_failure_to_error_finding(tmp_path, monkeypatch):
    from gatekeeper_cli.runner import run_scan

    _write_npm_lock(tmp_path, {"some-pkg": "2.0.0"})

    def raise_error(url, payload):
        raise TimeoutError("simulated network failure")

    monkeypatch.setattr(osv_mod, "_post_json", raise_error)

    pol = Policy(analyzers={"osv": {"enabled": True, "required": True}})
    result = run_scan(tmp_path, pol, only=["osv"])
    assert result["verdict"] == "failed"
    assert any(f["category"] == "error" for f in result["findings"])


def test_malformed_lockfile_does_not_crash(tmp_path):
    (tmp_path / "package-lock.json").write_text("{not valid json")
    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.ok
    assert result.findings == []


def test_dedupes_duplicate_package_version_pairs(tmp_path, monkeypatch):
    # Two different lockfile paths, same name@version (hoisting duplicate).
    data = {
        "name": "fixture",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture"},
            "node_modules/dup-pkg": {"version": "1.0.0"},
            "node_modules/nested/node_modules/dup-pkg": {"version": "1.0.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(data))

    calls = []

    def fake_post_json(url, payload):
        calls.append(payload)
        return {"results": [{"vulns": []} for _ in payload["queries"]]}

    monkeypatch.setattr(osv_mod, "_post_json", fake_post_json)

    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.ok
    assert result.findings == []
    total_queries = sum(len(c["queries"]) for c in calls)
    assert total_queries == 1  # deduped: only one query sent for the pair


def test_pagination_follows_next_page_token(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"chatty-pkg": "1.0.0"})

    call_count = {"n": 0}

    def fake_post_json(url, payload):
        call_count["n"] += 1
        query = payload["queries"][0]
        if "page_token" not in query:
            return {"results": [{"vulns": [{"id": "GHSA-page-one"}],
                                  "next_page_token": "tok-1"}]}
        assert query["page_token"] == "tok-1"
        return {"results": [{"vulns": [{"id": "GHSA-page-two"}]}]}

    monkeypatch.setattr(osv_mod, "_post_json", fake_post_json)
    monkeypatch.setattr(osv_mod, "_get_json", lambda url: {})

    result = osv_mod.run_osv(tmp_path, Policy())
    ids = {f.detail["osv_id"] for f in result.findings}
    assert ids == {"GHSA-page-one", "GHSA-page-two"}
    assert call_count["n"] == 2


def test_pagination_bounded_and_survives_mid_pagination_failure(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"chatty-pkg": "1.0.0"})

    def fake_post_json(url, payload):
        query = payload["queries"][0]
        if "page_token" not in query:
            return {"results": [{"vulns": [{"id": "GHSA-first-page"}],
                                  "next_page_token": "tok-1"}]}
        raise TimeoutError("second page unavailable")

    monkeypatch.setattr(osv_mod, "_post_json", fake_post_json)
    monkeypatch.setattr(osv_mod, "_get_json", lambda url: {})

    result = osv_mod.run_osv(tmp_path, Policy())
    # First page's data must survive even though the second page errored —
    # this must NOT be treated as a fatal analyzer failure.
    assert result.ok
    ids = {f.detail["osv_id"] for f in result.findings}
    assert ids == {"GHSA-first-page"}


def test_detail_fetch_cap_still_reports_finding_without_detail(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"some-pkg": "2.0.0"})
    monkeypatch.setattr(osv_mod, "MAX_DETAIL_FETCHES", 0)
    monkeypatch.setattr(
        osv_mod, "_post_json",
        lambda url, payload: {"results": [{"vulns": [{"id": "GHSA-uncapped"}]}]},
    )

    def fail_if_called(url):
        raise AssertionError("detail fetch should not run past the cap")

    monkeypatch.setattr(osv_mod, "_get_json", fail_if_called)

    result = osv_mod.run_osv(tmp_path, Policy())
    assert result.ok
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.HIGH  # degraded default
    assert result.findings[0].detail["osv_id"] == "GHSA-uncapped"


def test_detail_fetch_error_degrades_gracefully(tmp_path, monkeypatch):
    _write_npm_lock(tmp_path, {"some-pkg": "2.0.0"})

    monkeypatch.setattr(
        osv_mod, "_post_json",
        lambda url, payload: {"results": [{"vulns": [{"id": "GHSA-dead-beef-0000"}]}]},
    )

    def raise_detail_error(url):
        raise TimeoutError("detail fetch failed")

    monkeypatch.setattr(osv_mod, "_get_json", raise_detail_error)

    result = osv_mod.run_osv(tmp_path, Policy())
    # Missing detail must not crash the analyzer; it should still surface a
    # finding (falling back to defaults) rather than silently dropping it.
    assert result.ok
    assert len(result.findings) == 1
