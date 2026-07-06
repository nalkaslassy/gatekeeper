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
