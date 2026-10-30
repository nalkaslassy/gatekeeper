from __future__ import annotations

import json

from gatekeeper_cli.trust import (
    TRUST_FILENAME,
    build_trust_snapshot,
    compare_repo_to_baseline,
    compare_trust_snapshots,
    write_trust_snapshot,
)


def _pkg(snapshot, ecosystem, name):
    return next(
        p for p in snapshot["packages"]
        if p["ecosystem"] == ecosystem and p["name"] == name
    )


def test_snapshot_records_npm_install_script_and_directness(fixture_repo):
    repo = fixture_repo("npm_install_script")
    snap = build_trust_snapshot(repo)
    shady = _pkg(snap, "npm", "shady-pkg")
    assert shady["version"] == "1.0.0"
    assert shady["direct"] is True
    assert shady["install_script"] is True


def test_snapshot_records_python_exact_pins(fixture_repo):
    repo = fixture_repo("clean")
    snap = build_trust_snapshot(repo)
    assert _pkg(snap, "pypi", "numpy")["version"] == "1.26.0"
    assert _pkg(snap, "pypi", "requests")["version"] == "2.31.0"


def test_write_and_compare_trust_baseline_detects_new_install_script(fixture_repo):
    repo = fixture_repo("clean")
    write_trust_snapshot(repo)
    assert (repo / TRUST_FILENAME).exists()

    lock = repo / "package-lock.json"
    data = json.loads(lock.read_text())
    data["packages"]["node_modules/left-pad"]["hasInstallScript"] = True
    lock.write_text(json.dumps(data))

    diff = compare_repo_to_baseline(repo)
    rules = {event["rule"] for event in diff["risk_events"]}
    assert "install-script-added" in rules


def test_same_version_integrity_change_is_critical():
    old = {
        "schema_version": 1,
        "generated_at": "old",
        "summary": {"package_count": 1},
        "packages": [{
            "ecosystem": "npm", "name": "x", "version": "1.0.0",
            "direct": True, "source": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
            "source_kind": "registry", "integrity": "sha512-old",
            "install_script": False, "dependency_count": 0,
        }],
    }
    new = json.loads(json.dumps(old))
    new["generated_at"] = "new"
    new["packages"][0]["integrity"] = "sha512-new"

    diff = compare_trust_snapshots(old, new)
    event = next(e for e in diff["risk_events"] if e["rule"] == "integrity-changed-same-version")
    assert event["severity"] == "critical"


def test_new_direct_git_dependency_is_high_risk(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"internal-lib": "git+https://github.com/acme/internal-lib.git"}
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/internal-lib": {
                "version": "1.0.0",
                "resolved": "git+https://github.com/acme/internal-lib.git",
            },
        },
    }))

    empty = {
        "schema_version": 1,
        "generated_at": "old",
        "summary": {"package_count": 0},
        "packages": [],
    }
    diff = compare_trust_snapshots(empty, build_trust_snapshot(tmp_path))
    event = next(e for e in diff["risk_events"] if e["rule"] == "new-direct-nonregistry-source")
    assert event["severity"] == "high"


def test_required_dependency_edge_addition_is_medium_risk():
    old = {
        "schema_version": 1,
        "generated_at": "old",
        "summary": {"package_count": 1},
        "packages": [{
            "ecosystem": "npm", "name": "event-stream", "version": "3.3.4",
            "direct": True, "source": None, "source_kind": "registry",
            "integrity": None, "install_script": False,
            "dependency_count": 7,
            "required_dependencies": ["through", "split"],
        }],
    }
    new = {
        "schema_version": 1,
        "generated_at": "new",
        "summary": {"package_count": 2},
        "packages": [{
            "ecosystem": "npm", "name": "event-stream", "version": "3.3.6",
            "direct": True, "source": None, "source_kind": "registry",
            "integrity": None, "install_script": False,
            "dependency_count": 8,
            "required_dependencies": ["through", "split", "flatmap-stream"],
        }, {
            "ecosystem": "npm", "name": "flatmap-stream", "version": "0.1.1",
            "direct": False, "source": None, "source_kind": "registry",
            "integrity": None, "install_script": False,
            "dependency_count": 0,
            "required_dependencies": [],
        }],
    }

    diff = compare_trust_snapshots(old, new)
    event = next(
        e for e in diff["risk_events"] if e["rule"] == "required-dependency-added"
    )
    assert event["severity"] == "medium"
    assert event["package"] == "event-stream"
    assert "flatmap-stream" in event["message"]


def test_old_snapshots_without_required_dependencies_remain_compatible():
    old = {
        "schema_version": 1,
        "generated_at": "old",
        "summary": {"package_count": 1},
        "packages": [{
            "ecosystem": "npm", "name": "x", "version": "1.0.0",
            "direct": True, "source": None, "source_kind": "registry",
            "integrity": None, "install_script": False, "dependency_count": 0,
        }],
    }
    new = {
        "schema_version": 1,
        "generated_at": "new",
        "summary": {"package_count": 1},
        "packages": [{
            "ecosystem": "npm", "name": "x", "version": "1.1.0",
            "direct": True, "source": None, "source_kind": "registry",
            "integrity": None, "install_script": False, "dependency_count": 1,
            "required_dependencies": ["y"],
        }],
    }

    diff = compare_trust_snapshots(old, new)
    assert "required-dependency-added" not in {
        e["rule"] for e in diff["risk_events"]
    }
