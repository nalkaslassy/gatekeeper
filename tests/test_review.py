from __future__ import annotations

import json

import pytest

from gatekeeper_cli.review import review_repository
from gatekeeper_cli.trust import write_trust_snapshot


def test_review_passes_when_trusted_state_is_unchanged(fixture_repo):
    repo = fixture_repo("clean")
    write_trust_snapshot(repo)

    result = review_repository(repo)

    assert result["decision"] == "pass"
    assert result["mode"] == "offline"
    assert result["summary"]["risk_events"] == 0


def test_review_marks_medium_dependency_edge_drift_for_review(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"parent": "1.1.0", "child": "1.0.0"}
    }))
    old_lock = {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/parent": {
                "version": "1.0.0",
                "dependencies": {},
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(old_lock))
    write_trust_snapshot(tmp_path)

    new_lock = {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/parent": {
                "version": "1.1.0",
                "dependencies": {"child": "1.0.0"},
            },
            "node_modules/child": {
                "version": "1.0.0",
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(new_lock))

    result = review_repository(tmp_path)

    assert result["decision"] == "review"
    assert "required-dependency-added" in {e["rule"] for e in result["events"]}


def test_review_blocks_high_trust_drift(fixture_repo):
    repo = fixture_repo("clean")
    write_trust_snapshot(repo)

    lock = repo / "package-lock.json"
    data = json.loads(lock.read_text())
    data["packages"]["node_modules/left-pad"]["hasInstallScript"] = True
    lock.write_text(json.dumps(data))

    result = review_repository(repo)

    assert result["decision"] == "block"
    assert "install-script-added" in {e["rule"] for e in result["events"]}


def test_online_content_reviews_changed_npm_version(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"demo": "1.0.0"}
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "x",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "x"},
            "node_modules/demo": {"version": "1.0.0"},
        },
    }))
    write_trust_snapshot(tmp_path)

    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "x",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "x"},
            "node_modules/demo": {"version": "1.1.0"},
        },
    }))

    calls = []

    def fake_inspector(package, baseline_version, candidate_version, registry):
        calls.append((package, baseline_version, candidate_version, registry))
        return {
            "diff": {
                "risk_events": [{
                    "severity": "high",
                    "rule": "content-subprocess-execution",
                    "message": "New subprocess capability.",
                }]
            }
        }

    result = review_repository(
        tmp_path,
        online_content=True,
        npm_inspector=fake_inspector,
    )

    assert calls == [
        ("demo", "1.0.0", "1.1.0", "https://registry.npmjs.org")
    ]
    assert result["summary"]["content_checks"] == 1
    assert result["decision"] == "block"
    assert "content-subprocess-execution" in {
        e["rule"] for e in result["events"]
    }


def test_online_content_failure_fails_closed(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"demo": "1.0.0"}
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "x",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "x"},
            "node_modules/demo": {"version": "1.0.0"},
        },
    }))
    write_trust_snapshot(tmp_path)
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "x",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "x"},
            "node_modules/demo": {"version": "1.1.0"},
        },
    }))

    def fail(*args, **kwargs):
        raise ValueError("registry unavailable")

    with pytest.raises(ValueError, match="online content inspection failed"):
        review_repository(
            tmp_path,
            online_content=True,
            npm_inspector=fail,
        )
