from __future__ import annotations

import json

from gatekeeper_cli.analyzers import run_lockfile
from gatekeeper_cli.models import Severity
from gatekeeper_cli.policy import Policy
from gatekeeper_cli.runner import run_scan, write_baseline


def _rule_ids(findings):
    return [f.rule_id for f in findings]


def test_missing_lockfile_flagged(fixture_repo):
    repo = fixture_repo("missing_lockfile")
    result = run_lockfile(repo, Policy())
    assert result.ok
    assert "gk:npm-missing-lockfile" in _rule_ids(result.findings)


def test_yarn_lock_satisfies_missing_lockfile_check(fixture_repo):
    repo = fixture_repo("yarn_only")
    result = run_lockfile(repo, Policy())
    assert "gk:npm-missing-lockfile" not in _rule_ids(result.findings)


def test_pnpm_lock_satisfies_missing_lockfile_check(fixture_repo):
    repo = fixture_repo("pnpm_only")
    result = run_lockfile(repo, Policy())
    assert "gk:npm-missing-lockfile" not in _rule_ids(result.findings)


def test_npm_v3_has_install_script_detected(fixture_repo):
    repo = fixture_repo("npm_install_script")
    result = run_lockfile(repo, Policy())
    findings = [f for f in result.findings if f.rule_id == "gk:npm-install-script"]
    assert len(findings) == 1
    assert findings[0].detail["package"] == "shady-pkg"
    assert findings[0].detail["version"] == "1.0.0"
    assert findings[0].severity == Severity.MEDIUM  # default mode: warn


def test_pnpm_requires_build_detected(fixture_repo):
    repo = fixture_repo("pnpm_only")
    result = run_lockfile(repo, Policy())
    findings = [f for f in result.findings if f.rule_id == "gk:npm-install-script"]
    assert len(findings) == 1
    assert findings[0].detail["package"] == "node-sass"
    assert findings[0].detail["version"] == "9.0.0"
    assert findings[0].file_path == "pnpm-lock.yaml"
    # left-pad has no requiresBuild flag and must not be flagged
    assert all(f.detail["package"] != "left-pad" for f in findings)


def test_npm_lockfile_v1_flagged_for_upgrade(fixture_repo):
    repo = fixture_repo("npm_lockfile_v1")
    result = run_lockfile(repo, Policy())
    v1_findings = [f for f in result.findings if f.rule_id == "gk:npm-lockfile-v1"]
    assert len(v1_findings) == 1
    assert v1_findings[0].severity == Severity.LOW
    assert v1_findings[0].file_path == "package-lock.json"
    # v1 still satisfies "has a lockfile" — no missing-lockfile finding too
    assert "gk:npm-missing-lockfile" not in _rule_ids(result.findings)


def test_npm_lockfile_v1_does_not_crash_install_script_scan(fixture_repo):
    repo = fixture_repo("npm_lockfile_v1")
    # v1 has no "packages" map; the install-script scan must just find
    # nothing there rather than erroring.
    result = run_lockfile(repo, Policy(install_scripts="block"))
    assert result.ok
    assert "gk:npm-install-script" not in _rule_ids(result.findings)


def test_install_scripts_allow_suppresses_finding(fixture_repo):
    repo = fixture_repo("npm_install_script")
    pol = Policy(install_scripts="allow")
    result = run_lockfile(repo, pol)
    assert "gk:npm-install-script" not in _rule_ids(result.findings)


def test_install_scripts_block_is_high_severity(fixture_repo):
    repo = fixture_repo("npm_install_script")
    pol = Policy(install_scripts="block")
    result = run_lockfile(repo, pol)
    findings = [f for f in result.findings if f.rule_id == "gk:npm-install-script"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_unpinned_and_pinned_requirements(fixture_repo):
    repo = fixture_repo("requirements_mixed")
    result = run_lockfile(repo, Policy())
    unpinned = [f for f in result.findings if f.rule_id == "gk:py-unpinned-dependency"]
    packages_flagged = {f.detail["context"] for f in unpinned}
    assert "flask" in packages_flagged
    assert "requests>=2.0" in packages_flagged
    assert not any("numpy" in p for p in packages_flagged)
    assert not any("pandas" in p for p in packages_flagged)
    assert len(unpinned) == 2


def test_fingerprint_regression_version_bump_resurfaces_after_baseline(fixture_repo, tmp_path):
    """The exact scenario this fix targets: an install-script package is
    baselined at version X; it's later compromised in-place and bumped to
    version Y while keeping hasInstallScript true. The finding must come
    back as is_new=True even though a version of "this package has an
    install script" was already accepted."""
    repo = fixture_repo("npm_install_script")
    pol = Policy(analyzers={"lockfile": {"enabled": True}}, install_scripts="warn")

    baseline_result = run_scan(repo, pol, only=["lockfile"])
    write_baseline(repo, baseline_result)

    # rescan unchanged: the finding should now be known
    rescan = run_scan(repo, pol, only=["lockfile"])
    install_findings = [f for f in rescan["findings"] if f["rule_id"] == "gk:npm-install-script"]
    assert len(install_findings) == 1
    assert install_findings[0]["is_new"] is False

    # simulate an in-place compromise: same package, bumped version, still hasInstallScript
    lock_path = repo / "package-lock.json"
    data = json.loads(lock_path.read_text())
    data["packages"]["node_modules/shady-pkg"]["version"] = "1.0.1"
    lock_path.write_text(json.dumps(data))

    compromised_scan = run_scan(repo, pol, only=["lockfile"])
    compromised_findings = [
        f for f in compromised_scan["findings"] if f["rule_id"] == "gk:npm-install-script"
    ]
    assert len(compromised_findings) == 1
    assert compromised_findings[0]["is_new"] is True
    assert compromised_findings[0]["detail"]["version"] == "1.0.1"
