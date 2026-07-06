from __future__ import annotations

import sys

import pytest

from gatekeeper_cli.analyzers import run_lockfile, run_typosquat
from gatekeeper_cli.analyzers.python_manifests import (
    parse_pyproject_dependencies,
    pep508_name,
    resolved_versions,
)
from gatekeeper_cli.policy import Policy

TOMLLIB_UNAVAILABLE = sys.version_info < (3, 11)
skip_no_tomllib = pytest.mark.skipif(
    TOMLLIB_UNAVAILABLE, reason="tomllib is stdlib-only from Python 3.11"
)


@skip_no_tomllib
def test_parse_pyproject_dependencies(fixture_repo):
    repo = fixture_repo("pyproject_unpinned")
    deps = parse_pyproject_dependencies(repo)
    assert "flask>=2.0" in deps
    assert "requests==2.31.0" in deps


def test_parse_pyproject_dependencies_missing_file(tmp_path):
    assert parse_pyproject_dependencies(tmp_path) == []


def test_pep508_name_strips_specifiers_and_markers():
    assert pep508_name("flask>=2.0") == "flask"
    assert pep508_name("typer[all]>=0.12; python_version >= '3.10'") == "typer"
    assert pep508_name("requests==2.31.0") == "requests"


@skip_no_tomllib
def test_resolved_versions_from_poetry_lock(fixture_repo):
    repo = fixture_repo("pyproject_poetry_pinned")
    resolved = resolved_versions(repo)
    assert resolved["flask"] == "3.0.3"
    assert resolved["werkzeug"] == "3.0.1"


@skip_no_tomllib
def test_resolved_versions_from_uv_lock(fixture_repo):
    repo = fixture_repo("pyproject_uv_pinned")
    resolved = resolved_versions(repo)
    assert resolved["flask"] == "3.0.3"


def test_resolved_versions_missing_lockfiles(tmp_path):
    assert resolved_versions(tmp_path) == {}


# --------------------------------------------------------------------------
# lockfile analyzer: unpinned-dependency check across pyproject.toml/lockfiles
# --------------------------------------------------------------------------

@skip_no_tomllib
def test_pyproject_unpinned_dep_flagged_without_lockfile(fixture_repo):
    repo = fixture_repo("pyproject_unpinned")
    result = run_lockfile(repo, Policy())
    findings = [f for f in result.findings if f.rule_id == "gk:py-unpinned-dependency"]
    contexts = {f.detail["context"] for f in findings}
    assert "flask>=2.0" in contexts
    assert "requests==2.31.0" not in contexts  # exact-pinned in pyproject.toml itself


@skip_no_tomllib
def test_pyproject_dep_not_flagged_when_poetry_lock_pins_it(fixture_repo):
    repo = fixture_repo("pyproject_poetry_pinned")
    result = run_lockfile(repo, Policy())
    findings = [f for f in result.findings if f.rule_id == "gk:py-unpinned-dependency"]
    assert findings == []  # flask>=2.0 is unpinned in pyproject.toml, but poetry.lock resolves it


@skip_no_tomllib
def test_requirements_txt_dep_not_flagged_when_uv_lock_pins_it(fixture_repo):
    repo = fixture_repo("pyproject_uv_pinned")
    result = run_lockfile(repo, Policy())
    findings = [f for f in result.findings if f.rule_id == "gk:py-unpinned-dependency"]
    assert findings == []  # "flask" (bare, in requirements.txt) is resolved by uv.lock


# --------------------------------------------------------------------------
# typosquat analyzer: also reads pyproject.toml
# --------------------------------------------------------------------------

@skip_no_tomllib
def test_typosquat_detects_pyproject_dependency(fixture_repo):
    repo = fixture_repo("pyproject_typosquat")
    result = run_typosquat(repo, Policy())
    hit = next(f for f in result.findings if f.rule_id == "gk:py-possible-typosquat")
    assert hit.detail["package"] == "reqeusts"
    assert hit.detail["similar_to"] == "requests"
    assert hit.file_path == "pyproject.toml"


# --------------------------------------------------------------------------
# osv analyzer: pyproject.toml + lockfile precedence over requirements.txt
# --------------------------------------------------------------------------

def test_osv_pypi_packages_prefers_lockfile_over_requirements_txt(fixture_repo, monkeypatch):
    import gatekeeper_cli.analyzers.osv as osv_mod

    repo = fixture_repo("pyproject_uv_pinned")  # requirements.txt has bare "flask"
    # requirements.txt alone contributes no version (unpinned); uv.lock does.
    packages = osv_mod._pypi_packages(repo)
    versions = dict(packages)
    if TOMLLIB_UNAVAILABLE:
        assert versions == {}  # can't read uv.lock without tomllib on 3.10
    else:
        assert versions["flask"] == "3.0.3"


def test_osv_pypi_packages_lockfile_overrides_conflicting_requirements_pin(
    fixture_repo, tmp_path
):
    import gatekeeper_cli.analyzers.osv as osv_mod

    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
    if not TOMLLIB_UNAVAILABLE:
        (tmp_path / "uv.lock").write_text(
            '[[package]]\nname = "flask"\nversion = "3.0.3"\n'
        )
        versions = dict(osv_mod._pypi_packages(tmp_path))
        assert versions["flask"] == "3.0.3"  # lockfile wins over requirements.txt pin
