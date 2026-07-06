from __future__ import annotations

from gatekeeper_cli.analyzers.python_manifests import normalize_pypi_name
from gatekeeper_cli.analyzers.typosquat import _closest_match, _edit_distance, run_typosquat
from gatekeeper_cli.policy import Policy


def test_edit_distance_identical_strings():
    assert _edit_distance("express", "express") == 0


def test_edit_distance_single_substitution():
    assert _edit_distance("expres", "express") == 1  # missing trailing s = 1 insertion


def test_edit_distance_transposition_counts_as_one():
    assert _edit_distance("lodahs", "lodash") == 1  # adjacent transposition (h/s swapped)


def test_edit_distance_unrelated_strings_large():
    assert _edit_distance("react", "django") >= 4


def test_closest_match_returns_none_for_exact_popular_name():
    from gatekeeper_cli.analyzers.popular_packages import POPULAR_NPM_PACKAGES

    assert _closest_match("express", POPULAR_NPM_PACKAGES) is None


def test_closest_match_flags_distance_one_lookalike():
    from gatekeeper_cli.analyzers.popular_packages import POPULAR_NPM_PACKAGES

    match = _closest_match("expres", POPULAR_NPM_PACKAGES)
    assert match is not None
    name, dist = match
    assert name == "express"
    assert dist == 1


def test_normalize_pypi_treats_separators_as_equivalent():
    assert normalize_pypi_name("Foo_Bar") == normalize_pypi_name("foo-bar") == "foo-bar"
    assert normalize_pypi_name("Foo.Bar") == "foo-bar"


def test_run_typosquat_flags_npm_lookalike(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    result = run_typosquat(repo, Policy())
    assert result.ok
    rule_ids = [f.rule_id for f in result.findings]
    assert "gk:npm-possible-typosquat" in rule_ids
    hit = next(f for f in result.findings if f.rule_id == "gk:npm-possible-typosquat")
    assert hit.detail["package"] == "expres"
    assert hit.detail["similar_to"] == "express"


def test_run_typosquat_leaves_real_dependency_alone(fixture_repo):
    repo = fixture_repo("clean")
    result = run_typosquat(repo, Policy())
    assert result.findings == []


def test_typosquat_disabled_via_policy(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    result = run_typosquat(repo, Policy(typosquat=None))
    assert result.findings == []


def test_short_names_are_skipped(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"ws": "^1.0.0"}}')
    result = run_typosquat(tmp_path, Policy())
    assert result.findings == []


def test_typosquat_allowlist_suppresses_npm_finding(fixture_repo):
    repo = fixture_repo("bad_typosquat")
    result = run_typosquat(repo, Policy(typosquat_allow=frozenset({"expres"})))
    assert result.findings == []


def test_typosquat_allowlist_suppresses_pypi_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("reqeusts==2.31.0\n")
    result = run_typosquat(tmp_path, Policy(typosquat_allow=frozenset({"reqeusts"})))
    assert result.findings == []


def test_scope_typosquat_detected(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@type/lodash": "^1.0.0"}}'
    )
    result = run_typosquat(tmp_path, Policy())
    hits = [f for f in result.findings if f.rule_id == "gk:npm-scope-typosquat"]
    assert len(hits) == 1
    assert hits[0].detail["package"] == "@type/lodash"
    assert hits[0].detail["similar_to"] == "@types/..."


def test_known_scope_not_flagged_as_scope_typosquat(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@types/lodash": "^1.0.0"}}'
    )
    result = run_typosquat(tmp_path, Policy())
    assert not any(f.rule_id == "gk:npm-scope-typosquat" for f in result.findings)


def test_scoped_package_flags_typosquat_of_unscoped_popular_name(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@myorg/expres": "^1.0.0"}}'
    )
    result = run_typosquat(tmp_path, Policy())
    hits = [f for f in result.findings if f.rule_id == "gk:npm-possible-typosquat"]
    assert len(hits) == 1
    assert hits[0].detail["package"] == "@myorg/expres"
    assert hits[0].detail["similar_to"] == "express"


def test_scoped_legitimate_package_not_flagged(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@babel/core": "^7.0.0"}}'
    )
    result = run_typosquat(tmp_path, Policy())
    assert result.findings == []
