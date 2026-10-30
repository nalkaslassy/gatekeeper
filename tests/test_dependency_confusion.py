from __future__ import annotations

import json

from gatekeeper_cli.analyzers.dependency_confusion import run_dependency_confusion
from gatekeeper_cli.models import Severity
from gatekeeper_cli.policy import Policy


def _policy(**kwargs):
    return Policy(
        dependency_confusion=Severity.HIGH,
        internal_npm_scopes=frozenset(kwargs.get("scopes", [])),
        internal_npm_packages=frozenset(kwargs.get("npm", [])),
        internal_pypi_packages=frozenset(kwargs.get("pypi", [])),
    )


def test_internal_npm_scope_without_scope_registry_is_flagged(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"@acme/private-lib": "1.0.0"}
    }))
    result = run_dependency_confusion(tmp_path, _policy(scopes=["@acme"]))
    assert [f.rule_id for f in result.findings] == [
        "gk:npm-dependency-confusion-exposure"
    ]


def test_internal_npm_scope_with_private_registry_is_not_flagged(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"@acme/private-lib": "1.0.0"}
    }))
    (tmp_path / ".npmrc").write_text("@acme:registry=https://npm.acme.example/\n")
    result = run_dependency_confusion(tmp_path, _policy(scopes=["@acme"]))
    assert result.findings == []


def test_internal_unscoped_npm_on_public_default_is_flagged(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"acme-internal": "2.0.0"}
    }))
    result = run_dependency_confusion(tmp_path, _policy(npm=["acme-internal"]))
    assert len(result.findings) == 1


def test_internal_python_with_extra_index_is_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://packages.acme.example/simple\n"
        "acme-internal==1.2.3\n"
    )
    result = run_dependency_confusion(tmp_path, _policy(pypi=["acme-internal"]))
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "gk:py-dependency-confusion-exposure"


def test_internal_python_with_private_primary_index_is_not_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://packages.acme.example/simple\n"
        "acme-internal==1.2.3\n"
    )
    result = run_dependency_confusion(tmp_path, _policy(pypi=["acme-internal"]))
    assert result.findings == []


def test_internal_python_direct_url_is_not_flagged(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "acme-internal @ https://packages.acme.example/acme-internal.whl\n"
    )
    result = run_dependency_confusion(tmp_path, _policy(pypi=["acme-internal"]))
    assert result.findings == []
