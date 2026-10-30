from __future__ import annotations

import json

from typer.testing import CliRunner

from gatekeeper_cli.main import app
from gatekeeper_cli.sbom import generate_sbom

runner = CliRunner()


def _names(doc):
    return {(c["name"], c["version"]) for c in doc["components"]}


def test_generate_sbom_from_npm_and_requirements(fixture_repo):
    repo = fixture_repo("clean")
    doc = generate_sbom(repo)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert ("left-pad", "1.3.0") in _names(doc)
    assert ("numpy", "1.26.0") in _names(doc)
    assert ("requests", "2.31.0") in _names(doc)


def test_generate_sbom_from_poetry_lock(fixture_repo):
    repo = fixture_repo("pyproject_poetry_pinned")
    doc = generate_sbom(repo)
    assert ("flask", "3.0.3") in _names(doc)
    assert ("werkzeug", "3.0.1") in _names(doc)


def test_sbom_cli_writes_cyclonedx_json(fixture_repo, tmp_path):
    repo = fixture_repo("clean")
    output = tmp_path / "bom.cdx.json"
    result = runner.invoke(app, ["sbom", str(repo), "--output", str(output)])

    assert result.exit_code == 0, result.output
    doc = json.loads(output.read_text())
    assert doc["bomFormat"] == "CycloneDX"
    assert len(doc["components"]) >= 3
