"""CycloneDX SBOM generation from dependency files.

The generator is deliberately static: it reads lockfiles/manifests and never
executes project code or performs network requests.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .analyzers.python_manifests import normalize_pypi_name, resolved_versions

_REQ_PIN_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)")


def _purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == "npm":
        # purl uses @scope/name directly; only the slash needs percent-encoding.
        encoded = name.replace("/", "%2F")
        return f"pkg:npm/{encoded}@{version}"
    return f"pkg:pypi/{normalize_pypi_name(name)}@{version}"


def _component(ecosystem: str, name: str, version: str) -> dict:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": _purl(ecosystem, name, version),
        "properties": [{"name": "gatekeeper:ecosystem", "value": ecosystem}],
    }


def _npm_components(repo: Path) -> list[dict]:
    lock = repo / "package-lock.json"
    if not lock.exists():
        return []
    try:
        data = json.loads(lock.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    out: list[dict] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not pkg_path or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version or "node_modules/" not in pkg_path:
                continue
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            out.append(_component("npm", name, str(version)))
        return out

    # npm lockfileVersion 1 fallback.
    def walk(deps: dict) -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version:
                out.append(_component("npm", name, str(version)))
            child = meta.get("dependencies")
            if isinstance(child, dict):
                walk(child)

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        walk(deps)
    return out


def _python_components(repo: Path) -> list[dict]:
    versions = dict(resolved_versions(repo))

    req = repo / "requirements.txt"
    if req.exists():
        try:
            for raw in req.read_text().splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith(("-", "--")):
                    continue
                match = _REQ_PIN_RE.match(line)
                if match:
                    versions.setdefault(normalize_pypi_name(match.group(1)), match.group(2))
        except OSError:
            pass

    return [_component("pypi", name, version) for name, version in versions.items()]


def generate_sbom(repo: Path) -> dict:
    """Return a CycloneDX 1.6 JSON SBOM for dependencies visible statically."""
    components = _npm_components(repo) + _python_components(repo)

    # Stable ordering/dedup makes generated output review-friendly.
    unique: dict[tuple[str, str, str], dict] = {}
    for comp in components:
        ecosystem = next(
            (p["value"] for p in comp.get("properties", [])
             if p.get("name") == "gatekeeper:ecosystem"),
            "",
        )
        unique[(ecosystem, comp["name"], comp["version"])] = comp
    ordered = [unique[key] for key in sorted(unique)]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "gatekeeper-cli",
                }]
            },
        },
        "components": ordered,
    }
