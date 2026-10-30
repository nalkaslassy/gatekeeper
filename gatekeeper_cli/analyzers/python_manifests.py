"""Shared parsing for Python dependency manifests beyond requirements.txt:
pyproject.toml's [project.dependencies], poetry.lock, and uv.lock.

Python 3.11+ uses the standard-library tomllib module. Python 3.10 uses
the small conditional tomli backport so manifest and lockfile coverage is
consistent across every Python version Gatekeeper supports.
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

_PEP508_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of -_. collapsed to a single -."""
    return re.sub(r"[-_.]+", "-", name.lower())


def pep508_name(spec: str) -> str:
    """Extract the bare package name from a PEP 508 dependency string like
    "typer[all]>=0.12; python_version >= '3.10'"."""
    m = _PEP508_NAME_RE.match(spec)
    return m.group(1) if m else spec.strip()


def requirement_line_name(line: str) -> str:
    """Extract the bare package name from a requirements.txt line."""
    m = _REQ_NAME_RE.match(line)
    return m.group(1) if m else line.strip()


def _load_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def parse_pyproject_dependencies(repo: Path) -> list[str]:
    """Return raw PEP 508 dependency strings from [project.dependencies]."""
    data = _load_toml(repo / "pyproject.toml")
    deps = (data.get("project") or {}).get("dependencies")
    return list(deps) if isinstance(deps, list) else []


def _parse_lock_packages(path: Path) -> dict[str, str]:
    """poetry.lock and uv.lock share the same top-level shape for this
    purpose: a TOML array of tables under `package`, each with `name` and
    `version`. Returns normalized-name -> resolved version."""
    data = _load_toml(path)
    out: dict[str, str] = {}
    for pkg in data.get("package") or []:
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if name and version:
            out[normalize_pypi_name(name)] = version
    return out


def resolved_versions(repo: Path) -> dict[str, str]:
    """Merge poetry.lock and uv.lock resolved versions (normalized name ->
    version). If both exist, uv.lock wins on conflict — it's the more
    recently-introduced tool and the one more likely to be the actively
    used one when both files are present."""
    merged = _parse_lock_packages(repo / "poetry.lock")
    merged.update(_parse_lock_packages(repo / "uv.lock"))
    return merged
