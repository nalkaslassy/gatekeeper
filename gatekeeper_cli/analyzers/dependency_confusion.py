"""Static dependency-confusion exposure checks.

Gatekeeper cannot prove that a private package name is currently registered on
a public registry without making a network request. This analyzer instead
checks the part we can verify offline: whether package names the team declares
as internal are statically bound to a private registry in repository config.

That catches the configuration precondition that makes dependency-confusion
attacks possible while preserving Gatekeeper's static-first/no-network mode.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import AnalyzerResult, Finding
from ..policy import Policy
from .python_manifests import normalize_pypi_name, parse_pyproject_dependencies, pep508_name

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _npm_deps(repo: Path) -> set[str]:
    path = repo / "package.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return set()
    if not isinstance(data, dict):
        return set()
    out: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            out.update(str(name) for name in section)
    return out


def _npmrc(repo: Path) -> tuple[str | None, dict[str, str]]:
    """Return (default_registry, scope_registry_map) from repository .npmrc."""
    path = repo / ".npmrc"
    default: str | None = None
    scoped: dict[str, str] = {}
    if not path.exists():
        return default, scoped
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return default, scoped
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key == "registry":
            default = value
        elif key.startswith("@") and key.endswith(":registry"):
            scoped[key[:-9]] = value
    return default, scoped


def _is_public_npm_registry(value: str | None) -> bool:
    if value is None:
        return True  # npm's implicit default is the public registry
    lower = value.lower()
    return "registry.npmjs.org" in lower or "npmjs.com" in lower


def _python_requirements(repo: Path) -> tuple[set[str], set[str], str | None, bool]:
    """Return (declared_names, direct_url_names, index_url, has_extra_index)."""
    names: set[str] = set()
    direct: set[str] = set()
    index_url: str | None = None
    has_extra = False
    path = repo / "requirements.txt"
    if not path.exists():
        return names, direct, index_url, has_extra
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return names, direct, index_url, has_extra

    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("--index-url"):
            parts = line.split(None, 1)
            index_url = parts[1].strip() if len(parts) == 2 else None
            continue
        if line.startswith("--extra-index-url"):
            has_extra = True
            continue
        if line.startswith(("-", "--")):
            continue
        match = _REQ_NAME_RE.match(line)
        if not match:
            continue
        name = normalize_pypi_name(match.group(1))
        names.add(name)
        if " @ " in line or line.startswith(f"{match.group(1)}@"):
            direct.add(name)
    return names, direct, index_url, has_extra


def _repo_pip_index(repo: Path) -> str | None:
    """Read a repository-local pip.conf if present."""
    for rel in ("pip.conf", ".config/pip/pip.conf"):
        path = repo / rel
        if not path.exists():
            continue
        try:
            for raw in path.read_text().splitlines():
                line = raw.strip()
                if line.lower().startswith("index-url") and "=" in line:
                    return line.split("=", 1)[1].strip()
        except OSError:
            continue
    return None


def _is_public_pypi(value: str | None) -> bool:
    if value is None:
        return True
    lower = value.lower()
    return "pypi.org" in lower or "pythonhosted.org" in lower


def run_dependency_confusion(repo: Path, policy: Policy) -> AnalyzerResult:
    name = "dependency_confusion"
    severity = policy.dependency_confusion
    if severity is None:
        return AnalyzerResult(name, ok=True, findings=[])

    findings: list[Finding] = []

    npm_deps = _npm_deps(repo)
    default_registry, scoped_registries = _npmrc(repo)

    for pkg in sorted(npm_deps):
        if pkg.startswith("@") and "/" in pkg:
            scope = pkg.split("/", 1)[0]
            if scope in policy.internal_npm_scopes and scope not in scoped_registries:
                findings.append(
                    Finding(
                        category="supply_chain",
                        rule_id="gk:npm-dependency-confusion-exposure",
                        severity=severity,
                        title=f"Internal npm scope '{scope}' is not bound to a private "
                              "registry in .npmrc — dependency resolution can fall back "
                              "to the public npm registry",
                        file_path=".npmrc" if (repo / ".npmrc").exists() else "package.json",
                        detail={"package": pkg, "scope": scope, "context": pkg},
                        analyzer=name,
                    )
                )
        elif pkg in policy.internal_npm_packages and _is_public_npm_registry(default_registry):
            findings.append(
                Finding(
                    category="supply_chain",
                    rule_id="gk:npm-dependency-confusion-exposure",
                    severity=severity,
                    title=f"Internal npm package '{pkg}' uses the public/default registry "
                          "because no private default registry is bound in .npmrc",
                    file_path=".npmrc" if (repo / ".npmrc").exists() else "package.json",
                    detail={"package": pkg, "context": pkg},
                    analyzer=name,
                )
            )

    req_names, direct_names, req_index, has_extra = _python_requirements(repo)
    pyproject_names = {
        normalize_pypi_name(pep508_name(spec))
        for spec in parse_pyproject_dependencies(repo)
    }
    repo_index = req_index or _repo_pip_index(repo)

    for pkg in sorted(policy.internal_pypi_packages & (req_names | pyproject_names)):
        if pkg in direct_names:
            continue
        if has_extra or _is_public_pypi(repo_index):
            source = "requirements.txt" if pkg in req_names else "pyproject.toml"
            reason = (
                "requirements.txt uses --extra-index-url, so pip may choose a "
                "higher-version public package with the same name"
                if has_extra
                else "the repository does not statically bind pip to a private index"
            )
            findings.append(
                Finding(
                    category="supply_chain",
                    rule_id="gk:py-dependency-confusion-exposure",
                    severity=severity,
                    title=f"Internal Python package '{pkg}' is exposed to dependency "
                          f"confusion: {reason}",
                    file_path=source,
                    detail={"package": pkg, "context": pkg},
                    analyzer=name,
                )
            )

    return AnalyzerResult(name, ok=True, findings=findings)
