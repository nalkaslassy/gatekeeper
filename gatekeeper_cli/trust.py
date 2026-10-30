"""Change-aware dependency trust snapshots and drift analysis.

Trust snapshots are static and deterministic aside from generated_at: they read
manifests/lockfiles only, execute no target code, and make no network requests.
A committed .gatekeeper-trust.json records the dependency posture a team
reviewed. Later scans compare the current posture and surface security-relevant
changes ("trust drift") rather than treating every version bump as equally risky.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzers.python_manifests import (
    normalize_pypi_name,
    parse_pyproject_dependencies,
    pep508_name,
    resolved_versions,
)

TRUST_FILENAME = ".gatekeeper-trust.json"
TRUST_SCHEMA_VERSION = 1

_REQ_PIN_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)")
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _source_kind(source: str | None, ecosystem: str) -> str:
    if not source:
        return "registry"
    value = source.lower()
    if value.startswith(("git+", "git://", "git@", "github:", "gitlab:", "bitbucket:")):
        return "git"
    if ecosystem == "npm" and "registry.npmjs.org" in value:
        return "registry"
    if ecosystem == "pypi" and ("pypi.org" in value or "pythonhosted.org" in value):
        return "registry"
    if value.startswith(("http://", "https://", "file:", "../", "./", "/")):
        return "url"
    return "other"


def _npm_direct_names(repo: Path) -> set[str]:
    path = repo / "package.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return set()
    if not isinstance(data, dict):
        return set()
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            names.update(str(name) for name in section)
    return names


def _npm_snapshot(repo: Path) -> list[dict[str, Any]]:
    lock = repo / "package-lock.json"
    if not lock.exists():
        return []
    try:
        data = json.loads(lock.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    direct = _npm_direct_names(repo)
    packages = data.get("packages")
    out: list[dict[str, Any]] = []

    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not pkg_path or not isinstance(meta, dict) or "node_modules/" not in pkg_path:
                continue
            version = meta.get("version")
            if version is None:
                continue
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            source = meta.get("resolved")
            deps = meta.get("dependencies")
            optional = meta.get("optionalDependencies")
            peer = meta.get("peerDependencies")
            dep_count = sum(
                len(section) for section in (deps, optional, peer)
                if isinstance(section, dict)
            )
            out.append({
                "ecosystem": "npm",
                "name": name,
                "version": str(version),
                "direct": name in direct,
                "source": source,
                "source_kind": _source_kind(source, "npm"),
                "integrity": meta.get("integrity"),
                "install_script": bool(meta.get("hasInstallScript", False)),
                "dependency_count": dep_count,
            })
        return out

    # npm lockfileVersion 1 fallback.
    def walk(deps: dict[str, Any], top_level: bool = False) -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version is not None:
                source = meta.get("resolved")
                child = meta.get("dependencies")
                out.append({
                    "ecosystem": "npm",
                    "name": name,
                    "version": str(version),
                    "direct": top_level or name in direct,
                    "source": source,
                    "source_kind": _source_kind(source, "npm"),
                    "integrity": meta.get("integrity"),
                    "install_script": None,
                    "dependency_count": len(child) if isinstance(child, dict) else 0,
                })
            child = meta.get("dependencies")
            if isinstance(child, dict):
                walk(child)

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        walk(deps, top_level=True)
    return out


def _python_direct_and_sources(repo: Path) -> tuple[set[str], dict[str, str]]:
    direct: set[str] = set()
    sources: dict[str, str] = {}

    req = repo / "requirements.txt"
    if req.exists():
        try:
            lines = req.read_text().splitlines()
        except OSError:
            lines = []
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "--")):
                continue
            match = _REQ_NAME_RE.match(line)
            if not match:
                continue
            name = normalize_pypi_name(match.group(1))
            direct.add(name)
            if " @ " in line:
                sources[name] = line.split(" @ ", 1)[1].strip()

    for spec in parse_pyproject_dependencies(repo):
        name = normalize_pypi_name(pep508_name(spec))
        direct.add(name)
        if " @ " in spec:
            sources[name] = spec.split(" @ ", 1)[1].split(";", 1)[0].strip()

    return direct, sources


def _python_snapshot(repo: Path) -> list[dict[str, Any]]:
    direct, sources = _python_direct_and_sources(repo)
    versions = dict(resolved_versions(repo))

    req = repo / "requirements.txt"
    if req.exists():
        try:
            lines = req.read_text().splitlines()
        except OSError:
            lines = []
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "--")):
                continue
            match = _REQ_PIN_RE.match(line)
            if match:
                versions.setdefault(
                    normalize_pypi_name(match.group(1)), match.group(2)
                )

    out: list[dict[str, Any]] = []
    for name, version in versions.items():
        source = sources.get(name)
        out.append({
            "ecosystem": "pypi",
            "name": name,
            "version": str(version),
            "direct": name in direct,
            "source": source,
            "source_kind": _source_kind(source, "pypi"),
            "integrity": None,
            "install_script": None,
            "dependency_count": None,
        })
    return out


def build_trust_snapshot(repo: Path) -> dict[str, Any]:
    packages = _npm_snapshot(repo) + _python_snapshot(repo)
    packages.sort(key=lambda p: (p["ecosystem"], p["name"], p["version"]))
    direct_count = sum(1 for p in packages if p["direct"])
    return {
        "schema_version": TRUST_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "package_count": len(packages),
            "direct_count": direct_count,
            "transitive_count": len(packages) - direct_count,
        },
        "packages": packages,
    }


def write_trust_snapshot(repo: Path, snapshot: dict[str, Any] | None = None) -> Path:
    path = repo / TRUST_FILENAME
    doc = snapshot or build_trust_snapshot(repo)
    path.write_text(json.dumps(doc, indent=2) + "\n")
    return path


def load_trust_snapshot(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"Invalid trust snapshot {path}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != TRUST_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported trust snapshot schema in {path}; "
            f"expected schema_version={TRUST_SCHEMA_VERSION}"
        )
    if not isinstance(doc.get("packages"), list):
        raise ValueError(f"Invalid trust snapshot {path}: packages must be a list")
    return doc


def _index(snapshot: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for package in snapshot.get("packages", []):
        if not isinstance(package, dict):
            continue
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if ecosystem and name:
            out[(str(ecosystem), str(name))] = package
    return out


def compare_trust_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    old = _index(baseline)
    new = _index(current)
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    changed: list[dict[str, Any]] = []
    risk_events: list[dict[str, Any]] = []

    for key in sorted(old.keys() & new.keys()):
        before, after = old[key], new[key]
        fields: dict[str, dict[str, Any]] = {}
        for field in (
            "version", "source", "source_kind", "integrity",
            "install_script", "dependency_count", "direct",
        ):
            if before.get(field) != after.get(field):
                fields[field] = {"before": before.get(field), "after": after.get(field)}
        if not fields:
            continue
        entry = {
            "ecosystem": key[0],
            "name": key[1],
            "before_version": before.get("version"),
            "after_version": after.get("version"),
            "changes": fields,
        }
        changed.append(entry)

        if (
            "integrity" in fields
            and before.get("version") == after.get("version")
            and before.get("integrity")
            and after.get("integrity")
        ):
            risk_events.append(_event(
                "critical", "integrity-changed-same-version", after,
                "Integrity hash changed without a version change; the same package "
                "version now resolves to different bytes.",
            ))
        if "source_kind" in fields:
            risk_events.append(_event(
                "high", "source-kind-changed", after,
                f"Package source changed from {before.get('source_kind')} "
                f"to {after.get('source_kind')}.",
            ))
        elif (
            "source" in fields
            and before.get("version") == after.get("version")
            and before.get("source")
            and after.get("source")
        ):
            risk_events.append(_event(
                "high", "source-changed-same-version", after,
                "Package source URL changed without a version change.",
            ))
        if before.get("install_script") is False and after.get("install_script") is True:
            risk_events.append(_event(
                "high", "install-script-added", after,
                "A lifecycle install script appeared in a dependency that previously "
                "did not require install-time code execution.",
            ))

        old_count = before.get("dependency_count")
        new_count = after.get("dependency_count")
        if isinstance(old_count, int) and isinstance(new_count, int):
            delta = new_count - old_count
            if delta >= 20:
                risk_events.append(_event(
                    "high" if delta >= 50 else "medium",
                    "package-dependency-expansion", after,
                    f"Package dependency metadata expanded by {delta} entries "
                    f"({old_count} -> {new_count}).",
                ))

    for package in added:
        if package.get("direct") and package.get("source_kind") in {"git", "url", "other"}:
            risk_events.append(_event(
                "high", "new-direct-nonregistry-source", package,
                f"New direct dependency comes from a {package.get('source_kind')} "
                "source instead of the package registry.",
            ))
        if package.get("install_script") is True:
            risk_events.append(_event(
                "medium", "new-package-with-install-script", package,
                "New dependency executes lifecycle code during installation.",
            ))

    old_total = int((baseline.get("summary") or {}).get("package_count", len(old)))
    new_total = int((current.get("summary") or {}).get("package_count", len(new)))
    total_delta = new_total - old_total
    if total_delta >= 20:
        risk_events.append({
            "severity": "high" if total_delta >= 50 else "medium",
            "rule": "dependency-graph-expansion",
            "ecosystem": None,
            "package": None,
            "version": None,
            "message": f"Overall resolved dependency graph grew by {total_delta} "
                       f"packages ({old_total} -> {new_total}).",
        })

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    risk_events.sort(
        key=lambda event: (
            -severity_order.get(event["severity"], 0),
            event.get("ecosystem") or "",
            event.get("package") or "",
            event["rule"],
        )
    )

    return {
        "baseline_generated_at": baseline.get("generated_at"),
        "current_generated_at": current.get("generated_at"),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "risk_events": len(risk_events),
            "package_count_before": old_total,
            "package_count_after": new_total,
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "risk_events": risk_events,
    }


def _event(
    severity: str,
    rule: str,
    package: dict[str, Any],
    message: str,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "rule": rule,
        "ecosystem": package.get("ecosystem"),
        "package": package.get("name"),
        "version": package.get("version"),
        "message": message,
    }


def compare_repo_to_baseline(repo: Path) -> dict[str, Any] | None:
    path = repo / TRUST_FILENAME
    if not path.exists():
        return None
    baseline = load_trust_snapshot(path)
    current = build_trust_snapshot(repo)
    return compare_trust_snapshots(baseline, current)
