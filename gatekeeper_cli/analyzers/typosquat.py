"""typosquat — offline heuristic: flag declared dependencies that are
suspiciously close (small edit distance) to a well-known package name.

Zero network, zero execution: reads package.json / requirements.txt and
diffs against the bundled list in popular_packages.py. It cannot know
whether a close match is a deliberate fork, a legitimate similarly-named
package, or an actual typosquat — treat findings as a prompt for a human
to look, not proof of malice.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import AnalyzerResult, Finding
from ..policy import Policy
from .popular_packages import POPULAR_NPM_PACKAGES, POPULAR_PYPI_PACKAGES

_MIN_NAME_LEN = 3
_MAX_DISTANCE = 2

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


def _edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment variant): insert,
    delete, substitute, or transpose adjacent characters, each cost 1."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _closest_match(name: str, popular: frozenset[str]) -> tuple[str, int] | None:
    best: tuple[str, int] | None = None
    for cand in popular:
        if len(cand) < _MIN_NAME_LEN:
            continue
        if abs(len(cand) - len(name)) > _MAX_DISTANCE:
            continue
        dist = _edit_distance(name, cand)
        if dist == 0:
            return None  # exact match against the popular list: not a typosquat
        if dist <= _MAX_DISTANCE and (best is None or dist < best[1]):
            best = (cand, dist)
    return best


def _npm_declared_deps(repo: Path) -> dict[str, str]:
    pkg_json = repo / "package.json"
    if not pkg_json.exists():
        return {}
    try:
        data = json.loads(pkg_json.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.update(section)
    return deps


def _pypi_declared_deps(repo: Path) -> list[str]:
    req = repo / "requirements.txt"
    if not req.exists():
        return []
    names = []
    try:
        lines = req.read_text().splitlines()
    except OSError:
        return []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        m = _REQ_NAME_RE.match(line)
        if m:
            names.append(m.group(1))
    return names


def _normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def run_typosquat(repo: Path, policy: Policy) -> AnalyzerResult:
    name = "typosquat"
    if policy.typosquat is None:
        return AnalyzerResult(name, ok=True, findings=[])

    findings: list[Finding] = []

    for pkg_name in _npm_declared_deps(repo):
        if len(pkg_name) < _MIN_NAME_LEN or pkg_name in POPULAR_NPM_PACKAGES:
            continue
        match = _closest_match(pkg_name, POPULAR_NPM_PACKAGES)
        if match is None:
            continue
        popular_name, dist = match
        findings.append(
            Finding(
                category="supply_chain",
                rule_id="gk:npm-possible-typosquat",
                severity=policy.typosquat,
                title=f"npm dependency '{pkg_name}' is suspiciously similar to "
                      f"popular package '{popular_name}' (edit distance {dist}) "
                      f"— possible typosquat, verify before trusting",
                file_path="package.json",
                detail={"package": pkg_name, "similar_to": popular_name,
                        "distance": dist, "context": pkg_name},
                analyzer=name,
            )
        )

    for raw_name in _pypi_declared_deps(repo):
        key = _normalize_pypi(raw_name)
        if len(key) < _MIN_NAME_LEN or key in POPULAR_PYPI_PACKAGES:
            continue
        match = _closest_match(key, POPULAR_PYPI_PACKAGES)
        if match is None:
            continue
        popular_name, dist = match
        findings.append(
            Finding(
                category="supply_chain",
                rule_id="gk:py-possible-typosquat",
                severity=policy.typosquat,
                title=f"Python dependency '{raw_name}' is suspiciously similar to "
                      f"popular package '{popular_name}' (edit distance {dist}) "
                      f"— possible typosquat, verify before trusting",
                file_path="requirements.txt",
                detail={"package": raw_name, "similar_to": popular_name,
                        "distance": dist, "context": raw_name},
                analyzer=name,
            )
        )

    return AnalyzerResult(name, ok=True, findings=findings)
