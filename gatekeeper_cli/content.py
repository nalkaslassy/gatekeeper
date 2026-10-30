"""Static package-content fingerprinting and drift detection.

This module never executes target code and never performs network access. It scans
an already-available package directory (for example, an extracted npm tarball or
a package under node_modules) and records file inventory plus high-signal static
capabilities/patterns.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

CONTENT_SCHEMA_VERSION = 1

_TEXT_SUFFIXES = {
    ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".json", ".py", ".sh",
}
_NATIVE_SUFFIXES = {".node", ".so", ".dll", ".dylib", ".exe"}

_PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "infinite-loop": (
        re.compile(
            r"(for\s*\([^;]*;\s*[^;]*(?:<|<=)\s*Infinity[^;]*;[^)]*\)"
            r"|while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\))"
        ),
        "high",
    ),
    "dynamic-code-execution": (
        re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("),
        "high",
    ),
    "subprocess-execution": (
        re.compile(
            r"(?:require\s*\(\s*['\"]child_process['\"]\s*\)"
            r"|from\s+['\"]child_process['\"]"
            r"|\b(?:exec|execFile|spawn|fork)\s*\()"
        ),
        "high",
    ),
    "environment-access": (
        re.compile(r"\bprocess\.env\b|\bos\.environ\b"),
        "medium",
    ),
    "network-access": (
        re.compile(
            r"(?:require\s*\(\s*['\"](?:http|https|net|tls|dns)['\"]\s*\)"
            r"|\bfetch\s*\(|\baxios\s*\.)"
        ),
        "medium",
    ),
    "filesystem-write": (
        re.compile(
            r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|"
            r"createWriteStream|unlink|unlinkSync|rm|rmSync)\s*\("
        ),
        "medium",
    ),
    "long-encoded-blob": (
        re.compile(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]"),
        "medium",
    ),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def scan_content_files(files_by_path: dict[str, bytes | str]) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    capabilities: set[str] = set()
    pattern_hits: list[dict[str, Any]] = []
    native_files: list[str] = []
    code_bytes = 0

    for rel in sorted(files_by_path):
        raw = files_by_path[rel]
        data = raw.encode() if isinstance(raw, str) else raw
        suffix = Path(rel).suffix.lower()

        files.append({
            "path": rel,
            "size": len(data),
            "sha256": _sha256(data),
        })

        if suffix in _NATIVE_SUFFIXES:
            native_files.append(rel)

        if suffix not in _TEXT_SUFFIXES:
            continue

        code_bytes += len(data)
        text = data.decode("utf-8", errors="ignore")
        for name, (pattern, severity) in _PATTERNS.items():
            if pattern.search(text):
                capabilities.add(name)
                pattern_hits.append({
                    "rule": name,
                    "severity": severity,
                    "file": rel,
                })

    return {
        "schema_version": CONTENT_SCHEMA_VERSION,
        "summary": {
            "file_count": len(files),
            "code_bytes": code_bytes,
            "native_file_count": len(native_files),
        },
        "files": files,
        "native_files": sorted(native_files),
        "capabilities": sorted(capabilities),
        "pattern_hits": sorted(
            pattern_hits, key=lambda hit: (hit["rule"], hit["file"])
        ),
    }


def scan_content_tree(root: Path) -> dict[str, Any]:
    root = root.resolve()
    data: dict[str, bytes] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if any(part in {".git", "__pycache__"} for part in path.parts):
            continue
        try:
            data[rel] = path.read_bytes()
        except OSError:
            continue
    return scan_content_files(data)


def compare_content_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    before_caps = set(baseline.get("capabilities") or [])
    after_caps = set(current.get("capabilities") or [])
    new_caps = sorted(after_caps - before_caps)

    before_native = set(baseline.get("native_files") or [])
    after_native = set(current.get("native_files") or [])
    new_native = sorted(after_native - before_native)

    before_files = {
        item.get("path"): item for item in baseline.get("files", [])
        if isinstance(item, dict) and item.get("path")
    }
    after_files = {
        item.get("path"): item for item in current.get("files", [])
        if isinstance(item, dict) and item.get("path")
    }

    added_files = sorted(after_files.keys() - before_files.keys())
    removed_files = sorted(before_files.keys() - after_files.keys())
    changed_files = sorted(
        path for path in before_files.keys() & after_files.keys()
        if before_files[path].get("sha256") != after_files[path].get("sha256")
    )

    risk_events: list[dict[str, Any]] = []
    severity_for = {name: severity for name, (_, severity) in _PATTERNS.items()}
    for capability in new_caps:
        risk_events.append({
            "severity": severity_for.get(capability, "medium"),
            "rule": f"content-{capability}",
            "message": f"New static content capability/pattern: {capability}.",
        })

    for path in new_native:
        risk_events.append({
            "severity": "high",
            "rule": "content-native-binary-added",
            "message": f"New native/executable artifact: {path}.",
        })

    before_bytes = int((baseline.get("summary") or {}).get("code_bytes", 0))
    after_bytes = int((current.get("summary") or {}).get("code_bytes", 0))
    if before_bytes >= 1024 and after_bytes >= before_bytes * 2:
        risk_events.append({
            "severity": "medium",
            "rule": "content-code-growth",
            "message": f"Text/code footprint grew from {before_bytes} to {after_bytes} bytes.",
        })

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    risk_events.sort(key=lambda e: (-order.get(e["severity"], 0), e["rule"]))

    return {
        "summary": {
            "added_files": len(added_files),
            "removed_files": len(removed_files),
            "changed_files": len(changed_files),
            "new_capabilities": len(new_caps),
            "risk_events": len(risk_events),
        },
        "added_files": added_files,
        "removed_files": removed_files,
        "changed_files": changed_files,
        "new_capabilities": new_caps,
        "risk_events": risk_events,
    }
