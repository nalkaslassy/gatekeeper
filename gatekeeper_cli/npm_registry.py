"""Optional npm registry package inspection.

This module is deliberately networked and opt-in. It fetches npm version
metadata and tarballs, verifies registry-provided integrity, parses archives
in memory, and feeds package contents into Gatekeeper's static content engine.

It never runs npm install, lifecycle scripts, package executables, or extracted
files.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import posixpath
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .content import compare_content_snapshots, scan_content_files

DEFAULT_REGISTRY = "https://registry.npmjs.org"
DEFAULT_TIMEOUT_SECONDS = 20
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_TARBALL_BYTES = 25 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_FILES = 20_000


@dataclass(frozen=True)
class NpmVersionMetadata:
    name: str
    version: str
    tarball_url: str
    integrity: str | None
    shasum: str | None


def _read_limited(response: Any, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ValueError(f"download exceeds safety limit of {limit} bytes")
    return b"".join(chunks)


def _open(url: str, *, timeout: int) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, application/octet-stream",
            "User-Agent": "gatekeeper-cli",
        },
    )
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ValueError(f"network request failed for {url}: {exc}") from exc


def _encoded_package_name(name: str) -> str:
    # npm's registry endpoint expects @scope/name as @scope%2Fname.
    return urllib.parse.quote(name, safe="@")


def fetch_npm_version_metadata(
    package: str,
    version: str,
    *,
    registry: str = DEFAULT_REGISTRY,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> NpmVersionMetadata:
    base = registry.rstrip("/")
    url = f"{base}/{_encoded_package_name(package)}/{urllib.parse.quote(version, safe='')}"
    with _open(url, timeout=timeout) as response:
        raw = _read_limited(response, MAX_METADATA_BYTES)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid npm registry metadata for {package}@{version}") from exc

    dist = doc.get("dist") if isinstance(doc, dict) else None
    if not isinstance(dist, dict) or not dist.get("tarball"):
        raise ValueError(f"npm metadata for {package}@{version} has no dist.tarball")

    actual_name = str(doc.get("name") or package)
    actual_version = str(doc.get("version") or version)
    if actual_name != package or actual_version != version:
        raise ValueError(
            f"registry returned unexpected package identity "
            f"{actual_name}@{actual_version} for {package}@{version}"
        )

    return NpmVersionMetadata(
        name=actual_name,
        version=actual_version,
        tarball_url=str(dist["tarball"]),
        integrity=str(dist["integrity"]) if dist.get("integrity") else None,
        shasum=str(dist["shasum"]) if dist.get("shasum") else None,
    )


def _verify_integrity(data: bytes, metadata: NpmVersionMetadata) -> str:
    if metadata.integrity:
        # Subresource Integrity can contain multiple space-separated digests.
        for token in metadata.integrity.split():
            if "-" not in token:
                continue
            algorithm, expected = token.split("-", 1)
            if algorithm not in {"sha512", "sha384", "sha256"}:
                continue
            digest = hashlib.new(algorithm, data).digest()
            actual = base64.b64encode(digest).decode()
            if hmac.compare_digest(actual, expected):
                return algorithm
        raise ValueError(
            f"integrity verification failed for {metadata.name}@{metadata.version}"
        )

    if metadata.shasum:
        actual = hashlib.sha1(data).hexdigest()
        if not hmac.compare_digest(actual, metadata.shasum):
            raise ValueError(
                f"sha1 verification failed for {metadata.name}@{metadata.version}"
            )
        return "sha1"

    raise ValueError(
        f"registry metadata for {metadata.name}@{metadata.version} has no integrity hash"
    )


def _safe_member_path(name: str) -> str | None:
    normalized = posixpath.normpath(name.replace("\\", "/"))
    if normalized in {"", "."}:
        return None
    if normalized.startswith("/") or normalized == ".." or normalized.startswith("../"):
        raise ValueError(f"unsafe archive path: {name!r}")

    # npm tarballs normally use a package/ prefix. Remove only that conventional
    # top-level directory so snapshots compare package-relative paths.
    if normalized.startswith("package/"):
        normalized = normalized[len("package/"):]
    if not normalized:
        return None
    return normalized


def files_from_npm_tarball(data: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    extracted_bytes = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"invalid npm tarball: {exc}") from exc

    with archive:
        for member in archive:
            if member.issym() or member.islnk():
                # Static analysis does not need links, and ignoring them prevents
                # link-target/path traversal concerns.
                continue
            if not member.isfile():
                continue
            rel = _safe_member_path(member.name)
            if rel is None:
                continue
            if len(files) >= MAX_FILES:
                raise ValueError(f"archive exceeds safety limit of {MAX_FILES} files")
            if member.size < 0:
                raise ValueError(f"invalid archive member size for {member.name!r}")
            extracted_bytes += member.size
            if extracted_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError(
                    f"archive expands beyond safety limit of {MAX_EXTRACTED_BYTES} bytes"
                )
            stream = archive.extractfile(member)
            if stream is None:
                continue
            content = stream.read(member.size + 1)
            if len(content) != member.size:
                raise ValueError(f"truncated archive member: {member.name!r}")
            files[rel] = content
    return files


def fetch_npm_content_snapshot(
    package: str,
    version: str,
    *,
    registry: str = DEFAULT_REGISTRY,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    metadata = fetch_npm_version_metadata(
        package, version, registry=registry, timeout=timeout
    )
    with _open(metadata.tarball_url, timeout=timeout) as response:
        tarball = _read_limited(response, MAX_TARBALL_BYTES)
    verified_with = _verify_integrity(tarball, metadata)
    files = files_from_npm_tarball(tarball)
    snapshot = scan_content_files(files)
    snapshot["package"] = {
        "ecosystem": "npm",
        "name": package,
        "version": version,
        "registry": registry.rstrip("/"),
        "tarball_url": metadata.tarball_url,
        "verified_with": verified_with,
    }
    return snapshot


def inspect_npm_versions(
    package: str,
    baseline_version: str,
    candidate_version: str,
    *,
    registry: str = DEFAULT_REGISTRY,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    baseline = fetch_npm_content_snapshot(
        package, baseline_version, registry=registry, timeout=timeout
    )
    candidate = fetch_npm_content_snapshot(
        package, candidate_version, registry=registry, timeout=timeout
    )
    diff = compare_content_snapshots(baseline, candidate)
    return {
        "package": package,
        "baseline_version": baseline_version,
        "candidate_version": candidate_version,
        "registry": registry.rstrip("/"),
        "baseline": baseline,
        "candidate": candidate,
        "diff": diff,
    }
