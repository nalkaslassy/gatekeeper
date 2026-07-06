"""osv — opt-in known-vulnerability and known-malicious-package lookup via
OSV.dev (https://osv.dev).

Unlike every other analyzer in this package, this one makes network calls.
It is disabled by default (see policy.DEFAULT_DISABLED_ANALYZERS) and must
be explicitly turned on:

    analyzers:
      osv: { enabled: true, required: false }

`required: false` is strongly recommended — an OSV.dev outage or a
network-restricted CI runner should not fail a scan closed for a check
that is inherently best-effort over the network.

OSV ingests the OpenSSF "malicious packages" feed as ordinary advisories
whose id/alias is prefixed "MAL-"; a hit there is reported as a critical
supply_chain finding instead of an ordinary vuln finding.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..models import AnalyzerResult, Finding, Severity
from ..policy import Policy
from .python_manifests import (
    normalize_pypi_name,
    parse_pyproject_dependencies,
    pep508_name,
    resolved_versions,
)

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_TIMEOUT_SECONDS = 15
OSV_BATCH_SIZE = 500

# Detail fetches (one GET per distinct vuln id) are the expensive part of a
# scan with many hits. Cap how many we ever fetch; ids beyond the cap still
# produce a finding (never silently dropped), just without the enriched
# summary/severity from the detail endpoint.
MAX_DETAIL_FETCHES = 200
DETAIL_FETCH_WORKERS = 8

# OSV paginates a query's vulns via `next_page_token` when a single package
# matches an unusually large number of advisories. Bounded defensively so a
# misbehaving server can't make this loop forever.
MAX_QUERYBATCH_PAGES = 10

_NETWORK_ERRORS = (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError)

_DB_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _require_https(url: str) -> None:
    # Both URLs here are built from hardcoded https:// prefixes, so this
    # can't actually fail today — it's a guard against a future edit
    # accidentally turning a formatted-in value into a scheme change
    # (e.g. a vuln id containing "file://"), which urlopen would otherwise
    # follow without complaint.
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url!r}")


def _post_json(url: str, payload: dict) -> dict:
    _require_https(url)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_SECONDS) as resp:  # nosec B310
        return json.loads(resp.read())


def _get_json(url: str) -> dict:
    _require_https(url)
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_SECONDS) as resp:  # nosec B310
        return json.loads(resp.read())


def _npm_packages(repo: Path) -> list[tuple[str, str]]:
    lock = repo / "package-lock.json"
    if not lock.exists():
        return []
    try:
        data = json.loads(lock.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    out: list[tuple[str, str]] = []
    for pkg_path, meta in (data.get("packages") or {}).items():
        if not pkg_path or not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if not version:
            continue
        out.append((pkg_path.split("node_modules/")[-1], version))
    return out


def _pypi_packages(repo: Path) -> list[tuple[str, str]]:
    """Merge (in increasing precedence) exact '==' pins from
    requirements.txt, exact '==' pins from pyproject.toml's
    [project.dependencies], and poetry.lock/uv.lock resolved versions —
    the lockfile wins on conflict, since it reflects what actually gets
    installed rather than what the manifest merely permits."""
    versions: dict[str, str] = {}       # normalized name -> version
    display_names: dict[str, str] = {}  # normalized name -> name as written

    req = repo / "requirements.txt"
    if req.exists():
        try:
            lines = req.read_text().splitlines()
        except OSError:
            lines = []
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "--")) or "==" not in line:
                continue  # only exactly-pinned deps have a version to look up
            pkg_name, _, version = line.partition("==")
            pkg_name = pkg_name.strip()
            key = normalize_pypi_name(pkg_name)
            versions[key] = version.strip()
            display_names[key] = pkg_name

    for raw_spec in parse_pyproject_dependencies(repo):
        pkg_name = pep508_name(raw_spec)
        key = normalize_pypi_name(pkg_name)
        display_names.setdefault(key, pkg_name)
        spec_no_marker = raw_spec.split(";", 1)[0]
        if "==" in spec_no_marker:
            _, _, version = spec_no_marker.partition("==")
            versions[key] = re.split(r"[,\s\[]", version.strip())[0]

    for key, version in resolved_versions(repo).items():
        versions[key] = version
        display_names.setdefault(key, key)

    return [(display_names[key], version) for key, version in versions.items()]


def _severity_from_osv(vuln: dict) -> Severity:
    db_sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_sev, str) and db_sev.upper() in _DB_SEVERITY_MAP:
        return _DB_SEVERITY_MAP[db_sev.upper()]
    # OSV's `severity` field is usually a raw CVSS vector string, not a score
    # we can bucket without a CVSS parser we don't want to add as a
    # dependency. Treat any advisory without a parseable severity as HIGH
    # rather than silently under-reporting it.
    return Severity.HIGH


def _querybatch_page(queries: list[dict]) -> list[dict]:
    results: list[dict] = []
    for i in range(0, len(queries), OSV_BATCH_SIZE):
        chunk = queries[i:i + OSV_BATCH_SIZE]
        resp = _post_json(OSV_QUERYBATCH_URL, {"queries": chunk})
        results.extend(resp.get("results", []))
    return results


def _collect_vulns(queries: list[dict]) -> list[list[dict]]:
    """Run querybatch for `queries`, following each result's next_page_token
    until exhausted (bounded by MAX_QUERYBATCH_PAGES). Returns one aggregated
    list of brief vuln dicts per query, in the same order as `queries`.

    A failure on the first page is a hard failure (propagates — there is no
    data to report at all). A failure on a later page keeps whatever was
    already collected instead of discarding it: a partial result is more
    useful than none, and it isn't a case this analyzer should fail closed
    on the way a crashed/missing tool does.
    """
    aggregated: list[list[dict]] = [[] for _ in queries]
    pending_indexes = list(range(len(queries)))
    current_queries = list(queries)

    for page_num in range(MAX_QUERYBATCH_PAGES):
        if not pending_indexes:
            break
        try:
            results = _querybatch_page(current_queries)
        except _NETWORK_ERRORS:
            if page_num == 0:
                raise
            break

        next_queries: list[dict] = []
        next_indexes: list[int] = []
        for idx, result in zip(pending_indexes, results):
            aggregated[idx].extend(result.get("vulns") or [])
            token = result.get("next_page_token")
            if token:
                q = dict(queries[idx])
                q["page_token"] = token
                next_queries.append(q)
                next_indexes.append(idx)
        current_queries = next_queries
        pending_indexes = next_indexes

    return aggregated


def _fetch_detail_safe(vuln_id: str) -> dict:
    try:
        return _get_json(OSV_VULN_URL.format(id=vuln_id))
    except _NETWORK_ERRORS:
        return {}


def _fetch_details(vuln_ids: list[str]) -> dict[str, dict]:
    """Fetch full detail for up to MAX_DETAIL_FETCHES distinct ids,
    concurrently. IDs beyond the cap simply aren't enriched — callers fall
    back to defaults built from the brief (id-only) querybatch result, so a
    known vulnerability is never dropped just because of the cap."""
    capped = vuln_ids[:MAX_DETAIL_FETCHES]
    if not capped:
        return {}
    details: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=DETAIL_FETCH_WORKERS) as pool:
        future_to_id = {pool.submit(_fetch_detail_safe, vid): vid for vid in capped}
        for future in as_completed(future_to_id):
            details[future_to_id[future]] = future.result()
    return details


def run_osv(repo: Path, policy: Policy) -> AnalyzerResult:
    analyzer_name = "osv"
    raw_packages: list[tuple[str, str, str]] = (
        [("npm", n, v) for n, v in _npm_packages(repo)]
        + [("PyPI", n, v) for n, v in _pypi_packages(repo)]
    )
    if not raw_packages:
        return AnalyzerResult(analyzer_name, ok=True, findings=[])

    # Dedupe (ecosystem, name, version) triples: the same pinned version can
    # appear at multiple lockfile paths (hoisting, nested duplicates), and
    # each one would otherwise cost its own querybatch entry + detail fetch
    # for an identical result.
    seen_pkgs: set[tuple[str, str, str]] = set()
    packages: list[tuple[str, str, str]] = []
    for pkg in raw_packages:
        if pkg not in seen_pkgs:
            seen_pkgs.add(pkg)
            packages.append(pkg)

    queries = [
        {"package": {"name": n, "ecosystem": eco}, "version": v}
        for eco, n, v in packages
    ]

    try:
        vulns_per_package = _collect_vulns(queries)
    except _NETWORK_ERRORS as exc:
        return AnalyzerResult(analyzer_name, ok=False, findings=[],
                               error=f"OSV.dev query failed: {exc}")

    all_ids: list[str] = []
    seen_ids: set[str] = set()
    for vulns in vulns_per_package:
        for brief in vulns:
            vid = brief.get("id", "unknown")
            if vid not in seen_ids:
                seen_ids.add(vid)
                all_ids.append(vid)
    details = _fetch_details(all_ids)

    findings: list[Finding] = []
    for (eco, pkg_name, version), vulns in zip(packages, vulns_per_package):
        for brief in vulns:
            vuln_id = brief.get("id", "unknown")
            vuln = details.get(vuln_id, {})

            is_malicious = vuln_id.startswith("MAL-") or any(
                a.startswith("MAL-") for a in (vuln.get("aliases") or [])
            )
            file_path = "package-lock.json" if eco == "npm" else "requirements.txt"
            context = f"{pkg_name}@{version}:{vuln_id}"

            if is_malicious:
                findings.append(Finding(
                    category="supply_chain",
                    rule_id="gk:osv-malicious-package",
                    severity=Severity.CRITICAL,
                    title=f"'{pkg_name}@{version}' ({eco}) is flagged as a "
                          f"MALICIOUS package by OSV ({vuln_id})",
                    file_path=file_path,
                    detail={"package": pkg_name, "version": version,
                            "osv_id": vuln_id, "context": context},
                    analyzer=analyzer_name,
                ))
            else:
                summary = vuln.get("summary") or (vuln.get("details") or "")[:200] \
                    or "no summary available"
                findings.append(Finding(
                    category="vuln",
                    rule_id=f"osv:{vuln_id}",
                    severity=_severity_from_osv(vuln),
                    title=f"'{pkg_name}@{version}' ({eco}) has known advisory "
                          f"{vuln_id}: {summary}",
                    file_path=file_path,
                    detail={"package": pkg_name, "version": version,
                            "osv_id": vuln_id, "context": context},
                    analyzer=analyzer_name,
                ))

    return AnalyzerResult(analyzer_name, ok=True, findings=findings)
