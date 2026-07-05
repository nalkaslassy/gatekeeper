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
import urllib.error
import urllib.request
from pathlib import Path

from ..models import AnalyzerResult, Finding, Severity
from ..policy import Policy

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_TIMEOUT_SECONDS = 15
OSV_BATCH_SIZE = 500

_DB_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read())


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_SECONDS) as resp:
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
    req = repo / "requirements.txt"
    if not req.exists():
        return []
    out: list[tuple[str, str]] = []
    try:
        lines = req.read_text().splitlines()
    except OSError:
        return []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")) or "==" not in line:
            continue  # only exactly-pinned deps have a version to look up
        pkg_name, _, version = line.partition("==")
        out.append((pkg_name.strip(), version.strip()))
    return out


def _severity_from_osv(vuln: dict) -> Severity:
    db_sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_sev, str) and db_sev.upper() in _DB_SEVERITY_MAP:
        return _DB_SEVERITY_MAP[db_sev.upper()]
    # OSV's `severity` field is usually a raw CVSS vector string, not a score
    # we can bucket without a CVSS parser we don't want to add as a
    # dependency. Treat any advisory without a parseable severity as HIGH
    # rather than silently under-reporting it.
    return Severity.HIGH


def run_osv(repo: Path, policy: Policy) -> AnalyzerResult:
    analyzer_name = "osv"
    packages: list[tuple[str, str, str]] = (
        [("npm", n, v) for n, v in _npm_packages(repo)]
        + [("PyPI", n, v) for n, v in _pypi_packages(repo)]
    )
    if not packages:
        return AnalyzerResult(analyzer_name, ok=True, findings=[])

    queries = [
        {"package": {"name": n, "ecosystem": eco}, "version": v}
        for eco, n, v in packages
    ]

    try:
        matches: list[dict] = []
        for i in range(0, len(queries), OSV_BATCH_SIZE):
            chunk = queries[i:i + OSV_BATCH_SIZE]
            resp = _post_json(OSV_QUERYBATCH_URL, {"queries": chunk})
            matches.extend(resp.get("results", []))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return AnalyzerResult(analyzer_name, ok=False, findings=[],
                               error=f"OSV.dev query failed: {exc}")

    findings: list[Finding] = []
    for (eco, pkg_name, version), result in zip(packages, matches):
        for brief in result.get("vulns") or []:
            vuln_id = brief.get("id", "unknown")
            try:
                vuln = _get_json(OSV_VULN_URL.format(id=vuln_id))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
                vuln = {}

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
