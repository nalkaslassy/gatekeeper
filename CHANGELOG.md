# Changelog

All notable changes to Gatekeeper are documented here.

The format follows Keep a Changelog principles and the project uses semantic
versioning for published releases.

## [Unreleased]

### Added
- Opt-in `gatekeeper inspect npm` registry workflow that fetches two npm releases, verifies registry integrity, safely parses tarballs in memory, and runs static content drift without installing or executing package code.
- Static package-content fingerprinting and drift detection with content snapshot/diff CLI, including high-signal patterns such as infinite loops, dynamic code execution, subprocess use, environment access, network access, filesystem writes, encoded blobs, and newly introduced native binaries.
- Required dependency-edge drift detection, improving historical event-stream coverage without flagging optional dependency churn in the existing benign corpus.
- Historical supply-chain incident benchmark covering eslint-scope, ua-parser-js, event-stream, and colors with explicit detections and misses.
- Deterministic trust-drift benchmark corpus with benign public-release transitions, controlled security-drift cases, machine-readable results, and CI enforcement.
- Change-aware dependency trust snapshots with `gatekeeper trust snapshot`.
- Trust-drift review with `gatekeeper trust diff` and automatic scan findings for integrity, source, install-script, non-registry-source, and dependency-graph changes.
- CycloneDX 1.6 SBOM generation with `gatekeeper sbom`.
- Release-readiness and adoption evidence documentation.

## [0.1.0] - 2026-07-06

### Added
- Policy-driven CLI scans with baseline-aware pass/fail behavior.
- Ruff, Bandit, and optional gitleaks analyzers.
- Static npm/pnpm/Python lockfile and manifest analysis.
- Install-script, missing-lockfile, and unpinned-dependency detection.
- Offline typosquat detection, including scoped npm package handling.
- Opt-in OSV vulnerability and known-malicious-package lookup.
- JSON and SARIF output for GitHub Code Scanning.
- GitHub Actions integration and self-scanning CI.
- PyPI Trusted Publishing release workflow.
