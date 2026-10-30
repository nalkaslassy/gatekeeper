# Changelog

All notable changes to Gatekeeper are documented here.

The format follows Keep a Changelog principles and the project uses semantic
versioning for published releases.

## [Unreleased]

### Added
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
