# Changelog

All notable changes to Gatekeeper are documented here.

The project follows semantic versioning for published releases. No public
Gatekeeper release has been published yet; the first intended release is
`v0.1.0`.

## [Unreleased]

### Added
- Unified `gatekeeper review` workflow that combines trust drift and optional npm content drift into one PASS / REVIEW / BLOCK decision.
- Root GitHub Action focused on dependency trust review and GitHub job summaries.
- Opt-in `gatekeeper inspect npm` registry workflow that verifies modern integrity, safely parses tarballs in memory, and runs static content drift without installing or executing package code.
- Static package-content fingerprinting and drift detection for high-signal capability changes and newly introduced native binaries.
- Required dependency-edge drift detection.
- Historical supply-chain incident benchmark covering eslint-scope, ua-parser-js, event-stream, and colors.
- Deterministic trust-drift benchmark corpus with benign public-release transitions and controlled security-drift cases.
- Change-aware dependency trust snapshots with `gatekeeper trust snapshot`.
- CycloneDX 1.6 SBOM generation with `gatekeeper sbom`.
- Contributor, security-reporting, issue, pull-request, and public-launch documentation.
- Release workflow that validates distributions, publishes through PyPI Trusted Publishing, and creates a GitHub Release.

### Changed
- Executable GitHub Actions dependencies are upgraded and pinned to immutable commit SHAs; Dependabot now proposes weekly GitHub Actions and Python development-tool updates.
- GitHub Action summaries include lockfile locators so duplicate package instances are unambiguous.
- Pull-request reviews now fetch and use the base branch trust snapshot, preventing candidate changes from redefining their own trusted baseline.
- Same-version integrity removal is a critical trust-drift event, and same-version source appearance/disappearance is detected.
- npm registry, URL, Git, local, link, and workspace sources are classified separately; registry-backed content inspection is limited to registry-to-registry version transitions.
- Python distribution renamed from the unavailable `gatekeeper-cli` name to `gatekeeper-trust-drift`; the executable remains `gatekeeper`.
- Trust snapshots now preserve npm lockfile locators so multiple installed versions/instances of the same package are compared independently instead of being collapsed by package name.
- README and design documentation now center the dependency trust-delta model and explicitly keep broad DevSecOps/platform features out of near-term scope.
- CI now builds and smoke-tests the release wheel before launch.

### Initial implementation
- Policy-driven CLI scans with baseline-aware pass/fail behavior.
- Ruff, Bandit, and optional gitleaks analyzers.
- Static npm/pnpm/Python lockfile and manifest analysis.
- Install-script, missing-lockfile, unpinned-dependency, typosquat, and dependency-confusion checks.
- Optional OSV vulnerability and known-malicious-package lookup.
- JSON and SARIF output for supporting GitHub Code Scanning workflows.
- Self-scanning CI on Python 3.10 and 3.12.
