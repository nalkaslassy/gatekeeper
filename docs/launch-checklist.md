# Public launch checklist

This document tracks the small set of launch tasks that are intentionally not
new product features.

## Automated in the repository

- [x] focused `gatekeeper review` PASS / REVIEW / BLOCK workflow
- [x] duplicate npm package instances preserved by lockfile locator
- [x] pull requests use the trusted base-branch snapshot rather than the candidate snapshot
- [x] same-version integrity removal and complete source drift are detected
- [x] npm local/link/workspace sources are classified separately
- [x] root GitHub Action for trust review
- [x] release workflow builds, validates, publishes to PyPI, and creates a GitHub Release
- [x] security policy and contribution templates
- [x] deterministic benchmark in CI
- [x] executable GitHub Actions dependencies pinned to immutable commit SHAs
- [x] Dependabot monitors GitHub Actions and Python development tooling weekly
- [x] Action summaries show lockfile locators for duplicate package instances
- [x] separate end-to-end workflow validates the CLI against full commit-pinned public lockfile transitions
- [x] CI validates wheel + sdist metadata/installability before release
- [x] release workflow rejects tag/package-version mismatches

## One-time external setup

Before tagging `v0.1.0`:

- [ ] Create/claim the PyPI project **gatekeeper-trust-drift** through Trusted Publishing.
- [ ] Configure the PyPI trusted publisher:
  - owner: `nalkaslassy`
  - repository: `gatekeeper`
  - workflow: `release.yml`
  - environment: `pypi`
- [ ] Add GitHub repository description:
  `Change-aware dependency security gate that detects trust drift before merge.`
- [ ] Add repository topics:
  `software-supply-chain`, `supply-chain-security`, `dependency-security`,
  `trust-drift`, `devsecops`, `npm`, `security`, `sarif`, `sbom`,
  `cyclonedx`, `github-actions`.
- [ ] Enable GitHub Discussions.
- [ ] Enable GitHub private vulnerability reporting if available.

## Release

- [ ] Confirm `main` CI is green.
- [ ] Confirm README install command uses `gatekeeper-trust-drift`.
- [ ] Confirm the PyPI name is still available/owned before tagging.
- [ ] Tag `v0.1.0`.
- [ ] Verify PyPI installation in a clean environment.
- [ ] Verify `nalkaslassy/gatekeeper@v0.1.0` on a small public test repository.

## Adoption evidence

After launch, prioritize evidence over feature count:

- [ ] 10 external installs/users
- [ ] first independent issue or PR
- [ ] first public repository using the Action
- [x] 25 benign benchmark transitions (2 compact public lockfile transitions + 23 package-level public release pairs)
- [x] 10 historical incident reconstructions (including a retained documented miss)
- [x] publish a technical case study with both detections and misses (`docs/case-study-v0.1-evaluation.md`)
