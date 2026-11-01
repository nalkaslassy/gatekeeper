# Gatekeeper

[![CI](https://github.com/nalkaslassy/gatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/nalkaslassy/gatekeeper/actions/workflows/ci.yml)

**Detect security-relevant dependency trust drift before merge.**

Gatekeeper answers one focused question: **what became less trustworthy in this
dependency update?** It compares the dependency state a team previously reviewed
with the candidate state and surfaces meaningful trust deltas: integrity/source
changes, install behavior, required dependency edges, graph expansion, and
static package-content capabilities. The default review is offline; npm package
content retrieval is explicit and opt-in.

Gatekeeper still includes baseline-aware SAST, secret scanning, lockfile checks,
dependency-confusion checks, SBOM generation, and optional OSV lookup, but those
are supporting controls rather than the product's core identity.

## Quickstart (60 seconds)

```bash
pip install "gatekeeper-cli[analyzers]"

cd your-repo
gatekeeper policy init .        # writes gatekeeper.yaml — commit it
gatekeeper trust snapshot .     # establish reviewed dependency state; commit it
gatekeeper review .             # PASS / REVIEW / BLOCK, offline by default
```

Adopting on a codebase with existing debt? Record it, then block only regressions:

```bash
gatekeeper baseline .           # writes .gatekeeper-baseline.json — commit it
gatekeeper trust snapshot .     # writes .gatekeeper-trust.json — commit it
gatekeeper scan .               # now fails on new findings + risky trust drift
```

## CI (GitHub Actions)

Copy `action/example-workflow.yml` to `.github/workflows/gatekeeper.yml` in
*your* repo to have Gatekeeper scan it. PRs get a required status check, and
findings land in the repo's **Security → Code scanning** tab via SARIF.
(This is separate from `.github/workflows/ci.yml` in *this* repo, which
tests and lints Gatekeeper's own source — see [Development](#development).)

## Commands

| Command | Purpose |
|---|---|
| `gatekeeper review [PATH]` | Unified dependency trust decision: PASS / REVIEW / BLOCK |
| `gatekeeper review [PATH] --online-content` | Also fetch/verify changed npm releases and include content drift |
| `gatekeeper scan [PATH]` | Run supporting analyzers, print report, exit 0/1/2 |
| `gatekeeper scan --format json\|sarif --output FILE` | Machine-readable reports |
| `gatekeeper scan --fail-on medium` | Override the policy threshold |
| `gatekeeper scan --analyzers lockfile,bandit` | Run a subset |
| `gatekeeper baseline [PATH]` | Record current findings as accepted baseline |
| `gatekeeper sbom [PATH] --output bom.cdx.json` | Generate a static CycloneDX 1.6 SBOM |
| `gatekeeper trust snapshot [PATH]` | Record the dependency posture you currently trust |
| `gatekeeper trust diff [PATH]` | Compare current dependencies to the committed trust snapshot |
| `gatekeeper content snapshot PATH --output FILE` | Fingerprint an extracted package directory without executing it |
| `gatekeeper content diff PATH --baseline FILE` | Compare extracted package content to a trusted snapshot |
| `gatekeeper inspect npm PACKAGE --baseline VERSION --candidate VERSION` | Opt-in: fetch, verify, and statically compare two npm releases |
| `gatekeeper policy init` / `policy validate` | Create / check `gatekeeper.yaml` |

Exit codes: `0` passed · `1` blocking findings · `2` execution/config error.
A crashed or missing *required* analyzer is a failure — Gatekeeper fails
closed, never open.

## Policy (`gatekeeper.yaml`)

```yaml
version: 1
fail_on: high              # min severity of a NEW finding that blocks
new_findings_only: true

analyzers:
  ruff:      { enabled: true }
  bandit:    { enabled: true }
  gitleaks:  { enabled: true, required: false }
  lockfile:  { enabled: true }
  dependency_confusion: { enabled: true }
  trust_drift: { enabled: true }
  typosquat: { enabled: true }
  osv:       { enabled: false, required: false }  # opt-in, makes network calls

supply_chain:
  require_lockfile: high       # manifest with no lockfile at all
  install_scripts: warn        # allow | warn | block
  unpinned_python_deps: medium # requirements.txt/pyproject.toml entries
                                # without '==', unless a poetry.lock/uv.lock
                                # resolves them
  typosquat: high               # bundled popular-package list, no network
  typosquat_allow: []           # known-good near-misses, suppressed by exact name

  dependency_confusion: high
  internal_npm_scopes: []       # e.g. ["@yourcompany"]
  internal_npm_packages: []     # private unscoped npm names
  internal_pypi_packages: []    # private Python distribution names
```

Policy lives in the repo, so loosening it is itself a reviewable diff.

## Trust drift

Gatekeeper can record the dependency posture a team explicitly reviewed and then
flag security-relevant changes on later upgrades. This is intentionally different
from a CVE-only scanner: the question is not merely whether the candidate version
has a published advisory, but whether it became materially more dangerous than
the version already trusted.

Create and commit a baseline:

```bash
gatekeeper trust snapshot .
git add .gatekeeper-trust.json
```

Then use the unified review workflow:

```bash
gatekeeper review .
```

`review` automatically compares the committed trust snapshot with the current
dependency state and produces one decision:

- **PASS** — no security-relevant trust drift.
- **REVIEW** — non-blocking low/medium trust changes deserve human attention.
- **BLOCK** — high/critical trust drift should fail the gate.

For changed npm versions, add `--online-content` to fetch the two published
tarballs over HTTPS, verify modern registry integrity, and include static
package-content drift. Normal review remains offline.

The current engine records package identity/version, direct-vs-transitive status,
source type/URL, integrity hash when the lockfile provides one, install-script
state, and dependency-count metadata when available. High-signal drift includes:

- integrity changing without a version change (critical),
- package source/source type changing,
- a lifecycle install script appearing where none existed before,
- a new direct Git/URL dependency, and
- large dependency-graph expansion, and
- a previously known package adding new required dependency edges.

When a committed snapshot exists, the normal `gatekeeper scan` command runs the
`trust_drift` analyzer automatically and emits these events as standard findings,
so the existing policy threshold can block the PR.

Gatekeeper also ships a deterministic benchmark corpus under `benchmarks/`.
It currently includes two benign public-release dependency transitions, five
controlled security-drift mutations, and four reconstructed historical npm
supply-chain incidents. Run `python -m gatekeeper_cli.benchmarks.run` to reproduce
the case-level results locally; CI runs the same corpus on every pull request.
The historical set currently detects all 4 reconstructed incidents using the combined
metadata and static-content benchmark. This remains a small corpus and is not a universal detection-rate claim. Reported
precision/recall values apply only to the checked-in corpus and are not claims
about all software supply-chain attacks.

## Supply-chain coverage

What's covered today, and what still requires a human or a heavier tool:

| Signal | Analyzer | Network? | Covered? |
|---|---|---|---|
| Missing lockfile (npm/yarn/pnpm) | `lockfile` | no | ✅ |
| Install/postinstall scripts in `package-lock.json` | `lockfile` | no | ✅ |
| Install/build scripts in `pnpm-lock.yaml` (`requiresBuild`) | `lockfile` | no | ✅ (best-effort — pnpm's lockfile schema has shifted across versions) |
| Install scripts in `yarn.lock`-only projects | — | — | ❌ classic `yarn.lock` carries no script metadata at all; detecting it needs a registry lookup, which this analyzer deliberately doesn't do |
| npm `lockfileVersion: 1` (pre-npm-7) lockfiles | `lockfile` | no | ✅ flagged at low severity — v1 has no per-package metadata, so install-script detection is silently blind on it; upgrading the lockfile format is the fix |
| Unpinned `requirements.txt` entries | `lockfile` | no | ✅ |
| Unpinned `pyproject.toml` `[project.dependencies]` | `lockfile` | no | ✅ on Python 3.10+ (tomli backport on 3.10), suppressed when a `poetry.lock`/`uv.lock` resolves the dependency to an exact version regardless of the range in the manifest |
| Typosquat package names (`expres` vs `express`) | `typosquat` | no | ✅ edit-distance ≤2 against a bundled, curated (not download-ranked) list — expect false negatives for anything not on the list, and treat hits as "look closer," not proof. Also checks `pyproject.toml` deps, and scoped npm packages both by their unscoped part (`@myorg/expres`) and by scope lookalike (`@type/x` vs the real `@types/x`). Suppressible per-name via `supply_chain.typosquat_allow` |
| Known CVEs/advisories for pinned versions | `osv` (opt-in) | **yes**, OSV.dev | ✅ when enabled — resolves versions from `requirements.txt`/`pyproject.toml` exact pins and `poetry.lock`/`uv.lock`, with the lockfile winning on conflict |
| Known-malicious package versions | `osv` (opt-in) | **yes**, OSV.dev | ✅ when enabled — OSV ingests the OpenSSF malicious-packages feed as `MAL-*` advisories |
| CycloneDX SBOM from supported lockfiles/manifests | `gatekeeper sbom` | no | ✅ npm package-lock (v1-v3), exact requirements.txt pins, poetry.lock, uv.lock |
| Dependency-confusion exposure for configured internal names/scopes | `dependency_confusion` | no | ✅ verifies repo config binds private npm/PyPI names to private registries; does not claim a public-name collision without an online check |
| Runtime/dynamic analysis of install scripts (sandboxed execution) | — | — | ❌ roadmap only, see below — this is a real isolation/infra project (container runtime, syscall monitoring), not something bolted on statically |
| Trust drift vs a previously reviewed dependency posture | `trust_drift` | no | ✅ source/integrity/install-script/direct-source/dependency-edge/dependency-expansion changes |
| Static package-content drift | `content` / `inspect npm` | local: no; registry inspect: **yes** | ✅ file/hash/capability/native-binary comparison; registry mode verifies tarball integrity and never executes package code |
| In-place compromise of an *already-baselined* dependency | `lockfile` | no | ✅ partial — the install-script finding's fingerprint includes the version, so a version bump resurfaces for review even if an older version was already accepted. This only fires when `hasInstallScript`/`requiresBuild` is the signal; a compromise that doesn't touch that flag (e.g. malicious code with no new lifecycle script) won't be caught by static lockfile parsing — `osv` may catch it if the compromised version gets a published advisory |

**Python 3.10 support:** `pyproject.toml`/`poetry.lock`/`uv.lock` parsing uses
the standard-library `tomllib` on Python 3.11+ and the conditional `tomli`
backport on Python 3.10, so manifest and lockfile coverage is consistent across
all supported Python versions.

**Judgment call worth knowing about:** flagging a bare `dependencies =
["typer>=0.12", ...]` in `pyproject.toml` as "unpinned" (when there's no
`poetry.lock`/`uv.lock`) is debatable for a redistributable library — range
specifiers there are normal, PyPA-recommended practice, not a supply-chain
gap the way an unpinned `requirements.txt` (meant for reproducible installs)
is. This repo's own `pyproject.toml` gets flagged by its own rule as a result.
Implemented as specified; loosen `supply_chain.unpinned_python_deps` or add a
`typosquat_allow`-style exclusion if that's too noisy for a library project.

`osv` is opt-in and off by default specifically because it's the only analyzer here that leaves the machine: enable it with `analyzers: { osv: { enabled: true, required: false } }`. `required: false` is recommended so an OSV.dev outage doesn't fail CI closed for a best-effort network check.

## Design principles

- **Fail closed.** Tool crash or missing required analyzer ⇒ scan fails.
- **Structured output only.** Analyzers are parsed from JSON, never scraped.
- **Static-first supply chain.** Lockfile checks execute nothing and need no
  network; reading `package-lock.json` is safe, running `npm install` is not.
  The one documented exception is the opt-in `osv` analyzer, which is
  disabled by default precisely because it breaks this rule.
- **Baseline, don't bankrupt.** Legacy debt is recorded and visible; only
  regressions block.
- **Minimal, pinned dependencies.** Three runtime deps (typer, rich, pyyaml);
  analyzer tools are optional extras.

## Development

```bash
git clone https://github.com/nalkaslassy/gatekeeper.git
cd gatekeeper
pip install -e ".[analyzers,dev]"   # editable install + ruff/bandit + pytest

pytest -q            # ~100 tests, fully offline, under a second
ruff check .          # lint
gatekeeper scan .     # dogfood: this repo scans itself
```

CI (`.github/workflows/ci.yml`) runs the same three commands on Python 3.10
and 3.12 on every push/PR, plus uploads a SARIF report to the repo's
Security → Code scanning tab.

**Releasing:** `.github/workflows/release.yml` builds and publishes to PyPI
via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC —
no API token stored in the repo) whenever a `v*` tag is pushed. It has never
been run; see the one-time PyPI setup this needs before the first release.

## Roadmap

Server mode with sandboxed test execution (rootless Docker → gVisor →
Firecracker path) — a real isolation/infra project, intentionally not
attempted as a bolt-on to the static analyzers — plus dependency-confusion
optional online confirmation of public registry name collisions, Verdaccio registry mirroring with `npm ci --ignore-scripts`, and an
MCP server so agents can query scan results. Static dependency-confusion exposure checks and CycloneDX SBOM generation
is available today via `gatekeeper sbom`.
See `docs/design.md` for the full architecture.
