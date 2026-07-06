# Gatekeeper

[![CI](https://github.com/nalkaslassy/gatekeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/nalkaslassy/gatekeeper/actions/workflows/ci.yml)

Validate code for correctness, quality, and supply-chain security — before it merges.

Gatekeeper runs lint, SAST, secret scanning, and dependency/lockfile analysis
against your repo, compares results to a committed baseline, and fails only on
**new** findings above your policy threshold. Supply-chain checks (missing
lockfiles across npm/yarn/pnpm, install scripts, unpinned dependencies across
`requirements.txt`/`pyproject.toml`/`poetry.lock`/`uv.lock`, typosquat package
names including scoped npm packages) run from pure static parsing — no
network, no code execution. An opt-in `osv` analyzer adds known-CVE and
known-malicious-package lookup via OSV.dev for repos willing to trade that one
static-first guarantee for broader coverage. See
[Supply-chain coverage](#supply-chain-coverage) for exactly what is and isn't
caught.

## Quickstart (60 seconds)

```bash
pip install "gatekeeper-cli[analyzers]"

cd your-repo
gatekeeper policy init .        # writes gatekeeper.yaml — commit it
gatekeeper scan .               # exit 0 = pass, 1 = blocking findings
```

Adopting on a codebase with existing debt? Record it, then block only regressions:

```bash
gatekeeper baseline .           # writes .gatekeeper-baseline.json — commit it
gatekeeper scan .               # now fails only on NEW findings
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
| `gatekeeper scan [PATH]` | Run analyzers, print report, exit 0/1/2 |
| `gatekeeper scan --format json\|sarif --output FILE` | Machine-readable reports |
| `gatekeeper scan --fail-on medium` | Override the policy threshold |
| `gatekeeper scan --analyzers lockfile,bandit` | Run a subset |
| `gatekeeper baseline [PATH]` | Record current findings as accepted baseline |
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
```

Policy lives in the repo, so loosening it is itself a reviewable diff.

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
| Unpinned `pyproject.toml` `[project.dependencies]` | `lockfile` | no | ✅ (Python 3.11+ only — see note below), suppressed when a `poetry.lock`/`uv.lock` resolves the dependency to an exact version regardless of the range in the manifest |
| Typosquat package names (`expres` vs `express`) | `typosquat` | no | ✅ edit-distance ≤2 against a bundled, curated (not download-ranked) list — expect false negatives for anything not on the list, and treat hits as "look closer," not proof. Also checks `pyproject.toml` deps, and scoped npm packages both by their unscoped part (`@myorg/expres`) and by scope lookalike (`@type/x` vs the real `@types/x`). Suppressible per-name via `supply_chain.typosquat_allow` |
| Known CVEs/advisories for pinned versions | `osv` (opt-in) | **yes**, OSV.dev | ✅ when enabled — resolves versions from `requirements.txt`/`pyproject.toml` exact pins and `poetry.lock`/`uv.lock`, with the lockfile winning on conflict |
| Known-malicious package versions | `osv` (opt-in) | **yes**, OSV.dev | ✅ when enabled — OSV ingests the OpenSSF malicious-packages feed as `MAL-*` advisories |
| Dependency confusion (internal name resolvable on public registry) | — | — | ❌ not built |
| Runtime/dynamic analysis of install scripts (sandboxed execution) | — | — | ❌ roadmap only, see below — this is a real isolation/infra project (container runtime, syscall monitoring), not something bolted on statically |
| In-place compromise of an *already-baselined* dependency | `lockfile` | no | ✅ partial — the install-script finding's fingerprint includes the version, so a version bump resurfaces for review even if an older version was already accepted. This only fires when `hasInstallScript`/`requiresBuild` is the signal; a compromise that doesn't touch that flag (e.g. malicious code with no new lifecycle script) won't be caught by static lockfile parsing — `osv` may catch it if the compromised version gets a published advisory |

**Note on Python 3.10:** `pyproject.toml`/`poetry.lock`/`uv.lock` parsing uses
the stdlib `tomllib`, which doesn't exist before Python 3.11. Rather than add
a `tomli` backport as a new runtime dependency for one still-supported minor
version, these three checks simply find nothing on 3.10 — `requirements.txt`
parsing is unaffected on any supported version.

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
detection, SBOM generation, Verdaccio registry mirroring with `npm ci
--ignore-scripts`, and an MCP server so agents can query scan results.
See `docs/design.md` for the full architecture.
