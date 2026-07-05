# Gatekeeper

Validate code for correctness, quality, and supply-chain security — before it merges.

Gatekeeper runs lint, SAST, secret scanning, and dependency/lockfile analysis
against your repo, compares results to a committed baseline, and fails only on
**new** findings above your policy threshold. Supply-chain checks (missing
lockfiles, npm install scripts, unpinned dependencies) run from pure static
parsing — no network, no code execution.

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

Copy `action/example-workflow.yml` to `.github/workflows/gatekeeper.yml`.
PRs get a required status check, and findings land in the repo's
**Security → Code scanning** tab via SARIF.

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
  ruff:     { enabled: true }
  bandit:   { enabled: true }
  gitleaks: { enabled: true, required: false }
  lockfile: { enabled: true }

supply_chain:
  require_lockfile: high       # package.json without package-lock.json
  install_scripts: warn        # allow | warn | block
  unpinned_python_deps: medium # requirements.txt entries without '=='
```

Policy lives in the repo, so loosening it is itself a reviewable diff.

## Design principles

- **Fail closed.** Tool crash or missing required analyzer ⇒ scan fails.
- **Structured output only.** Analyzers are parsed from JSON, never scraped.
- **Static-first supply chain.** Lockfile checks execute nothing and need no
  network; reading `package-lock.json` is safe, running `npm install` is not.
- **Baseline, don't bankrupt.** Legacy debt is recorded and visible; only
  regressions block.
- **Minimal, pinned dependencies.** Three runtime deps (typer, rich, pyyaml);
  analyzer tools are optional extras.

## Roadmap

Server mode with sandboxed test execution (rootless Docker → gVisor →
Firecracker path), OSV vulnerability lookup, typosquat and dependency-confusion
detection, SBOM generation, Verdaccio registry mirroring with `npm ci
--ignore-scripts`, and an MCP server so agents can query scan results.
See `docs/design.md` for the full architecture.
