# Gatekeeper — Code Validation & Supply-Chain Security Platform

*Design document — working name "Gatekeeper," rename freely.*

Gatekeeper is a self-hostable platform that validates code for correctness, quality, and security before merge or deploy. Developers point it at a repository (or wire it into CI), and it runs a policy-driven pipeline of tests, linters, static analysis, secret scanning, and dependency/supply-chain checks inside isolated sandboxes, then produces a pass/fail verdict with an evidence report and SBOM. The platform practices what it preaches: its own codebase is built to minimize npm exposure, pin everything, and run untrusted code only in locked-down environments.

---

## 1. Core Features

**Validation pipeline.** A configurable sequence of checks per repository: unit tests, integration tests, linting, formatting, type checking, static analysis (SAST), secret scanning, dependency vulnerability scanning, license scanning, and supply-chain risk analysis. Each check is a pluggable "analyzer" that runs in its own sandbox and emits normalized findings.

**Policy engine.** Teams define policies as code (YAML): which checks are required, severity thresholds that block a merge (e.g., "fail on any HIGH CVE with a known exploit," "fail on any new secret," "fail if a new dependency has install scripts"), allowlists/denylists for packages, and minimum-package-age rules. Policies are versioned in the repo itself so they're reviewable like any other change.

**Supply-chain guard.** Lockfile-aware dependency analysis: known-vulnerability lookup (OSV), typosquat detection, dependency-confusion detection, install-script flagging, maintainer/publish anomaly signals, provenance verification, and SBOM generation (CycloneDX) for every scan.

**Sandboxed execution.** Anything that executes repository code (tests, builds, install steps) runs in an ephemeral, network-restricted, resource-limited sandbox. Static-only analyzers never execute repo code at all.

**Reports and verdicts.** A single scan produces: a verdict (pass / fail / warn), a findings list deduplicated against previous scans (so you see *new* findings vs. baseline), an SBOM artifact, and a signed scan attestation you can attach to a release.

**Integrations.** GitHub webhook + status check (block merge on fail), a CLI for local pre-push runs, and a REST API for CI systems.

**Baseline & triage.** First scan establishes a baseline; subsequent scans highlight regressions. Findings can be triaged (accepted-risk, false-positive, fixed) with an audit trail, so legacy debt doesn't permanently block merges while new issues do.

---

## 2. Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              Control Plane              │
  GitHub webhook ──────►│  API Server (FastAPI)                   │
  CLI / CI ────────────►│  - Auth, projects, policies             │
  Web UI ──────────────►│  - Scan orchestration                   │
                        │  - Findings & report service            │
                        └───────┬─────────────────────┬───────────┘
                                │ enqueue jobs        │ read/write
                                ▼                     ▼
                        ┌──────────────┐      ┌──────────────────┐
                        │  Job Queue   │      │  PostgreSQL      │
                        │  (Redis)     │      │  + object store  │
                        └──────┬───────┘      │  (S3/MinIO: logs,│
                               │              │  SBOMs, reports) │
                               ▼              └──────────────────┘
                ┌──────────────────────────────┐
                │        Worker Fleet          │
                │  Orchestrator process pulls  │
                │  jobs, provisions sandboxes  │
                └──────┬──────────┬────────────┘
                       │          │
             ┌─────────▼───┐  ┌───▼──────────────┐
             │ Static      │  │ Execution        │
             │ sandbox     │  │ sandbox          │
             │ (no code    │  │ (gVisor/Firecracker,
             │ execution,  │  │ no network or     │
             │ no network) │  │ egress-proxy only) │
             └─────────────┘  └──────────────────┘
                       │          │
                       └────┬─────┘
                            ▼
                  Normalized findings (SARIF-ish JSON)
                  back to control plane via queue
```

Key separations:

- **Control plane never executes user code.** It only clones metadata, schedules jobs, and stores results.
- **Workers are cattle.** Each scan job gets a fresh sandbox from a pre-built image; sandboxes are destroyed after the job. A compromised sandbox can't reach the database — workers communicate results only through the queue with a per-job token.
- **Two sandbox classes.** Static analyzers (linting, SAST, secret scan, lockfile parsing) run with **zero network and zero code execution** of the target repo. Execution analyzers (tests, builds) run in a hardened microVM/gVisor sandbox with no network by default, or an egress allowlist proxy when dependency installation is unavoidable.
- **Artifact store is append-only** from the workers' perspective (write-once presigned URLs), so a malicious test suite can't tamper with prior reports.

---

## 3. Recommended Tech Stack

Chosen to be strong for your portfolio (plays to your Python/FastAPI/AWS background) while deliberately minimizing npm surface area in the product itself.

| Layer | Choice | Why |
|---|---|---|
| API server | **Python 3.12 + FastAPI + Pydantic** | Your strength; great OpenAPI docs; async fits webhook + orchestration workloads |
| Job queue | **Redis + arq** (or Postgres `SELECT ... FOR UPDATE SKIP LOCKED` for MVP) | Simple, inspectable; Postgres-only queue removes a dependency for v0 |
| Database | **PostgreSQL 16** | JSONB for raw findings, relational for everything else |
| Object storage | **S3 / MinIO** | Logs, SBOMs, reports as immutable artifacts |
| Sandbox runtime | **Docker (rootless) for MVP → gVisor (`runsc`) → Firecracker microVMs** | Progressive hardening path; see §5 |
| Worker orchestrator | **Python** (MVP) with an eye toward a **Go** rewrite of just the runner | Go gives a single static binary with no runtime deps for the piece that touches untrusted code |
| Frontend | **Server-rendered Jinja2 + htmx + one vendored CSS file** | Reduces npm exposure in the core product (scanning JS/TS targets still requires npm-aware tooling in analyzer containers). If you later want a richer UI, add a small Vite/React app governed by the same npm policy in §7 — that itself becomes a portfolio talking point |
| Analyzers (wrapped tools) | Semgrep, Ruff, mypy, Bandit, pytest, ESLint, tsc, gitleaks or TruffleHog, **osv-scanner**, **Syft** (SBOM) + **Grype**, Trivy | Industry-standard, all runnable offline in containers |
| Auth | GitHub OAuth + PATs for API | Matches the GitHub-centric workflow |
| Infra | Docker Compose (dev) → single EC2/ECS or k8s later | Keep MVP deployable in one command |

Notable non-choice: **no Node.js in the control plane.** JavaScript/TypeScript repos are still fully supported as *scan targets* — ESLint, tsc, and npm-ecosystem checks run inside analyzer containers — but the platform itself doesn't depend on npm to exist.

---

## 4. How Code Validation Works

A scan is a DAG of analyzer jobs. Stages that don't depend on each other run in parallel.

**Stage 0 — Ingest (control plane, no execution).**
Shallow-clone the target ref into a tarball, compute a tree hash, detect languages and manifests (`package.json`, `pyproject.toml`, `requirements.txt`, `go.mod`, lockfiles), and load the repo's `gatekeeper.yaml` policy. The tarball is uploaded to object storage; workers pull it from there — workers never get repo credentials.

**Stage 1 — Static checks (static sandbox, parallel).**
- *Formatting & lint:* Ruff / ESLint / language-appropriate linters, run in check-only mode.
- *Type checks:* mypy / tsc (`--noEmit`) — note tsc type-checks without executing code.
- *SAST:* Semgrep with curated rulesets (OWASP, language-specific) + Bandit for Python.
- *Secret scan:* gitleaks over the full git history, not just the working tree — leaked-then-deleted secrets are still leaked.
- *Lockfile & manifest analysis:* pure parsing, feeds Stage 2.

**Stage 2 — Dependency & supply-chain (static sandbox).**
SBOM generation (Syft → CycloneDX), OSV/Grype vulnerability lookup, and the supply-chain heuristics from §6. This stage requires network access *only* to vulnerability databases, satisfied by a locally mirrored OSV/advisory DB refreshed on a schedule — so the sandbox itself still needs no egress.

**Stage 3 — Execution checks (execution sandbox, only if policy enables them).**
Dependency installation (under the controls in §7), then unit tests and integration tests with coverage. Test output is parsed from JUnit XML / pytest JSON, never trusted as free text.

**Stage 4 — Aggregate & verdict (control plane).**
All analyzers emit findings in a normalized schema (rule id, severity, file, line, fingerprint). The engine fingerprints each finding (hash of rule + normalized location + code context) to dedupe against the baseline, applies policy thresholds, and produces the verdict. New findings above threshold ⇒ fail; baseline findings ⇒ warn unless policy says otherwise.

Every analyzer runs with a hard timeout, CPU/memory caps, and produces logs streamed to the artifact store. A crashed analyzer yields an `error` finding rather than a silent pass — **fail closed, never open.**

---

## 5. Safely Running Untrusted Code

Treat every scanned repository as actively malicious. A test suite is arbitrary code execution by definition — someone *will* eventually point Gatekeeper at a repo whose `conftest.py` or test file tries to escape.

**Isolation layers (defense in depth):**

1. **Ephemeral sandbox per job.** Fresh container/microVM from a read-only golden image; destroyed after the job. Nothing persists between scans.
2. **Kernel isolation.** MVP: rootless Docker with a strict seccomp profile, `--cap-drop=ALL`, `no-new-privileges`, read-only root FS with a small tmpfs for scratch. These are legitimate hardening controls that meaningfully reduce risk, but they are **not equivalent to VM isolation** — the untrusted code still talks to the shared host kernel. Hence the phased path: **gVisor** (`runsc`) next, so untrusted code hits a userspace kernel instead of the host kernel; then **Firecracker-style microVMs**, which are used by several sandboxed compute platforms precisely because they provide stronger isolation than containers.
3. **No network by default.** `--network=none` for test execution. When installs are required, the sandbox gets access *only* to an egress proxy that allowlists your internal registry mirror (§7). No arbitrary outbound connections — this single control neuters most data-exfiltration and reverse-shell payloads, and blocks malicious postinstall scripts from phoning home.
4. **Resource ceilings.** CPU quota, memory limit, PID limit (fork-bomb protection), disk quota on the scratch tmpfs, wall-clock timeout. Enforced by the runtime, not by the code inside.
5. **Non-root, unprivileged user** inside the sandbox, with user-namespace remapping so even a container escape lands on an unprivileged host UID.
6. **Least-privilege result channel.** The sandbox can do exactly two things externally: PUT artifacts to a single-use presigned URL, and POST results to the queue with a per-job scoped token that expires when the job ends. It cannot read other jobs' data, reach the database, or hit cloud metadata endpoints (block 169.254.169.254 explicitly — classic sandbox-escape target).
7. **Host hardening.** Workers run on dedicated instances (never co-located with the control plane), with IMDSv2 enforced, minimal IAM, and auditd/Falco watching for anomalies.

**What never runs in a sandbox at all:** parsing lockfiles, reading manifests, secret scanning, SAST. These are done by *your* trusted tools reading untrusted *data* — dangerous input handling, but no untrusted execution. Keep that boundary crisp: `npm install` is code execution (lifecycle scripts); reading `package-lock.json` is not.

---

## 6. Dependency Scanning & Supply-Chain Risk Detection

The stance: npm (and PyPI) are not inherently unsafe, but the ecosystem's real incident history — compromised maintainer accounts, malicious postinstall payloads, typosquats, dependency confusion — means every dependency change deserves automated scrutiny. This is not theoretical: CISA has issued alerts on widespread npm supply-chain compromises (2025–2026), with guidance that includes pinning known-safe versions and rotating potentially exposed credentials. Gatekeeper's controls map directly onto that guidance.

**a) Known vulnerabilities.** Parse lockfiles (`package-lock.json`, `poetry.lock`, `uv.lock`, `go.sum`) without any install step, resolve the exact pinned versions, and query a locally mirrored **OSV** database plus **Grype** against the Syft SBOM. Report CVE, severity, fixed version, and whether a known exploit exists (CISA KEV enrichment) — a HIGH with a public exploit should outrank a CRITICAL that's theoretical.

**b) SBOM on every scan.** CycloneDX JSON stored as an artifact and diffed between scans: "this PR adds 3 direct and 47 transitive packages" is itself a reviewable finding.

**c) Typosquat detection.** For each *newly added* package, compute edit distance and common-substitution patterns (`1`↔`l`, hyphen shuffles, scope tricks like `@types/lodash` vs `@type/lodash`) against a cached list of the top ~10k packages by downloads. New package within edit distance 1–2 of a popular one, with low downloads and young age ⇒ high-severity finding.

**d) Install-script flagging.** Statically read each npm package's manifest for `preinstall` / `install` / `postinstall` scripts. Policy options: warn, block unless allowlisted, or block always. The overwhelming majority of packages need no install scripts; the ones that do (native builds) are exactly the ones deserving human review.

**e) Dependency confusion.** Detect internal/scoped package names in manifests and verify the registry configuration (`.npmrc` scope mapping, `pip.conf` index) actually pins them to the private registry. An internal-looking name resolvable from the public registry is a critical finding — this is the exact mechanism of the classic dependency-confusion attacks.

**f) Package anomaly signals** (metadata-only, from registry APIs via your mirror):
- Version published in the last N days (configurable **cooldown / quarantine period** — many compromised versions are detected and unpublished within days of release, so refusing to adopt versions younger than, say, 7–14 days can reduce exposure to newly published malicious versions — a risk-reduction measure, not a guarantee)
- Maintainer set changed recently; package ownership transferred
- Version jump anomalies; package suddenly adds install scripts or new binary blobs when previous versions had none
- Unusually large size delta between versions

**g) Provenance & integrity.** Verify lockfile integrity hashes match registry tarballs. npm supports Sigstore-backed provenance attestations, but adoption is partial — so verify provenance **where available**, treat its absence as an informational signal rather than a failure (policy can escalate this for high-privilege packages), and flag Git-URL and tarball-URL dependencies (unpinnable, unauditable) as findings.

**h) License scan.** From the SBOM, flag licenses outside the policy allowlist (GPL in a proprietary codebase, etc.).

All signals feed a per-package **risk score**, but policy acts on the individual signals (transparent, explainable) rather than only the composite number.

---

## 7. Minimizing & Controlling NPM Usage

Two distinct problems: reducing npm exposure in *your platform*, and safely handling npm in *scanned projects*. The goal is not to avoid npm — scanning JS/TS projects inherently requires npm-aware tooling — but to keep npm usage deliberate, pinned, and contained.

**In the platform itself:**
- Control plane is pure Python; frontend is server-rendered with htmx and vendored static assets — no `node_modules` in the control plane itself. npm-aware tooling lives exclusively inside pinned analyzer container images.
- If a richer SPA is ever added, it lives in an isolated workspace with: exact-version pinning (no `^`/`~`), `npm ci --ignore-scripts` as the only install command, a committed lockfile, `overrides` for transitive pins, a tiny dependency budget (target < 15 direct deps), and its own Gatekeeper policy — the tool scans itself in CI. Dogfooding is the portfolio story.

**For scanned projects (when Stage 3 needs an install):**
1. **Lockfile required.** No lockfile ⇒ policy finding, and installs run in a stricter mode or not at all. Install command is always `npm ci`, never `npm install` — reproducible, lockfile-exact.
2. **`--ignore-scripts` by default.** Lifecycle scripts are disabled globally (`.npmrc: ignore-scripts=true`). Packages that genuinely need builds (native addons) must be explicitly allowlisted in policy, and even then their scripts run inside the same no-network sandbox.
3. **Private registry mirror** (Verdaccio or Artifactory) as the *only* reachable registry through the egress proxy. The mirror enforces: package allowlist/denylist, minimum-age quarantine from §6f, and caching (so a package pulled from the registry today is byte-identical next week — protection against post-publish tampering).
4. **Integrity verification.** `npm ci` already verifies lockfile SHA-512 integrity hashes; the mirror adds a second checkpoint by refusing tarballs whose hashes changed for an existing version.
5. **Frozen environments elsewhere too.** Same philosophy for Python (`uv sync --frozen` / `pip install --require-hashes`) and Go (modules are content-addressed via `go.sum` already — hold npm to that standard).
6. **Install ≠ test.** Dependency installation runs as its own sandbox phase; the resulting `node_modules` is snapshotted and the test phase starts from that snapshot with **network fully disabled**. Even if something malicious got installed, it executes with no egress.

---

## 8. Database Schema

```sql
-- Tenancy & auth
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id     BIGINT UNIQUE,
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id),
    token_hash    TEXT NOT NULL,          -- store only the hash
    name          TEXT,
    scopes        TEXT[] NOT NULL,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id      UUID NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    repo_url      TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_id, name)
);

-- Policy as versioned config
CREATE TABLE policies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id),
    version       INT  NOT NULL,
    source        TEXT NOT NULL,          -- raw YAML
    compiled      JSONB NOT NULL,         -- validated/normalized form
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, version)
);

-- Scans & jobs
CREATE TABLE scans (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id),
    policy_id     UUID REFERENCES policies(id),
    commit_sha    TEXT NOT NULL,
    ref           TEXT,                   -- branch / PR ref
    trigger       TEXT NOT NULL,          -- webhook | cli | api | schedule
    status        TEXT NOT NULL DEFAULT 'queued',
                  -- queued|running|passed|failed|warned|errored|canceled
    verdict       JSONB,                  -- per-policy-rule outcomes
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scan_jobs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID NOT NULL REFERENCES scans(id),
    analyzer      TEXT NOT NULL,          -- ruff|semgrep|gitleaks|osv|pytest|...
    sandbox_class TEXT NOT NULL,          -- static | execution
    status        TEXT NOT NULL DEFAULT 'queued',
    exit_code     INT,
    log_url       TEXT,                   -- object-store pointer
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ
);

-- Findings with baseline-aware fingerprints
CREATE TABLE findings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID NOT NULL REFERENCES scans(id),
    job_id        UUID REFERENCES scan_jobs(id),
    fingerprint   TEXT NOT NULL,          -- stable hash for dedupe/baseline
    category      TEXT NOT NULL,          -- lint|sast|secret|vuln|supply_chain|test|license
    rule_id       TEXT NOT NULL,
    severity      TEXT NOT NULL,          -- critical|high|medium|low|info
    title         TEXT NOT NULL,
    file_path     TEXT,
    line          INT,
    detail        JSONB,                  -- tool-specific payload
    is_new        BOOLEAN NOT NULL DEFAULT true,   -- vs project baseline
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX findings_scan_idx ON findings (scan_id, severity);
CREATE INDEX findings_fp_idx   ON findings (fingerprint);

CREATE TABLE triage_decisions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id),
    fingerprint   TEXT NOT NULL,
    decision      TEXT NOT NULL,          -- accepted_risk|false_positive|fixed
    reason        TEXT,
    decided_by    UUID REFERENCES users(id),
    expires_at    TIMESTAMPTZ,            -- accepted-risk should expire
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, fingerprint)
);

-- Dependency graph & package intelligence
CREATE TABLE packages (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem     TEXT NOT NULL,          -- npm|pypi|go|...
    name          TEXT NOT NULL,
    UNIQUE (ecosystem, name)
);

CREATE TABLE package_versions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id    UUID NOT NULL REFERENCES packages(id),
    version       TEXT NOT NULL,
    published_at  TIMESTAMPTZ,
    has_install_scripts BOOLEAN,
    integrity     TEXT,                   -- registry tarball hash
    risk_signals  JSONB,                  -- typosquat score, maintainer changes, size delta...
    UNIQUE (package_id, version)
);

CREATE TABLE scan_dependencies (
    scan_id            UUID NOT NULL REFERENCES scans(id),
    package_version_id UUID NOT NULL REFERENCES package_versions(id),
    direct             BOOLEAN NOT NULL,
    newly_added        BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (scan_id, package_version_id)
);

CREATE TABLE artifacts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID NOT NULL REFERENCES scans(id),
    kind          TEXT NOT NULL,          -- sbom|report|log|attestation
    url           TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## 9. API Endpoints

```
Auth
  POST   /v1/auth/github/callback        OAuth exchange
  POST   /v1/tokens                      Create API token
  DELETE /v1/tokens/{id}

Projects & policy
  POST   /v1/projects                    Register a repo
  GET    /v1/projects
  GET    /v1/projects/{id}
  PUT    /v1/projects/{id}/policy        Upload/validate gatekeeper.yaml
  GET    /v1/projects/{id}/policy
  POST   /v1/projects/{id}/policy/validate   Dry-run a policy file

Scans
  POST   /v1/projects/{id}/scans         Trigger scan {ref|commit_sha}
  GET    /v1/scans/{id}                  Status + verdict
  GET    /v1/scans/{id}/findings         Filter: ?severity=&category=&new_only=
  GET    /v1/scans/{id}/sbom             CycloneDX JSON
  GET    /v1/scans/{id}/report           Human-readable report (HTML/MD)
  GET    /v1/scans/{id}/jobs/{job}/logs
  POST   /v1/scans/{id}/cancel

Triage
  POST   /v1/projects/{id}/triage        {fingerprint, decision, reason, expires_at}
  GET    /v1/projects/{id}/triage

Supply chain
  GET    /v1/packages/{eco}/{name}/{ver} Cached risk intel for a package version
  GET    /v1/projects/{id}/dependencies  Current dependency inventory + diff vs prev

Integrations
  POST   /v1/webhooks/github             PR opened/synchronized → scan → status check
  GET    /v1/projects/{id}/badge.svg     Pass/fail badge for the README
```

CI usage is one call + poll (or a webhook back): `POST scans` → poll `GET /v1/scans/{id}` → exit nonzero on `failed`. The CLI wraps exactly this.

---

## 10. MVP Plan

**Phase 1 — Core loop (2–3 weeks).** FastAPI + Postgres + a Postgres-backed job queue. One worker running rootless-Docker sandboxes with `--network=none`, cap-drop, resource limits. Python-only targets: Ruff, Bandit, gitleaks, pytest-in-sandbox. Normalized findings, pass/fail verdict, CLI (`gatekeeper scan .`), scan-by-API. *Deliverable: point it at a repo, get a verdict.*

**Phase 2 — Supply chain (2 weeks).** Syft SBOM, lockfile parsing for npm + PyPI, OSV vulnerability lookup (local mirror), install-script flagging, typosquat check for newly added packages, dependency diffing. Policy file (`gatekeeper.yaml`) with severity thresholds. *Deliverable: the differentiating feature set.*

**Phase 3 — JS/TS targets + hardened installs (2 weeks).** ESLint/tsc analyzers; execution-sandbox install phase with `npm ci --ignore-scripts`, egress proxy + Verdaccio mirror, install/test phase separation. *Deliverable: safely scan real npm projects.*

**Phase 4 — GitHub integration + UI (1–2 weeks).** Webhook, PR status checks, badge endpoint, minimal htmx dashboard (project list, scan detail, findings table, SBOM diff). Baseline/triage flow. *Deliverable: demo-able end-to-end story.*

**Phase 5 — Hardening pass (1 week).** gVisor runtime, signed scan attestations, threat-model writeup in the README, Gatekeeper scanning its own repo in CI. *Deliverable: the security narrative that makes it portfolio-grade.*

Scope discipline: single-node deploy via Docker Compose, two ecosystems (Python, npm), GitHub only. Firecracker, more ecosystems, and multi-tenant SaaS are all explicitly out of MVP scope.

---

## 11. Security Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Sandbox escape from malicious test code | Defense in depth: rootless containers → gVisor → Firecracker; seccomp, cap-drop, user-ns remap; dedicated worker hosts; no secrets on workers |
| Data exfiltration from sandbox | `--network=none` for execution; egress allowlist proxy for install phase only; block metadata IPs (169.254.169.254) |
| Malicious install scripts | `ignore-scripts=true` globally; allowlist exceptions run sandboxed without network |
| Dependency confusion against the platform or targets | Registry scope verification finding; mirror is sole reachable registry; internal names denylisted on public resolution |
| Compromised upstream package version | Version quarantine/cooldown, mirror caching + immutable hashes, publish-anomaly signals, OSV/KEV feeds |
| Result forgery (sandbox lies about passing) | Workers can't write verdicts — only raw analyzer output; control plane parses structured output (JUnit XML) and computes verdicts itself; per-job tokens; artifacts write-once |
| SSRF via repo URLs / webhook payloads | Strict URL validation, resolve-and-check against private IP ranges, clone through a dedicated fetcher with its own egress rules |
| Secrets in the platform | GitHub tokens encrypted at rest (KMS), never mounted into sandboxes; scans clone via short-lived deploy tokens; API tokens stored hashed |
| Log/report injection (findings containing HTML/ANSI/terminal escapes) | Escape everything at render; treat all analyzer output as hostile data |
| Zip-bomb / giant-repo DoS | Repo size caps, file-count caps, per-job disk/CPU/time quotas, queue rate limits per project |
| Vulnerable analyzers themselves (Semgrep etc. parsing hostile files) | Analyzers run inside the same sandboxes; pinned analyzer images rebuilt on a schedule; Gatekeeper scans its own images with Trivy |
| Policy tampering in-PR (attacker edits gatekeeper.yaml to disable checks) | Policy changes flagged as a distinct high-visibility finding; option to pin policy server-side and ignore in-repo overrides for protected branches |
| Webhook spoofing | GitHub HMAC signature verification, replay-window checks |

---

## 12. Example User Flow

1. Nadav signs in with GitHub and registers `nalkaslassy/capitol-radar` as a project. Gatekeeper suggests a starter `gatekeeper.yaml`; he commits it: Ruff + Bandit + gitleaks + pytest required, fail on new HIGH vulns, block packages younger than 7 days, block install scripts.
2. He opens a PR that adds a new npm dependency for a dashboard component. The webhook fires; Gatekeeper posts a pending status check.
3. Stage 1 runs in parallel static sandboxes: lint passes, Semgrep flags one MEDIUM (unsanitized string into a shell call), gitleaks is clean.
4. Stage 2 parses the lockfile diff: the PR adds 1 direct + 12 transitive packages. One transitive package is 3 days old **and** newly added a `postinstall` script that its previous version didn't have. Two policy violations → HIGH supply-chain findings.
5. Stage 3 runs anyway for evidence: `npm ci --ignore-scripts` against the Verdaccio mirror in the execution sandbox, then tests with network disabled — 214 tests pass.
6. Verdict: **failed** — 2 new HIGH supply-chain findings, 1 new MEDIUM SAST finding. The PR status check goes red with a link to the report showing exactly which package, which signal, and the SBOM diff.
7. He swaps the dependency for a mature alternative (or pins to the older, script-free version), pushes, and the re-scan passes. The MEDIUM SAST finding he fixes properly; the report shows "0 new findings vs baseline." Status check green, merge unblocked.
8. On merge to `main`, a scheduled scan generates the release SBOM and a signed attestation stored alongside the artifacts.

---

## 13. Future Feature Ideas

- **AI-assisted triage (Claude API):** summarize a scan into a reviewer-friendly narrative, classify likely false positives with cited reasoning, and propose minimal-diff fixes for lint/SAST findings — humans approve, findings stay ground truth. Natural fit for your Claude/MCP background, and an **MCP server exposing scan results** would let Claude Code query "what's blocking this PR?" directly.
- **Firecracker microVM runtime** and a Go-rewritten runner binary.
- **More ecosystems:** Go, Rust (cargo-audit), Java (Maven), containers (Dockerfile lint + image scan).
- **Runtime behavior sandbox:** actually execute suspicious packages' install scripts in an instrumented sandbox (strace/eBPF) and report syscall/network behavior — dynamic analysis on top of static signals.
- **Reachability analysis:** does the vulnerable function actually get called? Cuts CVE noise dramatically.
- **Org features:** teams, RBAC, org-wide base policies, dependency inventory across all repos ("which repos ship lodash 4.17.20?") — one query when the next big incident hits.
- **IDE integration:** VS Code extension showing findings inline pre-push.
- **Scheduled re-scans:** yesterday's clean SBOM re-checked against today's advisories, alerting on newly disclosed CVEs in already-merged code.
- **Attestation ecosystem:** SLSA-style provenance for builds validated by Gatekeeper; badge + verifiable report links for OSS maintainers.
- **Registry firewall mode:** run the Verdaccio mirror as a standalone product feature — a package firewall teams can adopt even without the scanner.
