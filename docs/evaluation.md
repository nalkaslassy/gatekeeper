# Gatekeeper evaluation methodology

Gatekeeper is designed to answer a narrow review question:

> **What became less trustworthy in this dependency update?**

Evaluation therefore needs to test both sides of that question:

1. **benign noise** — ordinary upgrades should usually remain PASS;
2. **security sensitivity** — meaningful trust changes should surface as REVIEW
   or BLOCK;
3. **review usefulness** — the event should explain what changed rather than
   merely label a package as risky.

## Corpus layers

### 1. Public lockfile transitions

These are the strongest benign fixtures because they preserve a compact form of
a real repository dependency transition. The current corpus contains two:
`npm/cli` and `axios/axios`.

### 2. Public package release transitions

These verify that ordinary registry version movement is not itself treated as a
security event. The current corpus contains 23 package-level release pairs across
10 public projects.

These are useful sanity checks, but they do not exercise graph churn,
hoisting/rehoisting, optional dependency changes, or package-manager-specific
lockfile behavior.

### 3. Controlled trust mutations

Five deterministic cases isolate the rules Gatekeeper intentionally implements:

- same-version integrity mutation;
- install script added;
- registry-to-Git source change;
- new direct Git dependency;
- large dependency-graph expansion.

Controlled cases test rule correctness. They are not historical compromises.

### 4. Historical incident reconstructions

Ten public npm incidents are represented using only facts supported by public
incident evidence and only fields/capabilities Gatekeeper understands.

The corpus intentionally keeps one current miss:
`data-value@45.0.0`. Its malicious behavior is carried by an off-registry URL
on a dependency edge. Gatekeeper records required edge names but does not yet
record each edge's source specification.

That miss is evidence for a possible future signal; it is **not** a reason to
rush a feature into v0.1.

## Decision metrics

For each case the runner derives the same severity model used by review:

- **PASS** — no modeled security-relevant drift;
- **REVIEW** — low/medium signal requiring human attention;
- **BLOCK** — high/critical trust drift.

The key usability metrics are:

- benign alert rate;
- benign block rate;
- historical detection rate;
- historical block rate;
- counts of historical REVIEW outcomes versus BLOCK outcomes.

A security tool that detects incidents but reviews every ordinary upgrade is not
useful. Conversely, a tool that always passes is quiet but not useful. Gatekeeper
needs evidence on both dimensions.

## Networked end-to-end evaluation

A separate `.github/workflows/real-world-eval.yml` workflow validates the actual
CLI against full `package-lock.json` graphs from public projects. It is kept
separate from deterministic CI because it depends on GitHub/network availability.

The initial matrix pins both the baseline and candidate releases to immutable
commit SHAs for:

- `npm/cli`;
- `axios/axios`;
- `nodejs/undici`;
- `jshttp/cookie`;
- `tj/commander.js`.

For each matrix entry the workflow:

1. checks out the old release;
2. runs `gatekeeper trust snapshot` to create the trusted state;
3. checks out the newer release independently;
4. runs `gatekeeper review --baseline ... --format json`;
5. uploads the complete JSON result.

This evaluates the real CLI, parser, snapshot builder, duplicate-instance
matching, and review decision over full public lockfiles without vendoring those
large lockfiles into Gatekeeper.

### Noise calibration from the first full-lockfile run

The first five-project run produced **2 PASS / 3 REVIEW / 0 BLOCK** on ordinary
upgrades. Every REVIEW came from `required-dependency-added` events on
**transitive** packages (for example `flat-cache`, `keyv`, and ESLint tooling);
none of the parent packages generating those events were direct dependencies.

Gatekeeper therefore keeps required-edge additions at **medium / REVIEW** when
the changed parent is a direct dependency, but records the same change as
**info** when the parent is transitive. The event remains visible in JSON/text
output without turning routine transitive graph churn into human-review work.

The historical `event-stream@3.3.6` reconstruction remains a REVIEW because
`event-stream` is the direct dependency whose required edge changed. The
real-world matrix now expects all five ordinary upgrades to PASS and will fail
if that noise regression returns.

## What the current corpus can support

It can support statements such as:

- the deterministic corpus contains 25 benign, 5 controlled, and 10 historical
  cases;
- the benchmark explicitly distinguishes package-level release sanity cases from
  lockfile-transition evidence;
- known misses remain visible in CI;
- every benchmark result is reproducible from checked-in fixtures.

It **cannot** support claims such as:

- universal 90% historical attack detection;
- a population false-positive rate;
- broad npm ecosystem coverage;
- superiority over other supply-chain scanners.

## Next evidence milestone

Before making stronger adoption/performance claims:

1. grow compact **full lockfile** benign transitions from 2 to at least 25;
2. grow historical reconstructions from 10 to at least 20;
3. include pnpm and Yarn transitions where the available metadata permits a fair
   comparison;
4. preserve misses and unsupported cases;
5. publish a case study that shows both detections and misses.

The benchmark should improve because the evidence improves, not because the
expected labels are changed to make Gatekeeper look better.
