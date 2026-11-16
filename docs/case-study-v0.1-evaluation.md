# Case study: evaluating Gatekeeper v0.1 before release

This case study documents how Gatekeeper was evaluated before its first public
release. The goal is not to claim broad ecosystem coverage. The goal is to test
whether the current trust-drift model is useful in two directions:

1. ordinary dependency upgrades should stay quiet enough to adopt in CI; and
2. meaningful security-relevant changes should still surface with an actionable
   reason.

All results below come from checked-in deterministic fixtures or commit-pinned
public repositories. The methodology and claim limits are documented in
[`docs/evaluation.md`](evaluation.md).

## What was evaluated

Gatekeeper currently has two complementary evaluation layers.

### Deterministic corpus

The checked-in benchmark contains 40 cases:

| Corpus | Cases | Purpose |
|---|---:|---|
| Benign transitions | 25 | Measure alert noise on ordinary dependency movement |
| Controlled security drift | 5 | Verify individual trust-drift rules deterministically |
| Historical incidents | 10 | Test the existing model against reconstructed public supply-chain incidents |

The 25 benign cases are intentionally split into two evidence strengths:

- 2 compact reproductions of real public lockfile transitions;
- 23 minimal package-level models of verified public release pairs.

The second group is useful as a version-transition sanity check, but it is not
presented as full dependency-graph evidence.

### Networked full-lockfile integration

A separate GitHub Actions workflow runs the actual Gatekeeper CLI against complete
`package-lock.json` graphs from five public projects. Both sides of every
transition are pinned to immutable commit SHAs.

The initial matrix is:

- `npm/cli` 12.2.1 -> 12.2.2
- `axios/axios` 1.20.0 -> 1.21.0
- `nodejs/undici` 8.12.2 -> 8.12.3
- `jshttp/cookie` 2.0.1 -> 2.0.2
- `tj/commander.js` 15.0.0 -> 15.1.0

For each project Gatekeeper creates the trusted snapshot from the older release,
then reviews the newer release with the normal `gatekeeper review --baseline`
path. This exercises the actual parser, snapshot builder, duplicate-instance
matching, trust rules, decision model, JSON output, and CLI exit behavior.

## What the first real-world run found

The first full-lockfile run was useful because it exposed a usability problem
rather than simply producing a perfect-looking score.

| Project | Added | Removed | Changed | Initial decision | Why |
|---|---:|---:|---:|---|---|
| npm CLI | 0 | 0 | 6 | PASS | No security-relevant trust event |
| Axios | 9 | 6 | 90 | REVIEW | 2 required-edge additions in transitive packages |
| Undici | 12 | 138 | 26 | REVIEW | 5 required-edge additions in transitive packages |
| cookie | 0 | 0 | 0 | PASS | No security-relevant trust event |
| Commander | 11 | 1 | 36 | REVIEW | 2 required-edge additions in transitive packages |

That was **2 PASS / 3 REVIEW / 0 BLOCK** on five ordinary upgrades.

The REVIEWs were not caused by integrity changes, install scripts, source changes,
or direct dependency expansion. Every one came from
`required-dependency-added` on a **transitive** parent package. Examples included
`flat-cache`, `keyv`, and ESLint-related tooling.

For a merge gate, that is too much human-review pressure for routine graph churn,
even though REVIEW is non-blocking.

## Evidence-driven calibration

Gatekeeper was changed in one narrow way:

- a **direct dependency** adding a required dependency edge remains
  **medium / REVIEW**;
- a **transitive dependency** adding a required edge becomes **info / PASS**.

The event is not discarded. It remains visible in the trust delta and JSON output.

This matters because it separates two different review situations:

- a dependency the project explicitly chose changes what it requires;
- a deep transitive package changes its internal dependency graph as part of
  routine ecosystem movement.

The first deserves a stronger human-review signal. The second can remain evidence
without forcing attention on every upgrade.

## Result after calibration

The same five immutable full-lockfile transitions were rerun with the calibrated
rule.

| Project | Decision after calibration | Remaining trust events |
|---|---|---:|
| npm CLI | PASS | 0 |
| Axios | PASS | 2 informational events |
| Undici | PASS | 5 informational events |
| cookie | PASS | 0 |
| Commander | PASS | 2 informational events |

The result is **5 PASS / 0 REVIEW / 0 BLOCK**.

Importantly, this was not achieved by deleting the noisy events. For example,
Axios still reports informational `required-dependency-added` events for
`flat-cache` and `keyv`; they simply no longer force human review.

## Did that weaken historical detection?

The deterministic historical corpus remained green after the calibration.

Current historical reconstruction results:

- **10 incidents represented**
- **9 surfaced by the current model**
- **5 BLOCK**
- **4 REVIEW**
- **1 PASS / documented miss**

The `event-stream@3.3.6` reconstruction remains a **REVIEW**. Its added
`flatmap-stream` edge belongs to `event-stream` itself, modeled as the direct
dependency, so the direct-edge rule still applies.

This is the key guardrail: reducing benign transitive noise did not require
removing the direct dependency-edge signal that surfaces the historical case.

## The known miss

The corpus intentionally retains `data-value@45.0.0` as a PASS/miss.

The public incident evidence describes a malicious off-registry URL on a
dependency edge. Gatekeeper currently records the names of required dependency
edges, but not each edge's source specification. Therefore the relevant signal is
outside the current trust model.

That limitation is left visible rather than silently changing the fixture or
adding a rushed detector solely to improve a benchmark number.

The incident evidence URLs and reconstruction basis are stored with the case in
`gatekeeper_cli/benchmarks/cases.py`.

## What this demonstrates

The evaluation supports several narrow conclusions:

- the CLI works end-to-end on full public npm lockfiles;
- trusted snapshots can be produced from one release and applied to another;
- large lockfile churn does not automatically produce BLOCK decisions;
- real benign graph churn exposed a review-noise issue that could be calibrated
  without erasing evidence;
- direct dependency-edge drift still produces REVIEW;
- high-signal rules such as integrity/source/install-script changes remain
  unchanged;
- known misses are retained and documented.

## What this does not demonstrate

These results do **not** establish:

- a universal 0% false-positive rate;
- universal 90% historical attack detection;
- broad npm ecosystem coverage;
- equivalent behavior across pnpm, Yarn, Maven, Cargo, or every Python resolver;
- superiority over Socket, Snyk, GitHub dependency review, or other tools.

Five full-lockfile transitions are useful integration evidence, not a population
sample.

## Next evaluation milestones

The next evidence work should prioritize breadth rather than new features:

1. grow full public lockfile transitions from 5 toward 25, then 50+;
2. grow historical reconstructions from 10 toward 20;
3. add pnpm/Yarn transitions where their lockfile metadata supports a fair test;
4. keep unsupported cases and misses explicit;
5. collect results from external repositories using the released GitHub Action.

The guiding rule is simple: **improve Gatekeeper when the evidence reveals a
problem, not merely to make benchmark numbers look better.**
