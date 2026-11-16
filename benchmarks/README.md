# Gatekeeper benchmark corpus

This directory contains Gatekeeper's deterministic evaluation corpus. Its purpose
is to make security and usability claims reproducible instead of anecdotal.

Run it locally with:

```bash
python -m gatekeeper_cli.benchmarks.run
```

The runner emits JSON and exits nonzero if an expected case changes.

## Current corpus

The corpus contains **40 cases**:

- **25 benign transitions**
  - 2 compact reproductions of public repository lockfile transitions
    (`npm/cli` and `axios/axios`);
  - 23 minimal package-level models of verified public release pairs across
    npm, Axios, Prettier, ESLint, Vite, Express, webpack, Zod, Fastify, and
    Commander.
- **5 controlled security-drift mutations** derived from public npm/cli data.
- **10 historical npm supply-chain incidents** reconstructed from public
  advisories and incident reports.

The package-level benign cases are intentionally limited: they establish that an
ordinary registry version change does not itself create a Gatekeeper alert. They
are **not substitutes for full lockfile transitions** and are reported separately
by the benchmark runner.

## Historical incident corpus

| Incident | Expected Gatekeeper outcome | Primary modeled signal |
|---|---|---|
| `eslint-scope@3.7.2` | detected / BLOCK | install script appeared |
| `ua-parser-js@0.7.29` | detected / BLOCK | install-time execution appeared |
| `event-stream@3.3.6` | detected / REVIEW | required dependency edge to `flatmap-stream` |
| `colors@1.4.1` | detected / BLOCK | new infinite-loop content pattern |
| `coa@2.0.3` | detected / BLOCK | malicious preinstall appeared |
| `rc@1.2.9` | detected / BLOCK | malicious install-time execution appeared |
| `node-ipc@10.1.1` | detected / REVIEW | new network + filesystem-write capabilities |
| `browserift@16.3.3` | detected / REVIEW | new package with malicious preinstall |
| `common-array-token@1.0.0` | detected / REVIEW | new package with postinstall execution |
| `data-value@45.0.0` | **documented miss / PASS** | malicious off-registry dependency-edge source is not currently modeled |

The historical corpus deliberately includes the `data-value` miss. The benchmark
must document limitations rather than be tuned until every historical case is
green.

Evidence URLs and the exact reconstruction basis for every case live beside the
case in `gatekeeper_cli/benchmarks/cases.py`.

## Metrics

The runner reports:

- benign PASS / REVIEW / BLOCK counts;
- benign alert rate and block rate;
- controlled-case detection;
- historical incidents detected and missed;
- historical PASS / REVIEW / BLOCK counts;
- historical block rate;
- corpus scope counts separating lockfile evidence from package-level release
  sanity cases.

A legacy `case_precision` field remains for compatibility. It is only a
controlled-vs-benign corpus proxy and must **not** be described as population
precision.

## Interpretation limits

This corpus cannot establish a universal detection rate or false-positive rate.
In particular:

- most benign cases are package-level release transitions, not complete
  dependency graphs;
- historical cases are compact reconstructions from public evidence rather than
  archived compromised environments;
- content fixtures encode documented capabilities without reproducing malicious
  payloads verbatim;
- Gatekeeper is static-first and will miss attack classes that do not change a
  modeled trust field or introduce a detectable content capability.

The next evaluation milestone is to increase **full public lockfile transitions**
from 2 toward 25, then continue toward 50+, while growing the historical corpus
from 10 toward 20 and retaining all misses.
