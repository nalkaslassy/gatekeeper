# Gatekeeper benchmark corpus

This directory contains a deterministic benchmark for Gatekeeper's trust-drift
engine. It is intended to make the project's security claims measurable and
reproducible rather than anecdotal.

## Corpus

The initial corpus contains two benign public-repository dependency transitions:

- `npm/cli`: `v12.2.0` -> `v12.2.1`
- `axios/axios`: `v1.19.0` -> `v1.20.0`

Those transitions were collected from the repositories' release-tag lockfiles on
2026-10-30. The checked-in cases are deliberately compact reproductions: they
retain only the records needed to exercise Gatekeeper's rules, while metadata
records the full package/change counts observed when the public lockfiles were
tested.

Five controlled security-drift cases are derived from the `npm/cli v12.2.1`
dependency state:

1. same-version integrity mutation;
2. newly introduced install script;
3. registry-to-Git source change;
4. new direct Git dependency; and
5. large dependency-graph expansion.

These are controlled mutations. They are **not** claims that npm/cli was
compromised.

## Run

```bash
python -m benchmarks.run
```

The runner emits machine-readable JSON and exits nonzero if any expected result
changes. CI runs the benchmark on every pull request.

## What the numbers mean

The benchmark reports case-level precision and controlled-case recall. Those
metrics apply only to this checked-in corpus. They are not estimates of
Gatekeeper's performance against all real-world software supply-chain attacks.

The next benchmark phase should add historical incident reconstruction, pnpm and
Yarn transitions, and a larger benign corpus before making broader detection
claims.
