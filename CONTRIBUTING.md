# Contributing to Gatekeeper

Gatekeeper is intentionally focused on dependency **trust drift** rather than
becoming a general-purpose security suite.

## Before proposing a feature

A feature should normally satisfy at least one of these conditions:

1. it improves the accuracy or usability of PASS / REVIEW / BLOCK dependency
   trust decisions;
2. it closes a demonstrated gap from the benchmark or a real user report; or
3. it strengthens evidence, reproducibility, or safe package inspection.

Generic license scanning, broad CVE replacement, dashboards, and unrelated SAST
features are out of scope unless real adoption shows a concrete need.

## Development

```bash
git clone https://github.com/nalkaslassy/gatekeeper.git
cd gatekeeper
pip install -e ".[analyzers,dev]"
pytest -q
ruff check .
python -m gatekeeper_cli.benchmarks.run
gatekeeper scan .
```

Pull requests should include tests for behavioral changes. Security detection
changes should include at least one positive case and, where practical, a benign
case that guards against false positives.

## Benchmark integrity

Do not alter historical or benign cases merely to improve headline metrics.
If Gatekeeper misses a supported incident, keep the miss visible until a general
product improvement fixes it without unacceptable benign noise.

## Pull requests

Keep changes small and explain:

- the user/security problem;
- why the change belongs in the trust-drift model;
- tests or benchmark evidence;
- any expected false-positive or compatibility tradeoffs.
