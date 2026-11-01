# Gatekeeper — Dependency Trust Drift Gate

Gatekeeper is an open-source, change-aware software supply-chain security gate.

Its core question is intentionally narrow:

> **What became less trustworthy in this dependency update?**

Gatekeeper does not try to replace full SAST platforms, CVE databases, package
health scores, or enterprise DevSecOps suites. Those can remain complementary
inputs. Gatekeeper focuses on the transition between a dependency state a team
already reviewed and the state a pull request wants the team to trust.

## Product model

```text
Previously reviewed dependency state
              |
              v
       .gatekeeper-trust.json
              |
              v
       Candidate dependency state
              |
      +-------+--------+
      |                |
      v                v
 metadata/graph     package content
 trust drift        drift (optional)
      |                |
      +-------+--------+
              |
              v
          Trust delta
              |
      +-------+-------+
      |       |       |
     PASS   REVIEW   BLOCK
```

### PASS

No security-relevant trust drift was found.

### REVIEW

A low/medium change deserves human review but is non-blocking by default. Examples
include a previously known package adding a required dependency edge.

### BLOCK

A high/critical trust change should fail the merge gate. Examples include a
same-version integrity mutation, a new install script, a package source-kind
change, or a newly introduced high-risk content capability.

## Core signals

Gatekeeper currently models:

- package identity and resolved version;
- direct vs transitive dependency status;
- registry/Git/URL source kind and source URL;
- integrity hashes where lockfiles provide them;
- install-script state;
- required dependency edges and graph expansion;
- static package file inventory and hashes;
- newly introduced static capabilities/patterns such as subprocess execution,
  dynamic code execution, environment access, network/filesystem access,
  infinite-loop patterns, encoded blobs, and native binaries.

The normal trust review is static and offline. Registry-backed npm content
inspection is explicit with `--online-content`; it fetches over HTTPS, requires
modern SRI integrity, parses tarballs in memory, and never executes package code
or lifecycle scripts.

## Supporting controls

Gatekeeper also includes useful supporting controls—Ruff, Bandit, optional
gitleaks, lockfile/reproducibility checks, typosquat heuristics,
dependency-confusion configuration checks, optional OSV lookups, CycloneDX SBOMs,
JSON, and SARIF.

These are not the differentiator. They help make Gatekeeper useful in CI while
the trust-delta model remains the product identity.

## Baseline workflow

```bash
gatekeeper policy init .
gatekeeper trust snapshot .
git add gatekeeper.yaml .gatekeeper-trust.json
git commit
```

Future dependency changes are reviewed with:

```bash
gatekeeper review .
```

For npm content drift:

```bash
gatekeeper review . --online-content
```

## Design principles

1. **Change-aware, not inventory-only.** Prefer security deltas over generic
   package scores.
2. **Static-first.** Never execute dependency code to decide whether it is safe.
3. **Offline by default.** Network-dependent checks require explicit opt-in.
4. **Fail closed when requested checks cannot complete.**
5. **Evidence over claims.** Maintain benign transitions, controlled drift cases,
   and reconstructed historical incidents; do not generalize small-corpus metrics.
6. **Avoid feature creep.** Add new signals only when they strengthen the trust
   transition model or are justified by benchmark/user evidence.

## Near-term scope

The near-term product work is intentionally constrained:

- improve the unified review/report experience;
- expand the benign and historical benchmark corpus;
- validate with real external users;
- consider publisher/provenance drift only if it strengthens the same trust model.

Large control planes, web dashboards, worker fleets, license platforms, broad CVE
replacement, dynamic malware sandboxes, and generalized DevSecOps orchestration
are explicitly out of scope until real adoption proves a need.
