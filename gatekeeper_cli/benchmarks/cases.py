"""Deterministic benchmark cases for Gatekeeper trust drift.

The benign cases are compact reproductions of dependency transitions observed
in public repository release tags on 2026-10-30. They intentionally retain only
the package records needed to exercise Gatekeeper's drift rules; metadata keeps
the full public-repo counts observed during collection.

The adversarial cases mutate a real package record from npm/cli v12.2.1 one
security-relevant property at a time. They are controlled scenarios, not claims
that npm/cli was compromised.
"""

from __future__ import annotations

from copy import deepcopy

REGISTRY = "registry"


def pkg(
    name: str,
    version: str,
    *,
    direct: bool = False,
    source: str | None = None,
    integrity: str | None = None,
    install_script: bool = False,
    dependency_count: int = 0,
    required_dependencies: list[str] | None = None,
) -> dict:
    return {
        "ecosystem": "npm",
        "name": name,
        "version": version,
        "direct": direct,
        "source": source,
        "source_kind": (
            "git" if source and source.startswith("git+")
            else "registry"
        ),
        "integrity": integrity,
        "install_script": install_script,
        "dependency_count": dependency_count,
        "required_dependencies": required_dependencies,
    }


def snapshot(packages: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "benchmark",
        "summary": {
            "package_count": len(packages),
            "direct_count": sum(1 for p in packages if p["direct"]),
            "transitive_count": sum(1 for p in packages if not p["direct"]),
        },
        "packages": packages,
    }


# Real benign transitions -------------------------------------------------

NPM_OLD = snapshot([
    pkg(
        "undici", "6.28.0",
        source="https://registry.npmjs.org/undici/-/undici-6.28.0.tgz",
        integrity="sha512-LIY910g9TI13YS95lrMFrs8Rm/u/irgHeTWoKCoteeJ04CUJ92eEfj0rVn+7VKMPBpUPiUoBKfhNyLI23EE/KA==",
    ),
    pkg(
        "brace-expansion", "1.1.18",
        source="https://registry.npmjs.org/brace-expansion/-/brace-expansion-1.1.18.tgz",
        integrity="sha512-Edep/X9fGqVNmzKBVsDYIOtD+z1tuezV70LBjdCst9Tqu76lsnvRiZ6oTic1n+/BIwX6QDGAO94PN4N2SADvtw==",
    ),
])

NPM_NEW = snapshot([
    pkg(
        "undici", "6.29.0",
        source="https://registry.npmjs.org/undici/-/undici-6.29.0.tgz",
        integrity="sha512-R+RODBqp6i2pPflGdq+xIOUkl+RNfGgHwoinecKu/JCuf2uO06cOKoDbI2P7Dn6KcswdKwrczbU6IYJ6K8X+wg==",
    ),
    pkg(
        "brace-expansion", "1.1.21",
        source="https://registry.npmjs.org/brace-expansion/-/brace-expansion-1.1.21.tgz",
        integrity="sha512-9zeA+KLZNNzglF2TPKRQEDyx6Yby7daAkuy8MiPzpXPsYDWi/DRM8jmwUDxokQjYqBpv5DgPiwD4h4ZZSy1Ujw==",
    ),
])

AXIOS_OLD = snapshot([
    pkg(
        "@eslint/config-helpers", "0.6.0",
        source="https://registry.npmjs.org/@eslint/config-helpers/-/config-helpers-0.6.0.tgz",
        integrity="sha512-ii6Bw9jJ2zi2cWA2Z+9/QZ/+3DX6kwaV5Q986D/CdP3Lap3w/pgQZ373FV7byY/i7L4IRH/G43I5dz1ClsCbpA==",
    ),
])

AXIOS_NEW = snapshot([
    pkg(
        "@eslint/config-helpers", "0.7.0",
        source="https://registry.npmjs.org/@eslint/config-helpers/-/config-helpers-0.7.0.tgz",
        integrity="sha512-DObd/KKUsU+FaFv4PLxSRenpXfQWmPXXP3pPZ6/K1PCrMu2vQpMDMuQe/BqYeoLcz8ro0bVDF1RxOJgfVEdhUw==",
    ),
    pkg(
        "@napi-rs/lzma-linux-x64-gnu", "1.5.1",
        source="https://registry.npmjs.org/@napi-rs/lzma-linux-x64-gnu/-/lzma-linux-x64-gnu-1.5.1.tgz",
        integrity="sha512-oTXEIha4SsuXdTA4Iyskj0kpdx2yVXdhd75c2v3xGrHFfVMsbhTPZU/nMPL4sWKo4pBHm3aucLaqGlF696dTyQ==",
    ),
])


def _npm_control_base() -> tuple[dict, dict]:
    before = snapshot([
        pkg(
            "undici", "6.29.0",
            direct=False,
            source="https://registry.npmjs.org/undici/-/undici-6.29.0.tgz",
            integrity="sha512-R+RODBqp6i2pPflGdq+xIOUkl+RNfGgHwoinecKu/JCuf2uO06cOKoDbI2P7Dn6KcswdKwrczbU6IYJ6K8X+wg==",
        ),
    ])
    return before, deepcopy(before)




def _historical_cases() -> list[dict]:
    """Reconstructed historical incidents from public postmortems/advisories.

    These cases encode only the trust fields Gatekeeper currently understands.
    They intentionally include expected misses so the benchmark documents blind
    spots instead of turning historical incidents into controlled toy cases.
    """
    return [
        {
            "id": "historical-eslint-scope-3.7.2",
            "kind": "historical-security-incident",
            "source": {
                "package": "eslint-scope",
                "before": "3.7.1",
                "malicious": "3.7.2",
                "incident_date": "2018-07-12",
                "evidence": [
                    "https://archive.eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes",
                    "https://github.com/advisories/GHSA-hxxf-q3w9-4xgw",
                ],
                "basis": "ESLint reports that 3.7.2 contained a malicious postinstall script.",
            },
            "baseline": snapshot([
                pkg("eslint-scope", "3.7.1", direct=False, install_script=False),
            ]),
            "current": snapshot([
                pkg("eslint-scope", "3.7.2", direct=False, install_script=True),
            ]),
            "expected_rules": ["install-script-added"],
            "expected_detected": True,
        },
        {
            "id": "historical-ua-parser-js-0.7.29",
            "kind": "historical-security-incident",
            "source": {
                "package": "ua-parser-js",
                "before": "0.7.28",
                "malicious": "0.7.29",
                "incident_date": "2021-10-22",
                "evidence": [
                    "https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
                    "https://github.com/readme/guides/dependency-risk",
                ],
                "basis": "Public incident documentation describes malicious pre-install execution in compromised versions.",
            },
            "baseline": snapshot([
                pkg("ua-parser-js", "0.7.28", direct=False, install_script=False),
            ]),
            "current": snapshot([
                pkg("ua-parser-js", "0.7.29", direct=False, install_script=True),
            ]),
            "expected_rules": ["install-script-added"],
            "expected_detected": True,
        },
        {
            "id": "historical-event-stream-3.3.6",
            "kind": "historical-security-incident",
            "source": {
                "package": "event-stream",
                "before": "3.3.4",
                "malicious": "3.3.6",
                "incident_date": "2018-09-09",
                "evidence": [
                    "https://github.com/advisories/GHSA-mh6f-8j2x-4483",
                    "https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/",
                ],
                "basis": "3.3.6 added malicious flatmap-stream as a dependency; one added transitive dependency is below Gatekeeper's graph-expansion threshold.",
            },
            "baseline": snapshot([
                pkg(
                    "event-stream", "3.3.4", direct=True, dependency_count=10,
                    required_dependencies=[
                        "duplexer", "from", "map-stream", "pause-stream", "split",
                        "stream-combiner", "through",
                    ],
                ),
            ]),
            "current": snapshot([
                pkg(
                    "event-stream", "3.3.6", direct=True, dependency_count=11,
                    required_dependencies=[
                        "duplexer", "flatmap-stream", "from", "map-stream",
                        "pause-stream", "split", "stream-combiner", "through",
                    ],
                ),
                pkg("flatmap-stream", "0.1.1", direct=False),
            ]),
            "expected_rules": ["required-dependency-added"],
            "expected_detected": True,
        },
        {
            "id": "historical-colors-1.4.1",
            "kind": "historical-security-incident",
            "source": {
                "package": "colors",
                "before": "1.4.0",
                "malicious": "1.4.1",
                "incident_date": "2022-01-08",
                "evidence": [
                    "https://snyk.io/blog/open-source-npm-packages-colors-faker/",
                    "https://github.com/readme/guides/dependency-risk",
                ],
                "basis": "The malicious behavior was introduced in package source code without a trust-field change Gatekeeper currently models.",
            },
            "baseline": snapshot([
                pkg("colors", "1.4.0", direct=False),
            ]),
            "current": snapshot([
                pkg("colors", "1.4.1", direct=False),
            ]),
            "expected_rules": [],
            "expected_detected": False,
        },
    ]


def benchmark_cases() -> list[dict]:
    cases: list[dict] = [
        {
            "id": "benign-npm-cli-12.2.0-to-12.2.1",
            "kind": "benign",
            "source": {
                "repository": "npm/cli",
                "from": "v12.2.0",
                "to": "v12.2.1",
                "observed_public_summary": {
                    "packages_before": 1169,
                    "packages_after": 1169,
                    "changed": 5,
                    "risk_events": 0,
                },
            },
            "baseline": NPM_OLD,
            "current": NPM_NEW,
            "expected_rules": [],
        },
        {
            "id": "benign-axios-1.19.0-to-1.20.0",
            "kind": "benign",
            "source": {
                "repository": "axios/axios",
                "from": "v1.19.0",
                "to": "v1.20.0",
                "observed_public_summary": {
                    "packages_before": 703,
                    "packages_after": 683,
                    "changed": 42,
                    "added": 1,
                    "removed": 13,
                    "risk_events": 0,
                },
            },
            "baseline": AXIOS_OLD,
            "current": AXIOS_NEW,
            "expected_rules": [],
        },
    ]

    before, after = _npm_control_base()
    after["packages"][0]["integrity"] = "sha512-CONTROLLED-MUTATION"
    cases.append({
        "id": "control-same-version-integrity-change",
        "kind": "controlled-security-drift",
        "source": {"repository": "npm/cli", "base": "v12.2.1"},
        "baseline": before,
        "current": after,
        "expected_rules": ["integrity-changed-same-version"],
    })

    before, after = _npm_control_base()
    after["packages"][0]["install_script"] = True
    cases.append({
        "id": "control-install-script-added",
        "kind": "controlled-security-drift",
        "source": {"repository": "npm/cli", "base": "v12.2.1"},
        "baseline": before,
        "current": after,
        "expected_rules": ["install-script-added"],
    })

    before, after = _npm_control_base()
    after["packages"][0]["source"] = "git+https://github.com/example/undici.git"
    after["packages"][0]["source_kind"] = "git"
    cases.append({
        "id": "control-source-kind-change",
        "kind": "controlled-security-drift",
        "source": {"repository": "npm/cli", "base": "v12.2.1"},
        "baseline": before,
        "current": after,
        "expected_rules": ["source-kind-changed"],
    })

    before, after = _npm_control_base()
    direct_git = pkg(
        "gatekeeper-control-dep", "1.0.0",
        direct=True,
        source="git+https://github.com/example/control.git",
    )
    after["packages"].append(direct_git)
    after["summary"] = {
        "package_count": 2,
        "direct_count": 1,
        "transitive_count": 1,
    }
    cases.append({
        "id": "control-new-direct-git-dependency",
        "kind": "controlled-security-drift",
        "source": {"repository": "npm/cli", "base": "v12.2.1"},
        "baseline": before,
        "current": after,
        "expected_rules": ["new-direct-nonregistry-source"],
    })

    before, after = _npm_control_base()
    for i in range(55):
        after["packages"].append(pkg(
            f"gk-control-{i}", "1.0.0",
            source=f"https://registry.npmjs.org/gk-control-{i}/-/gk-control-{i}-1.0.0.tgz",
        ))
    after["summary"] = {
        "package_count": 56,
        "direct_count": 0,
        "transitive_count": 56,
    }
    cases.append({
        "id": "control-large-graph-expansion",
        "kind": "controlled-security-drift",
        "source": {"repository": "npm/cli", "base": "v12.2.1"},
        "baseline": before,
        "current": after,
        "expected_rules": ["dependency-graph-expansion"],
    })

    cases.extend(_historical_cases())
    return cases
