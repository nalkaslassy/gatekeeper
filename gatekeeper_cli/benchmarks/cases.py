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

    return cases
