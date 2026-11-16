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

from gatekeeper_cli.content import scan_content_files

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


def _registry_source(package: str, version: str) -> str:
    filename = package.rsplit("/", 1)[-1]
    return f"https://registry.npmjs.org/{package}/-/{filename}-{version}.tgz"


def benign_release_case(
    *,
    case_id: str,
    repository: str,
    package: str,
    before: str,
    after: str,
    before_tag: str,
    after_tag: str,
) -> dict:
    """Minimal package-level model of a verified public release transition.

    These cases intentionally test ordinary registry version changes without
    pretending to reproduce the repository's complete lockfile graph.
    """
    return {
        "id": case_id,
        "kind": "benign",
        "source": {
            "repository": repository,
            "package": package,
            "from": before_tag,
            "to": after_tag,
            "fixture_scope": "package-level-release-transition",
            "evidence": [
                f"https://github.com/{repository}/releases/tag/{before_tag}",
                f"https://github.com/{repository}/releases/tag/{after_tag}",
            ],
        },
        "baseline": snapshot([
            pkg(
                package,
                before,
                direct=True,
                source=_registry_source(package, before),
            ),
        ]),
        "current": snapshot([
            pkg(
                package,
                after,
                direct=True,
                source=_registry_source(package, after),
            ),
        ]),
        "expected_rules": [],
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




COLORS_140_SOURCE = "var colors = require('./colors');\nmodule['exports'] = colors;\nrequire('./extendStringPrototype')();\n"
COLORS_141_SOURCE = "var colors = require('./colors');\nmodule['exports'] = colors;\nrequire('./extendStringPrototype')();\n\nlet am = require('../lib/custom/american');\nam();\nfor (let i = 666; i < Infinity; i++) {\n  if (i % 333) {\n  }\n  console.log('testing testing testing testing testing testing testing'.zalgo)\n}\n"

NODE_IPC_1010_SOURCE = "module.exports = { ipc: true };\n"
NODE_IPC_1011_SOURCE = """const https = require("https");
const fs = require("fs");
https.get("https://example.invalid/geolocation", () => {});
fs.writeFile("./target.txt", "❤", () => {});
module.exports = { ipc: true };
"""


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
            "content_baseline": scan_content_files({
                "lib/index.js": COLORS_140_SOURCE,
            }),
            "content_current": scan_content_files({
                "lib/index.js": COLORS_141_SOURCE,
            }),
            "expected_rules": ["content-infinite-loop"],
            "expected_detected": True,
        },
        {
            "id": "historical-coa-2.0.3",
            "kind": "historical-security-incident",
            "source": {
                "package": "coa",
                "before": "2.0.2",
                "malicious": "2.0.3",
                "incident_date": "2021-11-04",
                "evidence": [
                    "https://github.com/advisories/GHSA-73qr-pfmq-6rp8",
                    "https://cert.europa.eu/publications/security-advisories/2021-062/",
                ],
                "basis": "Public incident reporting documents a new malicious preinstall hook in the hijacked coa releases.",
            },
            "baseline": snapshot([
                pkg("coa", "2.0.2", direct=False, install_script=False),
            ]),
            "current": snapshot([
                pkg("coa", "2.0.3", direct=False, install_script=True),
            ]),
            "expected_rules": ["install-script-added"],
            "expected_detected": True,
        },
        {
            "id": "historical-rc-1.2.9",
            "kind": "historical-security-incident",
            "source": {
                "package": "rc",
                "before": "1.2.8",
                "malicious": "1.2.9",
                "incident_date": "2021-11-04",
                "evidence": [
                    "https://github.com/advisories/GHSA-g2q5-5433-rhrf",
                    "https://cert.europa.eu/publications/security-advisories/2021-062/",
                ],
                "basis": "The coordinated rc compromise used the same malicious install-time execution pattern documented for coa.",
            },
            "baseline": snapshot([
                pkg("rc", "1.2.8", direct=False, install_script=False),
            ]),
            "current": snapshot([
                pkg("rc", "1.2.9", direct=False, install_script=True),
            ]),
            "expected_rules": ["install-script-added"],
            "expected_detected": True,
        },
        {
            "id": "historical-node-ipc-10.1.1",
            "kind": "historical-security-incident",
            "source": {
                "package": "node-ipc",
                "before": "10.1.0",
                "malicious": "10.1.1",
                "incident_date": "2022-03-07",
                "evidence": [
                    "https://github.com/advisories/GHSA-97m3-w2cp-4xx6",
                    "https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/",
                ],
                "basis": "The destructive release added outbound HTTPS and filesystem-write behavior; the compact content fixture models those documented capabilities, not the original source verbatim.",
            },
            "baseline": snapshot([
                pkg("node-ipc", "10.1.0", direct=False),
            ]),
            "current": snapshot([
                pkg("node-ipc", "10.1.1", direct=False),
            ]),
            "content_baseline": scan_content_files({
                "node-ipc.cjs": NODE_IPC_1010_SOURCE,
            }),
            "content_current": scan_content_files({
                "node-ipc.cjs": NODE_IPC_1011_SOURCE,
            }),
            "expected_rules": [
                "content-filesystem-write",
                "content-network-access",
            ],
            "expected_detected": True,
        },
        {
            "id": "historical-browserift-16.3.3",
            "kind": "historical-security-incident",
            "source": {
                "package": "browserift",
                "malicious": "16.3.3",
                "incident_date": "2020-09-02",
                "evidence": [
                    "https://github.com/advisories/GHSA-43vf-2x6g-p2m5",
                ],
                "basis": "The advisory identifies a malicious preinstall script. This fixture models first introduction of that package into a dependency graph.",
            },
            "baseline": snapshot([]),
            "current": snapshot([
                pkg("browserift", "16.3.3", direct=True, install_script=True),
            ]),
            "expected_rules": ["new-package-with-install-script"],
            "expected_detected": True,
        },
        {
            "id": "historical-common-array-token-1.0.0",
            "kind": "historical-security-incident",
            "source": {
                "package": "common-array-token",
                "malicious": "1.0.0",
                "incident_date": "2026-08-29",
                "evidence": [
                    "https://github.com/advisories/GHSA-7x83-g5rh-27vr",
                ],
                "basis": "The advisory documents a postinstall hook that runs attacker-controlled dynamic code. This fixture models first introduction of the package.",
            },
            "baseline": snapshot([]),
            "current": snapshot([
                pkg("common-array-token", "1.0.0", direct=True, install_script=True),
            ]),
            "expected_rules": ["new-package-with-install-script"],
            "expected_detected": True,
        },
        {
            "id": "historical-data-value-45.0.0",
            "kind": "historical-security-incident",
            "source": {
                "package": "data-value",
                "malicious": "45.0.0",
                "incident_date": "2026-08-29",
                "evidence": [
                    "https://github.com/advisories/GHSA-rv73-wgh6-57xc",
                ],
                "basis": "The malicious shape is an off-registry URL on a dependency edge. Gatekeeper records required edge names but not each edge's source spec, so this is a deliberate documented miss.",
            },
            "baseline": snapshot([]),
            "current": snapshot([
                pkg(
                    "data-value",
                    "45.0.0",
                    direct=True,
                    dependency_count=1,
                    required_dependencies=["data-value"],
                ),
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

    cases.extend([
        benign_release_case(
            case_id="benign-npm-12.2.1-to-12.2.2",
            repository="npm/cli", package="npm",
            before="12.2.1", after="12.2.2",
            before_tag="v12.2.1", after_tag="v12.2.2",
        ),
        benign_release_case(
            case_id="benign-axios-1.20.0-to-1.21.0",
            repository="axios/axios", package="axios",
            before="1.20.0", after="1.21.0",
            before_tag="v1.20.0", after_tag="v1.21.0",
        ),
        benign_release_case(
            case_id="benign-axios-1.21.0-to-1.21.1",
            repository="axios/axios", package="axios",
            before="1.21.0", after="1.21.1",
            before_tag="v1.21.0", after_tag="v1.21.1",
        ),
        benign_release_case(
            case_id="benign-axios-0.34.0-to-0.35.0",
            repository="axios/axios", package="axios",
            before="0.34.0", after="0.35.0",
            before_tag="v0.34.0", after_tag="v0.35.0",
        ),
        benign_release_case(
            case_id="benign-prettier-3.9.8-to-3.9.9",
            repository="prettier/prettier", package="prettier",
            before="3.9.8", after="3.9.9",
            before_tag="3.9.8", after_tag="3.9.9",
        ),
        benign_release_case(
            case_id="benign-prettier-3.9.9-to-3.9.10",
            repository="prettier/prettier", package="prettier",
            before="3.9.9", after="3.9.10",
            before_tag="3.9.9", after_tag="3.9.10",
        ),
        benign_release_case(
            case_id="benign-prettier-3.10.0-to-3.10.1",
            repository="prettier/prettier", package="prettier",
            before="3.10.0", after="3.10.1",
            before_tag="3.10.0", after_tag="3.10.1",
        ),
        benign_release_case(
            case_id="benign-prettier-3.9.10-to-3.10.0",
            repository="prettier/prettier", package="prettier",
            before="3.9.10", after="3.10.0",
            before_tag="3.9.10", after_tag="3.10.0",
        ),
        benign_release_case(
            case_id="benign-eslint-10.11.0-to-10.12.0",
            repository="eslint/eslint", package="eslint",
            before="10.11.0", after="10.12.0",
            before_tag="v10.11.0", after_tag="v10.12.0",
        ),
        benign_release_case(
            case_id="benign-eslint-10.12.0-to-10.13.0",
            repository="eslint/eslint", package="eslint",
            before="10.12.0", after="10.13.0",
            before_tag="v10.12.0", after_tag="v10.13.0",
        ),
        benign_release_case(
            case_id="benign-eslint-10.13.0-to-10.14.0",
            repository="eslint/eslint", package="eslint",
            before="10.13.0", after="10.14.0",
            before_tag="v10.13.0", after_tag="v10.14.0",
        ),
        benign_release_case(
            case_id="benign-eslint-10.14.0-to-10.15.0",
            repository="eslint/eslint", package="eslint",
            before="10.14.0", after="10.15.0",
            before_tag="v10.14.0", after_tag="v10.15.0",
        ),
        benign_release_case(
            case_id="benign-vite-8.2.5-to-8.2.6",
            repository="vitejs/vite", package="vite",
            before="8.2.5", after="8.2.6",
            before_tag="v8.2.5", after_tag="v8.2.6",
        ),
        benign_release_case(
            case_id="benign-vite-8.3.7-to-8.3.8",
            repository="vitejs/vite", package="vite",
            before="8.3.7", after="8.3.8",
            before_tag="v8.3.7", after_tag="v8.3.8",
        ),
        benign_release_case(
            case_id="benign-express-5.2.0-to-5.2.1",
            repository="expressjs/express", package="express",
            before="5.2.0", after="5.2.1",
            before_tag="v5.2.0", after_tag="v5.2.1",
        ),
        benign_release_case(
            case_id="benign-express-5.2.1-to-5.3.0",
            repository="expressjs/express", package="express",
            before="5.2.1", after="5.3.0",
            before_tag="v5.2.1", after_tag="v5.3.0",
        ),
        benign_release_case(
            case_id="benign-webpack-5.111.0-to-5.111.1",
            repository="webpack/webpack", package="webpack",
            before="5.111.0", after="5.111.1",
            before_tag="v5.111.0", after_tag="v5.111.1",
        ),
        benign_release_case(
            case_id="benign-webpack-5.112.0-to-5.112.1",
            repository="webpack/webpack", package="webpack",
            before="5.112.0", after="5.112.1",
            before_tag="v5.112.0", after_tag="v5.112.1",
        ),
        benign_release_case(
            case_id="benign-webpack-5.112.1-to-5.112.2",
            repository="webpack/webpack", package="webpack",
            before="5.112.1", after="5.112.2",
            before_tag="v5.112.1", after_tag="v5.112.2",
        ),
        benign_release_case(
            case_id="benign-zod-4.6.3-to-4.6.4",
            repository="colinhacks/zod", package="zod",
            before="4.6.3", after="4.6.4",
            before_tag="v4.6.3", after_tag="v4.6.4",
        ),
        benign_release_case(
            case_id="benign-zod-4.6.4-to-4.6.5",
            repository="colinhacks/zod", package="zod",
            before="4.6.4", after="4.6.5",
            before_tag="v4.6.4", after_tag="v4.6.5",
        ),
        benign_release_case(
            case_id="benign-fastify-5.12.6-to-5.12.7",
            repository="fastify/fastify", package="fastify",
            before="5.12.6", after="5.12.7",
            before_tag="v5.12.6", after_tag="v5.12.7",
        ),
        benign_release_case(
            case_id="benign-commander-15.0.0-to-15.1.0",
            repository="tj/commander.js", package="commander",
            before="15.0.0", after="15.1.0",
            before_tag="v15.0.0", after_tag="v15.1.0",
        ),
    ])

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
