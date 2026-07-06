"""gatekeeper.yaml policy: load, validate, and provide defaults.

The policy file lives in the scanned repo so changes to it are reviewable
like any other code change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Severity

POLICY_FILENAME = "gatekeeper.yaml"

STARTER_POLICY = """\
# Gatekeeper policy — versioned with your code, reviewable in PRs.
version: 1

# Minimum severity of a NEW finding that fails the scan.
# One of: info | low | medium | high | critical
fail_on: high

# Fail only on findings not present in the baseline (see `gatekeeper baseline`).
new_findings_only: true

analyzers:
  ruff:      { enabled: true }    # Python lint
  bandit:    { enabled: true }    # Python SAST
  gitleaks:  { enabled: true, required: false }  # secret scan (skipped if binary absent)
  lockfile:  { enabled: true }    # dependency & supply-chain checks (no network)
  typosquat: { enabled: true }    # offline heuristic vs a bundled popular-package list

  # Opt-in: known-vulnerability + known-malicious-package lookup via OSV.dev.
  # Disabled by default because, unlike every other analyzer here, it makes
  # network calls. required: false is recommended so an OSV.dev outage or a
  # network-restricted CI runner doesn't fail the scan closed.
  osv:       { enabled: false, required: false }

supply_chain:
  # Missing lockfile for a detected manifest is a finding at this severity.
  require_lockfile: high
  # npm packages whose lockfile entry declares install scripts:
  # allow | warn | block   (block => high-severity finding)
  install_scripts: warn
  # Unpinned version specifiers in requirements.txt (no '==') are a finding.
  unpinned_python_deps: medium
  # A declared dependency within edit-distance 1-2 of a well-known package
  # name (bundled static list, no network) is a finding at this severity.
  typosquat: high
  # Known-good near-misses (deliberate forks, internal packages that
  # legitimately resemble a popular name, etc.) — suppressed by exact name,
  # reviewable in a diff instead of edited out of the analyzer itself.
  typosquat_allow: []
"""

VALID_INSTALL_SCRIPT_MODES = {"allow", "warn", "block"}

# Analyzers that must be explicitly enabled in gatekeeper.yaml even though
# no `analyzers:` entry is present at all. Currently just `osv`: it's the
# only analyzer that makes network calls, so a policy file written before
# it existed (or one that simply doesn't mention it) must not silently
# start phoning home to OSV.dev after an upgrade.
DEFAULT_DISABLED_ANALYZERS = {"osv"}


@dataclass
class Policy:
    fail_on: Severity = Severity.HIGH
    new_findings_only: bool = True
    analyzers: dict[str, dict[str, Any]] = field(default_factory=dict)
    require_lockfile: Severity | None = Severity.HIGH
    install_scripts: str = "warn"
    unpinned_python_deps: Severity | None = Severity.MEDIUM
    typosquat: Severity | None = Severity.HIGH
    typosquat_allow: frozenset[str] = field(default_factory=frozenset)
    source_path: Path | None = None

    def analyzer_enabled(self, name: str) -> bool:
        cfg = self.analyzers.get(name)
        if cfg is None:
            return name not in DEFAULT_DISABLED_ANALYZERS
        return bool(cfg.get("enabled", True))

    def analyzer_required(self, name: str) -> bool:
        """Required => a missing tool is an error finding (fail closed)."""
        return bool(self.analyzers.get(name, {}).get("required", True))


def load_policy(repo_path: Path, explicit: Path | None = None) -> Policy:
    """Load policy from an explicit path or <repo>/gatekeeper.yaml.

    Absent file => sensible defaults. Malformed file => ValueError (fail
    closed at the CLI layer, never silently ignore a broken policy).
    """
    path = explicit or (repo_path / POLICY_FILENAME)
    if not path.exists():
        if explicit is not None:
            raise ValueError(f"Policy file not found: {path}")
        return Policy()

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping at the top level")

    sc = data.get("supply_chain", {}) or {}
    mode = str(sc.get("install_scripts", "warn")).lower()
    if mode not in VALID_INSTALL_SCRIPT_MODES:
        raise ValueError(
            f"supply_chain.install_scripts must be one of "
            f"{sorted(VALID_INSTALL_SCRIPT_MODES)}, got {mode!r}"
        )

    def _sev_or_none(value: Any, default: Severity | None) -> Severity | None:
        if value is None:
            return default
        if value is False or str(value).lower() in {"off", "none", "disabled"}:
            return None
        return Severity.parse(str(value))

    return Policy(
        fail_on=Severity.parse(str(data.get("fail_on", "high"))),
        new_findings_only=bool(data.get("new_findings_only", True)),
        analyzers={k: (v or {}) for k, v in (data.get("analyzers") or {}).items()},
        require_lockfile=_sev_or_none(sc.get("require_lockfile"), Severity.HIGH),
        install_scripts=mode,
        unpinned_python_deps=_sev_or_none(
            sc.get("unpinned_python_deps"), Severity.MEDIUM
        ),
        typosquat=_sev_or_none(sc.get("typosquat"), Severity.HIGH),
        typosquat_allow=frozenset(str(x) for x in (sc.get("typosquat_allow") or [])),
        source_path=path,
    )
