"""Normalized finding model shared by every analyzer.

Every analyzer — regardless of the underlying tool — emits Findings in this
shape. The fingerprint is a stable hash used for baseline comparison and
deduplication across scans.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"Unknown severity {value!r}; expected one of "
                f"{[s.name.lower() for s in cls]}"
            )

    def __str__(self) -> str:  # pragma: no cover
        return self.name.lower()


@dataclass
class Finding:
    category: str          # lint | sast | secret | supply_chain | vuln | error
    rule_id: str           # e.g. "ruff:E501", "bandit:B602", "gk:npm-install-script"
    severity: Severity
    title: str
    file_path: str | None = None
    line: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    analyzer: str = ""
    is_new: bool = True    # set to False when matched against a baseline

    @property
    def fingerprint(self) -> str:
        """Stable identity for baseline matching.

        Deliberately excludes the line number (code moves) and includes a
        small amount of context via detail.get('context') when available.
        """
        raw = "|".join(
            [
                self.rule_id,
                self.file_path or "",
                str(self.detail.get("context", "")),
                self.title,
            ]
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = str(self.severity)
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class AnalyzerResult:
    analyzer: str
    ok: bool                       # tool ran to completion (NOT "no findings")
    findings: list[Finding]
    skipped: bool = False          # tool unavailable / not applicable
    error: str | None = None      # populated when ok is False


def verdict(
    findings: list[Finding],
    fail_on: Severity,
    new_only: bool = True,
) -> tuple[str, list[Finding]]:
    """Compute pass/fail. Fail closed: any 'error' category finding fails.

    Returns (verdict, blocking_findings).
    """
    blocking = [
        f
        for f in findings
        if (f.category == "error")
        or (f.severity >= fail_on and (f.is_new or not new_only))
    ]
    return ("failed" if blocking else "passed"), blocking
