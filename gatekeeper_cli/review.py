"""Unified dependency trust review.

Gatekeeper review combines dependency trust drift with optional registry-backed
package-content drift into one PASS / REVIEW / BLOCK decision.

The default path is fully offline. Online npm content inspection is explicit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .npm_registry import inspect_npm_versions
from .trust import (
    TRUST_FILENAME,
    build_trust_snapshot,
    compare_trust_snapshots,
    load_trust_snapshot,
)

_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _decision(events: list[dict[str, Any]]) -> str:
    highest = max(
        (_SEVERITY_ORDER.get(str(event.get("severity")), 0) for event in events),
        default=0,
    )
    if highest >= _SEVERITY_ORDER["high"]:
        return "block"
    if highest >= _SEVERITY_ORDER["low"]:
        return "review"
    return "pass"


def review_repository(
    repo: Path,
    *,
    online_content: bool = False,
    registry: str = "https://registry.npmjs.org",
    npm_inspector: Callable[..., dict[str, Any]] = inspect_npm_versions,
) -> dict[str, Any]:
    repo = repo.resolve()
    trust_path = repo / TRUST_FILENAME
    if not trust_path.exists():
        raise ValueError(
            f"no {TRUST_FILENAME} found; run 'gatekeeper trust snapshot .' first"
        )

    baseline = load_trust_snapshot(trust_path)
    current = build_trust_snapshot(repo)
    trust_diff = compare_trust_snapshots(baseline, current)

    events: list[dict[str, Any]] = [
        {**event, "source": "trust"}
        for event in trust_diff["risk_events"]
    ]
    package_reviews: list[dict[str, Any]] = []

    for change in trust_diff["changed"]:
        before = change.get("before_version")
        after = change.get("after_version")
        ecosystem = change.get("ecosystem")
        name = change.get("name")

        item: dict[str, Any] = {
            "ecosystem": ecosystem,
            "package": name,
            "before_version": before,
            "after_version": after,
            "content_checked": False,
            "content_events": [],
        }

        if (
            online_content
            and ecosystem == "npm"
            and before
            and after
            and before != after
        ):
            try:
                inspection = npm_inspector(
                    str(name),
                    str(before),
                    str(after),
                    registry=registry,
                )
            except ValueError as exc:
                raise ValueError(
                    f"online content inspection failed for "
                    f"{name} {before} -> {after}: {exc}"
                ) from exc

            content_events = [
                {
                    **event,
                    "source": "content",
                    "ecosystem": "npm",
                    "package": name,
                    "version": after,
                }
                for event in inspection["diff"]["risk_events"]
            ]
            item["content_checked"] = True
            item["content_events"] = content_events
            events.extend(content_events)

        package_reviews.append(item)

    events.sort(
        key=lambda event: (
            -_SEVERITY_ORDER.get(str(event.get("severity")), 0),
            str(event.get("ecosystem") or ""),
            str(event.get("package") or ""),
            str(event.get("rule") or ""),
        )
    )

    decision = _decision(events)
    return {
        "decision": decision,
        "mode": "online-content" if online_content else "offline",
        "repo": str(repo),
        "summary": {
            "packages_added": trust_diff["summary"]["added"],
            "packages_removed": trust_diff["summary"]["removed"],
            "packages_changed": trust_diff["summary"]["changed"],
            "risk_events": len(events),
            "content_checks": sum(
                1 for item in package_reviews if item["content_checked"]
            ),
        },
        "packages": package_reviews,
        "events": events,
        "trust_diff": trust_diff,
    }
