"""Gatekeeper CLI.

Command surface (v0):

  gatekeeper scan [PATH]            Run all enabled analyzers, print report
      --policy FILE                 Explicit policy file (default: <PATH>/gatekeeper.yaml)
      --format text|json|sarif      Output format (default: text)
      --output FILE                 Write report to a file instead of stdout
      --fail-on SEVERITY            Override policy threshold
      --analyzers a,b,c             Run only these analyzers
      --all-findings                Fail on baseline findings too, not just new ones

  gatekeeper baseline [PATH]        Scan and record current findings as the baseline
  gatekeeper policy init [PATH]     Write a starter gatekeeper.yaml
  gatekeeper policy validate [PATH] Validate the policy file without scanning
  gatekeeper version

Exit codes: 0 = passed, 1 = failed (blocking findings), 2 = execution error.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .content import compare_content_snapshots, scan_content_tree
from .models import Severity
from .npm_registry import inspect_npm_versions
from .policy import POLICY_FILENAME, STARTER_POLICY, load_policy
from .review import review_repository
from .runner import run_scan, to_sarif, write_baseline
from .sbom import generate_sbom
from .trust import (
    TRUST_FILENAME,
    build_trust_snapshot,
    compare_repo_to_baseline,
    write_trust_snapshot,
)

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Validate code for correctness, quality, and supply-chain security.")
policy_app = typer.Typer(help="Manage the gatekeeper.yaml policy file.")
trust_app = typer.Typer(help="Record and review dependency trust drift.")
content_app = typer.Typer(help="Record and compare static package-content fingerprints.")
inspect_app = typer.Typer(help="Opt-in online package inspection.")
app.add_typer(policy_app, name="policy")
app.add_typer(trust_app, name="trust")
app.add_typer(content_app, name="content")
app.add_typer(inspect_app, name="inspect")

console = Console(stderr=False)
err_console = Console(stderr=True, style="bold red")

_SEV_STYLE = {
    "critical": "bold red", "high": "red",
    "medium": "yellow", "low": "cyan", "info": "dim",
}


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    policy_file: Path | None = typer.Option(None, "--policy"),
    output_format: str = typer.Option("text", "--format",
                                      help="text | json | sarif"),
    output: Path | None = typer.Option(None, "--output"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    analyzers: str | None = typer.Option(None, "--analyzers",
                                         help="Comma-separated subset"),
    all_findings: bool = typer.Option(False, "--all-findings",
                                      help="Fail on baseline findings too"),
) -> None:
    """Run enabled analyzers against PATH and report a verdict."""
    try:
        pol = load_policy(path, policy_file)
        if fail_on:
            pol.fail_on = Severity.parse(fail_on)
        if all_findings:
            pol.new_findings_only = False
        only = [a.strip() for a in analyzers.split(",")] if analyzers else None
        result = run_scan(path.resolve(), pol, only=only)
    except ValueError as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2)

    rendered = _render(result, output_format)
    if output:
        output.write_text(rendered if isinstance(rendered, str) else "")
        console.print(f"Report written to [bold]{output}[/bold]")
        if output_format == "text":
            console.print(rendered)
    elif output_format == "text":
        _print_text_report(result)
    else:
        print(rendered)

    raise typer.Exit(0 if result["verdict"] == "passed" else 1)


@app.command()
def review(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    online_content: bool = typer.Option(
        False,
        "--online-content",
        help="Fetch changed npm releases and include static package-content drift.",
    ),
    registry: str = typer.Option(
        "https://registry.npmjs.org",
        "--registry",
        help="npm-compatible registry used only with --online-content",
    ),
    output_format: str = typer.Option("text", "--format", help="text | json"),
) -> None:
    """Review dependency trust changes and return PASS / REVIEW / BLOCK."""
    try:
        result = review_repository(
            path.resolve(),
            online_content=online_content,
            registry=registry,
        )
    except ValueError as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2)

    if output_format == "json":
        print(json.dumps(result, indent=2))
    elif output_format == "text":
        summary = result["summary"]
        console.print(
            f"[bold]Gatekeeper review[/bold] — "
            f"{summary['packages_changed']} changed, "
            f"{summary['packages_added']} added, "
            f"{summary['packages_removed']} removed package(s)"
        )
        console.print(
            f"Mode: {result['mode']}   "
            f"Content checks: {summary['content_checks']}"
        )
        if result["events"]:
            table = Table(show_header=True, header_style="bold", title="Trust delta")
            for col in ("Severity", "Package", "Source", "Rule", "Why"):
                table.add_column(col)
            for event in result["events"]:
                package = (
                    f"{event.get('ecosystem')}:{event.get('package')}"
                    if event.get("package") else "-"
                )
                table.add_row(
                    str(event.get("severity") or ""),
                    package,
                    str(event.get("source") or ""),
                    str(event.get("rule") or ""),
                    str(event.get("message") or ""),
                )
            console.print(table)
        else:
            console.print("[green]No security-relevant dependency trust drift.[/green]")

        decision = result["decision"]
        if decision == "pass":
            console.print("[bold green]TRUST DECISION: PASS[/bold green]")
        elif decision == "review":
            console.print("[bold yellow]TRUST DECISION: REVIEW[/bold yellow]")
        else:
            console.print("[bold red]TRUST DECISION: BLOCK[/bold red]")
    else:
        err_console.print("error: unknown format (text|json)")
        raise typer.Exit(2)

    # REVIEW is non-blocking by default: it is a human-review signal, while
    # BLOCK is the policy gate. Execution/config failures use exit 2 above.
    raise typer.Exit(1 if result["decision"] == "block" else 0)


@app.command()
def baseline(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    policy_file: Path | None = typer.Option(None, "--policy"),
) -> None:
    """Record current findings as the baseline; future scans flag only new ones."""
    try:
        pol = load_policy(path, policy_file)
        result = run_scan(path.resolve(), pol)
    except ValueError as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2)
    out = write_baseline(path, result)
    console.print(
        f"Baseline written to [bold]{out}[/bold] "
        f"({len(result['findings'])} findings recorded). "
        f"Commit this file so scans compare against it."
    )


@policy_app.command("init")
def policy_init(path: Path = typer.Argument(Path("."), file_okay=False)) -> None:
    """Write a starter gatekeeper.yaml."""
    target = path / POLICY_FILENAME
    if target.exists():
        err_console.print(f"error: {target} already exists")
        raise typer.Exit(2)
    target.write_text(STARTER_POLICY)
    console.print(f"Wrote starter policy to [bold]{target}[/bold]")


@policy_app.command("validate")
def policy_validate(
    path: Path = typer.Argument(Path("."), file_okay=False),
    policy_file: Path | None = typer.Option(None, "--policy"),
) -> None:
    """Validate the policy file without running a scan."""
    try:
        pol = load_policy(path, policy_file)
    except ValueError as exc:
        err_console.print(f"invalid policy: {exc}")
        raise typer.Exit(2)
    console.print(
        f"[green]Policy OK[/green] — fail_on={pol.fail_on}, "
        f"install_scripts={pol.install_scripts}, "
        f"analyzers={{{', '.join(pol.analyzers) or 'defaults'}}}"
    )


@trust_app.command("snapshot")
def trust_snapshot(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Record the dependency posture currently trusted for this repository."""
    repo = path.resolve()
    target = output or (repo / TRUST_FILENAME)
    snapshot = build_trust_snapshot(repo)
    if output:
        target.write_text(json.dumps(snapshot, indent=2) + "\n")
    else:
        write_trust_snapshot(repo, snapshot)
    console.print(
        f"Wrote trust snapshot to [bold]{target}[/bold] "
        f"({snapshot['summary']['package_count']} package(s))."
    )


@trust_app.command("diff")
def trust_diff(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    output_format: str = typer.Option("text", "--format", help="text | json"),
) -> None:
    """Compare current dependencies with the committed trust snapshot."""
    repo = path.resolve()
    try:
        diff = compare_repo_to_baseline(repo)
    except ValueError as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2)

    if diff is None:
        err_console.print(
            f"error: no {TRUST_FILENAME} found; run 'gatekeeper trust snapshot .' first"
        )
        raise typer.Exit(2)

    if output_format == "json":
        print(json.dumps(diff, indent=2))
    elif output_format == "text":
        summary = diff["summary"]
        console.print(
            f"[bold]Gatekeeper trust diff[/bold] — "
            f"{summary['added']} added, {summary['removed']} removed, "
            f"{summary['changed']} changed"
        )
        if diff["risk_events"]:
            table = Table(show_header=True, header_style="bold", title="Trust drift")
            for col in ("Severity", "Package", "Rule", "Why"):
                table.add_column(col)
            for event in diff["risk_events"]:
                pkg = (
                    f"{event.get('ecosystem')}:{event.get('package')}"
                    if event.get("package") else "-"
                )
                table.add_row(
                    event["severity"],
                    pkg,
                    event["rule"],
                    event["message"],
                )
            console.print(table)
        else:
            console.print("[green]No security-relevant trust drift detected.[/green]")
    else:
        err_console.print("error: unknown format (text|json)")
        raise typer.Exit(2)

    blocking = any(
        event["severity"] in {"high", "critical"} for event in diff["risk_events"]
    )
    raise typer.Exit(1 if blocking else 0)


@content_app.command("snapshot")
def content_snapshot(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    output: Path = typer.Option(Path(".gatekeeper-content.json"), "--output", "-o"),
) -> None:
    """Create a static fingerprint for an extracted package directory."""
    snapshot = scan_content_tree(path.resolve())
    output.write_text(json.dumps(snapshot, indent=2) + "\n")
    console.print(
        f"Wrote content snapshot to [bold]{output}[/bold] "
        f"({snapshot['summary']['file_count']} file(s))."
    )


@content_app.command("diff")
def content_diff(
    path: Path = typer.Argument(..., exists=True, file_okay=False),
    baseline: Path = typer.Option(..., "--baseline", "-b", exists=True, dir_okay=False),
    output_format: str = typer.Option("text", "--format", help="text | json"),
) -> None:
    """Compare an extracted package directory with a prior content snapshot."""
    try:
        before = json.loads(baseline.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        err_console.print(f"error: invalid content baseline: {exc}")
        raise typer.Exit(2)
    diff = compare_content_snapshots(before, scan_content_tree(path.resolve()))

    if output_format == "json":
        print(json.dumps(diff, indent=2))
    elif output_format == "text":
        console.print(
            f"[bold]Gatekeeper content diff[/bold] — "
            f"{diff['summary']['added_files']} added, "
            f"{diff['summary']['removed_files']} removed, "
            f"{diff['summary']['changed_files']} changed"
        )
        if diff["risk_events"]:
            table = Table(show_header=True, header_style="bold", title="Content drift")
            for col in ("Severity", "Rule", "Why"):
                table.add_column(col)
            for event in diff["risk_events"]:
                table.add_row(event["severity"], event["rule"], event["message"])
            console.print(table)
        else:
            console.print("[green]No high-signal content drift detected.[/green]")
    else:
        err_console.print("error: unknown format (text|json)")
        raise typer.Exit(2)

    blocking = any(
        event["severity"] in {"high", "critical"} for event in diff["risk_events"]
    )
    raise typer.Exit(1 if blocking else 0)


@inspect_app.command("npm")
def inspect_npm(
    package: str = typer.Argument(..., help="npm package name, e.g. colors"),
    baseline_version: str = typer.Option(..., "--baseline", "-b"),
    candidate_version: str = typer.Option(..., "--candidate", "-c"),
    registry: str = typer.Option(
        "https://registry.npmjs.org", "--registry",
        help="npm-compatible registry base URL",
    ),
    output_format: str = typer.Option("text", "--format", help="text | json"),
) -> None:
    """Fetch, verify, and statically compare two npm package versions."""
    try:
        result = inspect_npm_versions(
            package,
            baseline_version,
            candidate_version,
            registry=registry,
        )
    except ValueError as exc:
        err_console.print(f"error: {exc}")
        raise typer.Exit(2)

    diff = result["diff"]
    if output_format == "json":
        print(json.dumps(result, indent=2))
    elif output_format == "text":
        console.print(
            f"[bold]Gatekeeper npm inspection[/bold] — "
            f"{package} {baseline_version} → {candidate_version}"
        )
        console.print(
            f"Verified registry tarballs; "
            f"{diff['summary']['added_files']} added, "
            f"{diff['summary']['removed_files']} removed, "
            f"{diff['summary']['changed_files']} changed file(s)."
        )
        if diff["risk_events"]:
            table = Table(show_header=True, header_style="bold", title="Content drift")
            for col in ("Severity", "Rule", "Why"):
                table.add_column(col)
            for event in diff["risk_events"]:
                table.add_row(event["severity"], event["rule"], event["message"])
            console.print(table)
        else:
            console.print("[green]No high-signal content drift detected.[/green]")
    else:
        err_console.print("error: unknown format (text|json)")
        raise typer.Exit(2)

    blocking = any(
        event["severity"] in {"high", "critical"} for event in diff["risk_events"]
    )
    raise typer.Exit(1 if blocking else 0)


@app.command()
def sbom(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    output: Path = typer.Option(Path("bom.cdx.json"), "--output", "-o"),
) -> None:
    """Generate a static CycloneDX 1.6 SBOM from supported manifests/lockfiles."""
    doc = generate_sbom(path.resolve())
    output.write_text(json.dumps(doc, indent=2) + "\n")
    console.print(
        f"Wrote CycloneDX SBOM to [bold]{output}[/bold] "
        f"({len(doc['components'])} component(s))."
    )


@app.command()
def version() -> None:
    """Print the Gatekeeper CLI version."""
    console.print(f"gatekeeper-cli {__version__}")


# --------------------------------------------------------------------------

def _render(result: dict, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2)
    if fmt == "sarif":
        return json.dumps(to_sarif(result), indent=2)
    if fmt == "text":
        return ""  # printed via rich in scan()
    err_console.print(f"error: unknown format {fmt!r} (text|json|sarif)")
    sys.exit(2)


def _print_text_report(result: dict) -> None:
    counts = result["counts"]
    console.print()
    console.print(f"[bold]Gatekeeper scan[/bold] — {result['repo']}")
    console.print(f"Policy: {result['policy']}   Fail on: {result['fail_on']}+ (new)")

    t = Table(show_header=True, header_style="bold")
    t.add_column("Analyzer")
    t.add_column("Status")
    for a in result["analyzers"]:
        status = a["status"]
        if "findings" in a:
            status += f" — {a['findings']} finding(s)"
        t.add_row(a["analyzer"], status)
    console.print(t)

    if result["findings"]:
        ft = Table(show_header=True, header_style="bold", title="Findings")
        for col in ("Sev", "New", "Rule", "Location", "Title"):
            ft.add_column(col)
        ordered = sorted(result["findings"],
                         key=lambda f: Severity.parse(f["severity"]),
                         reverse=True)
        for f in ordered[:50]:
            loc = f.get("file_path") or "-"
            if f.get("line"):
                loc += f":{f['line']}"
            ft.add_row(
                f"[{_SEV_STYLE.get(f['severity'], '')}]{f['severity']}[/]",
                "•" if f["is_new"] else "",
                f["rule_id"], loc, f["title"][:80],
            )
        console.print(ft)
        if len(result["findings"]) > 50:
            console.print(f"...and {len(result['findings']) - 50} more "
                          f"(use --format json for the full list)")

    console.print(
        f"\nTotals: {counts['total']} finding(s), {counts['new']} new — "
        + ", ".join(f"{v} {k}" for k, v in counts.items()
                    if k not in ("total", "new") and v)
    )
    if result["verdict"] == "passed":
        console.print("[bold green]VERDICT: PASSED[/bold green]")
    else:
        console.print(f"[bold red]VERDICT: FAILED[/bold red] — "
                      f"{len(result['blocking'])} blocking finding(s)")


if __name__ == "__main__":
    app()
