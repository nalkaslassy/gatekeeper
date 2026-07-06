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

from .models import Severity
from .policy import POLICY_FILENAME, STARTER_POLICY, load_policy
from .runner import run_scan, to_sarif, write_baseline

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Validate code for correctness, quality, and supply-chain security.")
policy_app = typer.Typer(help="Manage the gatekeeper.yaml policy file.")
app.add_typer(policy_app, name="policy")

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


@app.command()
def version() -> None:
    """Print the Gatekeeper CLI version."""
    console.print("gatekeeper-cli 0.1.0")


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
