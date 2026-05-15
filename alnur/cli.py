"""ALNUR CLI — entry point for the vulnerability scanner."""
from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from alnur.core.models import ScanConfig, Severity
from alnur.core.scanner import run
from alnur.reporters import console as console_reporter
from alnur.reporters import html_reporter, json_reporter

_console = Console(stderr=True)

_SEVERITY_CHOICES = ["critical", "high", "medium", "low", "info"]
_OUTPUT_CHOICES = ["console", "json", "html", "all"]


@click.group()
@click.version_option("1.0.0", prog_name="alnur")
def main() -> None:
    """ALNUR — Open-source end-to-end vulnerability scanner."""


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True))
@click.option("--output", "-o", default="console", type=click.Choice(_OUTPUT_CHOICES), help="Output format (default: console)")
@click.option("--output-file", "-f", default=None, type=click.Path(), help="Write report to file (JSON or HTML)")
@click.option("--severity", "-s", default="low", type=click.Choice(_SEVERITY_CHOICES), help="Minimum severity to report (default: low)")
@click.option("--skip-cve", is_flag=True, default=False, help="Skip CVE/vulnerability check")
@click.option("--skip-secrets", is_flag=True, default=False, help="Skip secrets detection")
@click.option("--skip-arch", is_flag=True, default=False, help="Skip architecture analysis")
@click.option("--skip-standards", is_flag=True, default=False, help="Skip standards compliance check")
@click.option("--skip-ports", is_flag=True, default=False, help="Skip port risk analysis")
@click.option("--no-dev", is_flag=True, default=False, help="Exclude dev dependencies from CVE scan")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show detailed output")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Only show final result (suppresses progress)")
def scan(
    path: str,
    output: str,
    output_file: str | None,
    severity: str,
    skip_cve: bool,
    skip_secrets: bool,
    skip_arch: bool,
    skip_standards: bool,
    skip_ports: bool,
    no_dev: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """Scan a project directory for security vulnerabilities.

    PATH defaults to the current directory.

    Examples:

    \b
      alnur scan .
      alnur scan /path/to/project --output html --output-file report.html
      alnur scan . --severity high --skip-secrets
      alnur scan . -o all -f report.json --verbose
    """
    target = Path(path)
    config = ScanConfig(
        min_severity=Severity(severity.upper()),
        skip_cve=skip_cve,
        skip_secrets=skip_secrets,
        skip_architecture=skip_arch,
        skip_standards=skip_standards,
        skip_ports=skip_ports,
        include_dev_deps=not no_dev,
    )

    steps = _build_steps(config)

    if not quiet:
        _console.print(f"\n[bold cyan]ALNUR[/bold cyan] [dim]— scanning[/dim] [bold]{target}[/bold]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console,
        disable=quiet,
        transient=True,
    ) as progress:
        task = progress.add_task("Detecting project type...", total=len(steps))
        for step_name in steps:
            progress.update(task, description=f"{step_name}...", advance=1)

        result = run(target, config)

    # ── Console output ────────────────────────────────────────────────────
    if output in ("console", "all"):
        console_reporter.render(result, verbose=verbose)

    # ── JSON output ───────────────────────────────────────────────────────
    if output in ("json", "all"):
        json_out = Path(output_file) if output_file and output == "json" else Path("alnur-report.json")
        if output == "all":
            json_out = Path(output_file).with_suffix(".json") if output_file else Path("alnur-report.json")
        json_reporter.write(result, json_out)
        if not quiet:
            _console.print(f"[dim]JSON report written to:[/dim] [bold]{json_out}[/bold]")

    # ── HTML output ───────────────────────────────────────────────────────
    if output in ("html", "all"):
        html_out = Path(output_file) if output_file and output == "html" else Path("alnur-report.html")
        if output == "all":
            html_out = Path(output_file).with_suffix(".html") if output_file else Path("alnur-report.html")
        html_reporter.write(result, html_out)
        if not quiet:
            _console.print(f"[dim]HTML report written to:[/dim] [bold]{html_out}[/bold]")

    # ── Exit code ─────────────────────────────────────────────────────────
    min_sev = Severity(severity.upper())
    critical_issues = (
        any(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in result.vulnerabilities)
        or any(s.severity in (Severity.CRITICAL, Severity.HIGH) for s in result.secrets)
        or any(a.severity == Severity.CRITICAL for a in result.architecture_findings)
    )

    if critical_issues and min_sev <= Severity.HIGH:
        sys.exit(1)


def _build_steps(config: ScanConfig) -> list:
    steps = ["Detecting project type", "Extracting dependencies"]
    if not config.skip_cve:
        steps.append("Checking CVE database (OSV.dev)")
    if not config.skip_secrets:
        steps.append("Scanning for secrets")
    if not config.skip_architecture:
        steps.append("Analyzing architecture")
    if not config.skip_standards:
        steps.append("Checking standards compliance")
    if not config.skip_ports:
        steps.append("Analyzing port configurations")
    steps.append("Generating report")
    return steps


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True))
def detect(path: str) -> None:
    """Detect project type(s) only — quick identification without scanning."""
    from alnur.detectors import project_type, dependency
    target = Path(path)
    types = project_type.detect(target)
    packages = dependency.extract(target)

    _console.print(f"\n[bold cyan]Project types:[/bold cyan]")
    for pt in types:
        _console.print(f"  · {pt.value}")
    _console.print(f"\n[bold cyan]Packages found:[/bold cyan] {len(packages)}")
    for pkg in packages[:20]:
        dev_tag = " [dim](dev)[/dim]" if pkg.is_dev else ""
        _console.print(f"  · [cyan]{pkg.name}[/cyan] {pkg.version} [dim]({pkg.ecosystem})[/dim]{dev_tag}")
    if len(packages) > 20:
        _console.print(f"  [dim]... and {len(packages) - 20} more[/dim]")
    _console.print()
