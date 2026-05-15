"""Rich terminal reporter — the primary human-readable output."""
from __future__ import annotations

from pathlib import Path
from typing import List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from alnur.core.models import (
    ArchitectureFinding,
    PortFinding,
    ScanResult,
    SecretFinding,
    Severity,
    StandardsFinding,
    Vulnerability,
)

console = Console()

_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEV_ICON = {
    Severity.CRITICAL: "[bold red]●[/]",
    Severity.HIGH: "[red]●[/]",
    Severity.MEDIUM: "[yellow]●[/]",
    Severity.LOW: "[cyan]●[/]",
    Severity.INFO: "[dim]●[/]",
}

_GRADE_COLOR = {
    "A": "bold green",
    "B": "bold green",
    "C": "bold yellow",
    "D": "bold red",
    "F": "bold red",
}

_BANNER = """
[bold cyan]
   ▄████████  ▄█        ███▄▄▄▄   ███    █▄     ████████▄
  ███    ███ ███        ███▀▀▀██▄ ███    ███    ███   ▀███
  ███    ███ ███        ███   ███ ███    ███    ███    ███
  ███    ███ ███        ███   ███ ███    ███    ███    ███
▀███████████ ███        ███   ███ ███    ███    █████████
  ███    ███ ███        ███   ███ ███    ███    ███    ███
  ███    ███ ███▌    ▄  ███   ███ ███    ███    ███    ███
  ███    █▀  █████▄▄██   ▀█   █▀  ████████▀    ████    █▀
             ▀                                           [/bold cyan]
[dim cyan]            Open-Source Vulnerability Scanner v1.0.0[/dim cyan]
"""


def render(result: ScanResult, verbose: bool = False) -> None:
    console.print(_BANNER)
    _render_summary(result)
    _render_vulnerabilities(result.vulnerabilities, verbose)
    _render_secrets(result.secrets, verbose)
    _render_architecture(result.architecture_findings, verbose)
    _render_standards(result.standards_findings)
    _render_ports(result.port_findings, verbose)
    _render_footer(result)


def _render_summary(result: ScanResult) -> None:
    console.print()
    console.print(Rule("[bold]Scan Summary[/bold]", style="cyan"))
    console.print()

    # Target info
    info_table = Table(box=None, show_header=False, padding=(0, 2))
    info_table.add_column("key", style="dim")
    info_table.add_column("value")
    info_table.add_row("Target", f"[bold]{result.target_path}[/bold]")
    info_table.add_row(
        "Project",
        ", ".join(f"[cyan]{pt.value}[/cyan]" for pt in result.project_types),
    )
    info_table.add_row("Packages scanned", str(len(result.packages)))
    info_table.add_row("Duration", f"{result.scan_duration:.2f}s")
    console.print(info_table)
    console.print()

    # Risk grade
    grade = result.risk_grade
    grade_color = _GRADE_COLOR.get(grade, "white")
    grade_text = Text(f" {grade} ", style=f"bold {grade_color} on default")

    # Counts table
    counts = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    counts.add_column("Category", style="bold")
    counts.add_column("Critical", justify="center", style="bold red")
    counts.add_column("High", justify="center", style="red")
    counts.add_column("Medium", justify="center", style="yellow")
    counts.add_column("Low", justify="center", style="cyan")

    def sev_count(items, sev_attr: str = "severity"):
        return {
            s: sum(1 for i in items if getattr(i, sev_attr) == s)
            for s in Severity
        }

    vuln_c = sev_count(result.vulnerabilities)
    secret_c = sev_count(result.secrets)
    arch_c = sev_count(result.architecture_findings)
    port_c = sev_count(result.port_findings, "risk")

    def fmt(n: int) -> str:
        return f"[bold]{n}[/bold]" if n > 0 else "[dim]0[/dim]"

    counts.add_row("CVE Vulnerabilities", fmt(vuln_c[Severity.CRITICAL]), fmt(vuln_c[Severity.HIGH]), fmt(vuln_c[Severity.MEDIUM]), fmt(vuln_c[Severity.LOW]))
    counts.add_row("Secret Leaks", fmt(secret_c[Severity.CRITICAL]), fmt(secret_c[Severity.HIGH]), fmt(secret_c[Severity.MEDIUM]), fmt(secret_c[Severity.LOW]))
    counts.add_row("Architecture Issues", fmt(arch_c[Severity.CRITICAL]), fmt(arch_c[Severity.HIGH]), fmt(arch_c[Severity.MEDIUM]), fmt(arch_c[Severity.LOW]))
    counts.add_row("Port Risks", fmt(port_c[Severity.CRITICAL]), fmt(port_c[Severity.HIGH]), fmt(port_c[Severity.MEDIUM]), fmt(port_c[Severity.LOW]))

    passed = sum(1 for f in result.standards_findings if f.passed)
    total_std = len(result.standards_findings)
    counts.add_row(
        f"Standards ({passed}/{total_std} passed)",
        "[dim]—[/dim]", "[dim]—[/dim]", "[dim]—[/dim]", "[dim]—[/dim]",
    )

    console.print(counts)
    console.print()

    risk_label = "[bold green]LOW RISK[/bold green]"
    if result.risk_score >= 200:
        risk_label = "[bold red]CRITICAL RISK[/bold red]"
    elif result.risk_score >= 100:
        risk_label = "[bold red]HIGH RISK[/bold red]"
    elif result.risk_score >= 50:
        risk_label = "[bold yellow]MEDIUM RISK[/bold yellow]"
    elif result.risk_score >= 20:
        risk_label = "[bold cyan]LOW-MEDIUM RISK[/bold cyan]"

    console.print(f"  Risk Score: [bold]{result.risk_score}/1000[/bold]  |  Grade: [{grade_color}]{grade}[/{grade_color}]  |  {risk_label}")
    console.print()


def _render_vulnerabilities(vulns: List[Vulnerability], verbose: bool) -> None:
    if not vulns:
        console.print(Panel("[green]✓ No CVE vulnerabilities found[/green]", title="[bold]CVE Vulnerabilities[/bold]", border_style="green"))
        return

    console.print(Rule(f"[bold red]CVE Vulnerabilities[/bold red] ([bold]{len(vulns)}[/bold] found)", style="red"))
    console.print()

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("Severity", width=10)
    table.add_column("CVE ID", style="bold", width=22)
    table.add_column("Package", width=20)
    table.add_column("Version", width=12)
    table.add_column("Fixed In", width=14)
    table.add_column("Summary", no_wrap=False)

    sorted_vulns = sorted(vulns, key=lambda v: v.severity.weight, reverse=True)
    for v in sorted_vulns:
        sev_text = Text(v.severity.value, style=_SEV_COLOR[v.severity])
        cvss_str = f" ({v.cvss_score:.1f})" if v.cvss_score else ""
        fixed = v.fixed_versions[0] if v.fixed_versions else "[dim]No fix[/dim]"
        table.add_row(
            sev_text,
            f"{v.id}{cvss_str}",
            v.package,
            v.version,
            fixed,
            v.summary[:80],
        )
        if verbose and v.details:
            table.add_row("", "", "", "", "", f"[dim]{v.details[:120]}[/dim]")

    console.print(table)
    console.print()


def _render_secrets(findings: List[SecretFinding], verbose: bool) -> None:
    if not findings:
        console.print(Panel("[green]✓ No hardcoded secrets detected[/green]", title="[bold]Secret Detection[/bold]", border_style="green"))
        return

    console.print(Rule(f"[bold red]Secret Leaks[/bold red] ([bold]{len(findings)}[/bold] found)", style="red"))
    console.print()

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("Severity", width=10)
    table.add_column("Type", width=28)
    table.add_column("File", width=40)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Preview")

    for f in sorted(findings, key=lambda x: x.severity.weight, reverse=True):
        sev_text = Text(f.severity.value, style=_SEV_COLOR[f.severity])
        rel_path = _rel_path(f.file_path)
        table.add_row(sev_text, f.secret_type, rel_path, str(f.line_number), f"[dim]{f.match_preview}[/dim]")
        if verbose:
            table.add_row("", "", "", "", f"[dim italic]{f.description}[/dim italic]")

    console.print(table)
    console.print()


def _render_architecture(findings: List[ArchitectureFinding], verbose: bool) -> None:
    if not findings:
        console.print(Panel("[green]✓ No architecture security issues found[/green]", title="[bold]Architecture Analysis[/bold]", border_style="green"))
        return

    console.print(Rule(f"[bold]Architecture Issues[/bold] ([bold]{len(findings)}[/bold] found)", style="yellow"))
    console.print()

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=10)
    table.add_column("Category", width=22)
    table.add_column("File", width=35)
    table.add_column("Line", justify="right", width=6)
    table.add_column("Issue")

    for f in sorted(findings, key=lambda x: x.severity.weight, reverse=True):
        sev_text = Text(f.severity.value, style=_SEV_COLOR[f.severity])
        cwe_str = f" [{f.cwe}]" if f.cwe else ""
        file_str = _rel_path(f.file_path) if f.file_path else "[dim]—[/dim]"
        line_str = str(f.line_number) if f.line_number else "[dim]—[/dim]"
        table.add_row(sev_text, f"{f.rule_id}{cwe_str}", f.category, file_str, line_str, f.description[:70])
        if verbose and f.recommendation:
            table.add_row("", "", "", "", "", f"[dim italic]→ {f.recommendation[:100]}[/dim italic]")

    console.print(table)
    console.print()


def _render_standards(findings: List[StandardsFinding]) -> None:
    if not findings:
        return

    passed = sum(1 for f in findings if f.passed)
    total = len(findings)
    pass_rate = int((passed / total) * 100) if total else 100

    color = "green" if pass_rate >= 80 else "yellow" if pass_rate >= 60 else "red"
    console.print(Rule(f"[bold]Standards Compliance[/bold] [dim]({pass_rate}% — {passed}/{total} checks passed)[/dim]", style=color))
    console.print()

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("", width=3)
    table.add_column("Check", width=40)
    table.add_column("Severity", width=10)
    table.add_column("Notes")

    for f in sorted(findings, key=lambda x: (x.passed, -x.severity.weight)):
        status = "[green]✓[/green]" if f.passed else "[red]✗[/red]"
        sev_text = Text(f.severity.value, style=_SEV_COLOR[f.severity]) if not f.passed else Text("—", style="dim")
        table.add_row(status, f.check_name, sev_text, f.description[:90])

    console.print(table)
    console.print()


def _render_ports(findings: List[PortFinding], verbose: bool) -> None:
    if not findings:
        console.print(Panel("[green]✓ No risky port configurations detected[/green]", title="[bold]Port Risk Analysis[/bold]", border_style="green"))
        return

    console.print(Rule(f"[bold]Port Risk Analysis[/bold] ([bold]{len(findings)}[/bold] issues)", style="yellow"))
    console.print()

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("Risk", width=10)
    table.add_column("Port", justify="right", width=7)
    table.add_column("Service", width=18)
    table.add_column("Protocol", width=8)
    table.add_column("Source File", width=35)
    table.add_column("Issue")

    for f in sorted(findings, key=lambda x: x.risk.weight, reverse=True):
        risk_text = Text(f.risk.value, style=_SEV_COLOR[f.risk])
        port_str = str(f.port) if f.port else "[dim]?[/dim]"
        table.add_row(risk_text, port_str, f.service, f.protocol, _rel_path(f.source_file), f.description[:70])
        if verbose and f.recommendation:
            table.add_row("", "", "", "", "", f"[dim italic]→ {f.recommendation[:100]}[/dim italic]")

    console.print(table)
    console.print()


def _render_footer(result: ScanResult) -> None:
    console.print(Rule(style="dim"))
    if result.errors:
        console.print("\n[bold yellow]Scan Warnings:[/bold yellow]")
        for err in result.errors:
            console.print(f"  [yellow]⚠ {err}[/yellow]")
        console.print()

    if result.total_issues == 0:
        console.print(Panel(
            "[bold green]✓ Excellent! No security issues detected.[/bold green]\n"
            "[dim]Continue following security best practices.[/dim]",
            border_style="green",
        ))
    else:
        top_issues: List[str] = []
        crit = result.critical_count
        if crit:
            top_issues.append(f"[bold red]{crit} CRITICAL CVE(s)[/bold red] — patch immediately")
        high_secrets = sum(1 for s in result.secrets if s.severity in (Severity.CRITICAL, Severity.HIGH))
        if high_secrets:
            top_issues.append(f"[red]{high_secrets} high-severity secret leak(s)[/red] — rotate credentials now")
        if top_issues:
            console.print("[bold]Priority Actions:[/bold]")
            for action in top_issues:
                console.print(f"  1. {action}")
            console.print()

    console.print(f"[dim]ALNUR — Scan completed in {result.scan_duration:.2f}s[/dim]\n")


def _rel_path(abs_path: str) -> str:
    try:
        return str(Path(abs_path).relative_to(Path.cwd()))
    except ValueError:
        return abs_path
