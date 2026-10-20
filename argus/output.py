"""Rich terminal output rendering for ARGUS findings."""

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus.models import REPORT_SCHEMA_VERSION, Finding, SeverityLevel

console = Console()

SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "bold red",
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "cyan",
    SeverityLevel.INFO: "dim",
}


def severity_badge(severity: SeverityLevel) -> Text:
    """Create a colored severity badge."""
    color = SEVERITY_COLORS.get(severity, "white")
    return Text(severity.value.upper(), style=color)


def render_findings_table(findings: list[Finding]) -> None:
    """Render findings as a Rich table."""
    if not findings:
        console.print("\n[green]No security findings detected.[/green]\n")
        return

    table = Table(
        title="Security Findings",
        show_header=True,
        header_style="bold white",
        border_style="dim",
        pad_edge=False,
    )
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=12)
    table.add_column("Finding", min_width=40)

    sorted_findings = sorted(
        findings,
        key=lambda f: list(SeverityLevel).index(f.severity),
    )

    for finding in sorted_findings:
        table.add_row(
            severity_badge(finding.severity),
            finding.category,
            finding.title,
        )

    console.print()
    console.print(table)
    console.print()


def render_summary_panel(findings: list[Finding], hostname: str = "") -> None:
    """Render a summary panel with finding counts."""
    critical = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
    high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
    medium = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
    low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)
    info = sum(1 for f in findings if f.severity == SeverityLevel.INFO)

    lines = [
        f"[bold]Host:[/bold] {hostname}" if hostname else "",
        f"[bold]Total findings:[/bold] {len(findings)}",
        "",
        f"  [bold red]CRITICAL[/bold red]  {critical}",
        f"  [red]HIGH[/red]      {high}",
        f"  [yellow]MEDIUM[/yellow]    {medium}",
        f"  [cyan]LOW[/cyan]       {low}",
        f"  [dim]INFO[/dim]      {info}",
    ]
    summary_text = "\n".join(line for line in lines if line or line == "")

    console.print(Panel(
        summary_text,
        title="[bold]ARGUS Scan Summary[/bold]",
        border_style="cyan",
        padding=(1, 2),
    ))


def render_drift_summary(summary: dict[str, int]) -> None:
    """Render baseline drift counts."""
    console.print("[bold cyan]ARGUS Baseline Drift[/bold cyan]")
    console.print(f"  [bold red]New:[/bold red] {summary['new']}")
    console.print(f"  [bold green]Resolved:[/bold green] {summary['resolved']}")
    console.print(f"  [dim]Unchanged:[/dim] {summary['unchanged']}")


def render_drift_section(title: str, findings: list[Finding]) -> None:
    """Render one drift finding section."""
    console.print(f"\n[bold]{title}[/bold]")
    if not findings:
        console.print("  [dim]None[/dim]")
        return
    for finding in findings:
        console.print(
            f"  [{SEVERITY_COLORS.get(finding.severity, 'white')}]"
            f"{finding.severity.value.upper()}[/] {finding.id} {finding.title}"
        )


def render_recommendations(findings: list[Finding]) -> None:
    """Render prioritized remediation recommendations."""
    actionable = [
        f for f in findings
        if f.recommendation and f.severity in (
            SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM,
        )
    ]
    if not actionable:
        return

    sorted_findings = sorted(
        actionable,
        key=lambda f: list(SeverityLevel).index(f.severity),
    )

    console.print("\n[bold]Recommended Next Steps[/bold]")
    console.print()
    for i, finding in enumerate(sorted_findings[:10], 1):
        color = SEVERITY_COLORS.get(finding.severity, "white")
        console.print(
            f"  {i}. [{color}]{finding.severity.value.upper()}[/{color}] "
            f"{finding.recommendation}"
        )
    console.print()


def render_finding_detail(finding: Finding) -> None:
    """Render detailed view of a single finding."""
    color = SEVERITY_COLORS.get(finding.severity, "white")
    content_parts = [
        f"[bold]{finding.title}[/bold]\n",
        f"[{color}]Severity: {finding.severity.value.upper()}[/{color}]",
        f"Category: {finding.category}",
        f"ID: {finding.id}\n",
        finding.description,
        "\n[bold]Evidence:[/bold]",
    ]
    for e in finding.evidence:
        content_parts.append(f"  • {e}")
    if finding.recommendation:
        content_parts.append("\n[bold]Recommendation:[/bold]")
        content_parts.append(f"  {finding.recommendation}")
    if finding.mitre:
        content_parts.append(f"\n[bold]MITRE ATT&CK:[/bold] {', '.join(finding.mitre)}")

    console.print(Panel(
        "\n".join(content_parts),
        border_style=color,
    ))


def render_collector_stats(
    users_count: int,
    ports_count: int,
    services_count: int,
    packages_count: int,
    cron_count: int,
) -> None:
    """Render collector statistics."""
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_column("Label", style="bold")
    stats_table.add_column("Value")
    stats_table.add_row("Users", str(users_count))
    stats_table.add_row("Open ports", str(ports_count))
    stats_table.add_row("Systemd services", str(services_count))
    stats_table.add_row("Installed packages", str(packages_count))
    stats_table.add_row("Cron entries", str(cron_count))
    console.print(Panel(stats_table, title="[bold]Collection Stats[/bold]", border_style="dim"))


def render_host_info(
    hostname: str,
    os_release: str,
    kernel_version: str,
    uptime: str,
) -> None:
    """Render host information panel."""
    info_lines = [
        f"[bold]Hostname:[/bold]   {hostname}",
        f"[bold]OS:[/bold]         {os_release}",
        f"[bold]Kernel:[/bold]     {kernel_version}",
        f"[bold]Uptime:[/bold]     {uptime}",
    ]
    console.print(Panel(
        "\n".join(info_lines),
        title="[bold]Host Information[/bold]",
        border_style="dim",
        padding=(0, 2),
    ))


def write_json_output(findings: list[Finding], output_path: str) -> None:
    """Write findings to a JSON file."""
    data = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "findings": [f.model_dump() for f in findings],
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
            "high": sum(1 for f in findings if f.severity == SeverityLevel.HIGH),
            "medium": sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM),
            "low": sum(1 for f in findings if f.severity == SeverityLevel.LOW),
            "info": sum(1 for f in findings if f.severity == SeverityLevel.INFO),
        },
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))
    console.print(f"\n[green]JSON output written to:[/green] {output_path}")


def write_markdown_output(
    findings: list[Finding],
    output_path: str,
    hostname: str = "",
) -> None:
    """Write findings to a Markdown report file."""
    lines: list[str] = []
    lines.append("# ARGUS Security Report\n")
    if hostname:
        lines.append(f"**Host:** {hostname}\n")

    critical = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
    high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
    medium = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
    low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

    lines.append("## Executive Summary\n")
    lines.append(
        f"ARGUS identified **{critical} critical**, **{high} high**, "
        f"**{medium} medium**, and **{low} low** risk findings.\n"
    )

    lines.append("## Findings\n")
    sorted_findings = sorted(
        findings,
        key=lambda f: list(SeverityLevel).index(f.severity),
    )
    for finding in sorted_findings:
        sev = finding.severity.value.upper()
        lines.append(f"### {sev}: {finding.title}\n")
        lines.append(f"**Category:** {finding.category}  ")
        if finding.mitre:
            lines.append(f"**MITRE ATT&CK:** {', '.join(finding.mitre)}  ")
        lines.append(f"**ID:** {finding.id}\n")
        lines.append(f"{finding.description}\n")
        if finding.evidence:
            lines.append("**Evidence:**\n")
            for e in finding.evidence:
                lines.append(f"- `{e}`")
            lines.append("")
        if finding.recommendation:
            lines.append(f"**Recommendation:** {finding.recommendation}\n")
        lines.append("---\n")

    lines.append("## Recommended Actions\n")
    for i, f in enumerate(sorted_findings[:10], 1):
        if f.recommendation:
            lines.append(f"{i}. {f.recommendation}")
    lines.append("")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))
    console.print(f"\n[green]Report written to:[/green] {output_path}")
