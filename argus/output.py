"""Rich terminal output rendering for ARGUS findings."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus.models import Finding, SeverityLevel

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
        content_parts.append(f"\n[bold]Recommendation:[/bold]")
        content_parts.append(f"  {finding.recommendation}")
    if finding.mitre:
        content_parts.append(f"\n[bold]MITRE ATT&CK:[/bold] {', '.join(finding.mitre)}")

    console.print(Panel(
        "\n".join(content_parts),
        border_style=color,
    ))
