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
