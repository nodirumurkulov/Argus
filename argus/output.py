"""Rich terminal output rendering for ARGUS findings."""

import json
from html import escape
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus.models import Finding, REPORT_SCHEMA_VERSION, SeverityLevel

console = Console()

SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "bold red",
    SeverityLevel.HIGH: "red",
    SeverityLevel.MEDIUM: "yellow",
    SeverityLevel.LOW: "cyan",
    SeverityLevel.INFO: "dim",
}

HTML_SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "#ef4444",
    SeverityLevel.HIGH: "#f97316",
    SeverityLevel.MEDIUM: "#eab308",
    SeverityLevel.LOW: "#38bdf8",
    SeverityLevel.INFO: "#94a3b8",
}


def severity_badge(severity: SeverityLevel) -> Text:
    """Create a colored severity badge."""
    color = SEVERITY_COLORS.get(severity, "white")
    return Text(severity.value.upper(), style=color)


def severity_counts(findings: list[Finding]) -> dict[SeverityLevel, int]:
    """Count findings by severity."""
    return {
        severity: sum(1 for finding in findings if finding.severity == severity)
        for severity in SeverityLevel
    }


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


def _html_list(items: list[str]) -> str:
    """Render a list of strings as escaped HTML list items."""
    if not items:
        return "<p class=\"muted\">None</p>"
    rendered = "".join(f"<li><code>{escape(item)}</code></li>" for item in items)
    return f"<ul>{rendered}</ul>"


def _html_finding_card(finding: Finding) -> str:
    """Render one finding as an HTML card."""
    color = HTML_SEVERITY_COLORS.get(finding.severity, "#e2e8f0")
    mitre = ", ".join(escape(item) for item in finding.mitre) or "None"
    recommendation = escape(finding.recommendation) or "No recommendation provided."
    return f"""
    <article class="finding" style="--severity-color: {color}">
      <div class="finding-header">
        <span class="severity">{escape(finding.severity.value.upper())}</span>
        <span class="category">{escape(finding.category)}</span>
      </div>
      <h3>{escape(finding.title)}</h3>
      <p>{escape(finding.description)}</p>
      <dl>
        <dt>ID</dt><dd><code>{escape(finding.id)}</code></dd>
        <dt>Fingerprint</dt><dd><code>{escape(finding.fingerprint)}</code></dd>
        <dt>MITRE ATT&CK</dt><dd>{mitre}</dd>
      </dl>
      <h4>Evidence</h4>
      {_html_list(finding.evidence)}
      <h4>Recommendation</h4>
      <p>{recommendation}</p>
    </article>
    """


def _html_summary_cards(findings: list[Finding]) -> str:
    """Render severity count cards for an HTML report."""
    counts = severity_counts(findings)
    cards = [f"<div class=\"metric total\"><span>{len(findings)}</span><strong>Total</strong></div>"]
    for severity in SeverityLevel:
        cards.append(
            "<div class=\"metric\" style=\"--severity-color: "
            f"{HTML_SEVERITY_COLORS[severity]}\"><span>{counts[severity]}</span>"
            f"<strong>{escape(severity.value.title())}</strong></div>"
        )
    return "".join(cards)


HTML_REPORT_CSS = """
:root { color-scheme: dark; }
body { margin: 0; background: #020617; color: #e2e8f0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
main { max-width: 1120px; margin: 0 auto; padding: 48px 24px; }
header { margin-bottom: 32px; }
.eyebrow { color: #38bdf8; font-size: 12px; font-weight: 700; letter-spacing: .18em; text-transform: uppercase; }
h1 { margin: 8px 0; font-size: clamp(36px, 6vw, 72px); line-height: .95; }
h2 { margin-top: 36px; }
.muted { color: #94a3b8; }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 24px 0; }
.metric { border: 1px solid #1e293b; border-top: 3px solid var(--severity-color, #38bdf8); border-radius: 16px; padding: 16px; background: #0f172a; }
.metric span { display: block; font-size: 32px; font-weight: 800; }
.finding { border: 1px solid #1e293b; border-left: 4px solid var(--severity-color); border-radius: 18px; padding: 22px; margin: 18px 0; background: #0f172a; }
.finding-header { display: flex; gap: 10px; flex-wrap: wrap; }
.severity, .category { border-radius: 999px; padding: 4px 10px; font-size: 12px; font-weight: 700; background: #1e293b; }
.severity { color: var(--severity-color); }
dl { display: grid; grid-template-columns: 140px 1fr; gap: 8px 16px; }
dt { color: #94a3b8; }
dd { margin: 0; }
code { color: #bae6fd; }
ul { padding-left: 22px; }
"""


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
