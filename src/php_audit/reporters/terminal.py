"""Terminal reporter — readable console output using Rich."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ..models import ScanResult, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def render_terminal(result: ScanResult, console: Console | None = None) -> str:
    """Render a scan result as terminal output.

    Returns the rendered string. If a console is provided, also prints.
    """
    console = console or Console(record=True)
    lines: list[str] = []

    # Header
    console.print()
    console.print("[bold cyan]PHP Security Audit Toolkit[/bold cyan]")
    console.print("=" * 50)
    console.print(f"[dim]Project:[/dim] {result.project_path}")
    console.print(f"[dim]Scan time:[/dim] {result.scan_time}")
    console.print(f"[dim]Files scanned:[/dim] {result.files_scanned}")
    console.print(f"[dim]Checks completed:[/dim] {result.checks_completed}")
    console.print(f"[dim]Checks skipped:[/dim] {result.checks_skipped}")

    # Skipped checks
    for check in result.checks:
        if check.status.value in ("SKIPPED", "INCONCLUSIVE") and check.message:
            console.print(f"[dim]  Skipped: {check.name} — {check.message}[/dim]")

    console.print()

    # Summary table
    summary = result.findings_by_severity
    console.print("[bold]Findings by severity:[/bold]")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = summary.get(sev.value, 0)
        color = SEVERITY_COLORS.get(sev, "white")
        console.print(f"  [{color}]{sev.value:10s}[/{color}] {count}")

    console.print()

    # Findings table
    if result.findings:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", style="dim", width=10)
        table.add_column("Rule", style="dim", width=10)
        table.add_column("File:Line", width=40)
        table.add_column("Description", width=50)

        for f in result.findings:
            if f.suppressed:
                continue
            sev_color = SEVERITY_COLORS.get(f.severity, "white")
            loc = f"{f.file}:{f.line}" if f.line > 0 else f.file
            table.add_row(
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                f.rule_id,
                loc,
                f.description[:80],
            )

        if table.row_count > 0:
            console.print(table)

    # Suppressed findings
    suppressed = [f for f in result.findings if f.suppressed]
    if suppressed:
        console.print()
        console.print(f"[dim]Suppressed findings: {len(suppressed)}[/dim]")
        for f in suppressed:
            console.print(
                f"[dim]  {f.rule_id} {f.file} — {f.suppression_reason}[/dim]"
            )

    # Footer
    console.print()
    total = result.total_findings
    if total > 0:
        console.print(f"[bold]Scan completed. {total} findings reported.[/bold]")
    else:
        console.print("[bold green]Scan completed. No findings reported.[/bold green]")
    console.print(
        "[dim]Note: A clean scan does not prove the application is secure.[/dim]"
    )

    # Export as string
    return console.export_text()
