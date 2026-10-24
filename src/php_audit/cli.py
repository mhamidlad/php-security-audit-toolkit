"""Command-line interface for the PHP Security Audit Toolkit."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .config import ScanConfig, load_config, validate_config
from .engine import run_scan
from .models import Severity
from .php_rules import PHP_RULES
from .reporters.json_report import render_json
from .reporters.markdown_report import render_markdown
from .reporters.sarif_report import render_sarif
from .reporters.terminal import render_terminal

app = typer.Typer(
    name="php-security-audit",
    help="Find PHP security risks. Understand the findings. Fix them. Verify the results.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool):
    if value:
        console.print(f"php-security-audit-toolkit v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    """PHP Security Audit Toolkit."""


@app.command()
def scan(
    project_path: str = typer.Argument(..., help="Path to the PHP project to scan."),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, markdown, sarif",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path. If not specified, output goes to stdout.",
    ),
    checks: str | None = typer.Option(
        None,
        "--checks",
        "-c",
        help="Comma-separated list of checks to run: php,secrets,composer,runtime,config,docker,workflow",
    ),
    severity: str = typer.Option(
        "low",
        "--severity",
        "-s",
        help="Minimum severity to report: info, low, medium, high, critical",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        help="Path to a php-audit.toml configuration file.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output."),
):
    """Scan a PHP project for security vulnerabilities."""
    # Load configuration
    if config_file:
        try:
            config = load_config(config_file)
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(code=2)
    else:
        config = ScanConfig()

    # Override with CLI arguments
    if checks:
        config.checks = [c.strip() for c in checks.split(",")]
    config.severity_threshold = severity

    # Validate project path
    path = Path(project_path)
    if not path.exists():
        console.print(f"[red]Error: Project path does not exist: {project_path}[/red]")
        raise typer.Exit(code=2)
    if not path.is_dir():
        console.print(f"[red]Error: Project path is not a directory: {project_path}[/red]")
        raise typer.Exit(code=2)

    # Run scan
    result = run_scan(str(path.resolve()), config)

    # Filter findings by severity threshold
    result.findings = [
        f for f in result.findings
        if config.should_include_finding(f.severity.value)
    ]

    # Generate output
    fmt = format.lower()
    if fmt == "terminal":
        output_text = render_terminal(result, console if not quiet else Console(quiet=True))
        if output:
            Path(output).write_text(output_text, encoding="utf-8")
        elif not quiet:
            # Already printed to console
            pass
    elif fmt == "json":
        output_text = render_json(result)
        if output:
            Path(output).write_text(output_text, encoding="utf-8")
        else:
            console.print(output_text)
    elif fmt == "markdown":
        output_text = render_markdown(result)
        if output:
            Path(output).write_text(output_text, encoding="utf-8")
        else:
            console.print(output_text)
    elif fmt == "sarif":
        output_text = render_sarif(result)
        if output:
            Path(output).write_text(output_text, encoding="utf-8")
        else:
            console.print(output_text)
    else:
        console.print(f"[red]Error: Unknown format '{format}'. Use: terminal, json, markdown, sarif[/red]")
        raise typer.Exit(code=2)

    # Exit code
    # 0: No findings meeting threshold
    # 1: Findings meeting threshold
    threshold_severity = Severity.from_string(severity)
    has_failing = any(
        not f.suppressed and Severity.meets_threshold(f.severity, threshold_severity)
        for f in result.findings
    )

    if has_failing:
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)


@app.command()
def rules(
    action: str = typer.Argument(..., help="Action: list or show"),
    rule_id: str | None = typer.Option(None, "--id", help="Rule ID to show (for 'show' action)"),
):
    """List or show security rules."""
    if action == "list":
        console.print("[bold]Available Security Rules[/bold]")
        console.print()
        for rule_id, info in PHP_RULES.items():
            console.print(f"  [cyan]{rule_id}[/cyan]  [{_severity_color(info['severity'])}]{info['severity'].value}[/{_severity_color(info['severity'])}]  {info['title']}")
            console.print(f"          [dim]{info['description']}[/dim]")
    elif action == "show":
        target = rule_id or typer.prompt("Enter rule ID")
        if target not in PHP_RULES:
            console.print(f"[red]Rule not found: {target}[/red]")
            raise typer.Exit(code=2)
        info = PHP_RULES[target]
        console.print(f"[bold cyan]{target}: {info['title']}[/bold cyan]")
        console.print(f"  Severity: {info['severity'].value}")
        console.print(f"  Category: {info['category']}")
        console.print(f"  Description: {info['description']}")
    else:
        console.print(f"[red]Unknown action: {action}. Use 'list' or 'show'.[/red]")
        raise typer.Exit(code=2)


@app.command()
def config(
    action: str = typer.Argument(..., help="Action: validate"),
    path: str = typer.Argument(..., help="Path to the configuration file."),
):
    """Validate a configuration file."""
    if action == "validate":
        valid, errors = validate_config(path)
        if valid:
            console.print(f"[green]Configuration is valid: {path}[/green]")
        else:
            console.print(f"[red]Configuration is invalid:[/red]")
            for err in errors:
                console.print(f"  [red]- {err}[/red]")
            raise typer.Exit(code=2)
    else:
        console.print(f"[red]Unknown action: {action}. Use 'validate'.[/red]")
        raise typer.Exit(code=2)


def _severity_color(severity) -> str:
    """Get color for a severity level."""
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    return colors.get(severity, "white")


if __name__ == "__main__":
    app()
