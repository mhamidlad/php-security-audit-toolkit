"""Scan engine — orchestrates all checks and produces a ScanResult."""

from __future__ import annotations

from datetime import UTC, datetime

from .composer_audit import audit_dependencies
from .config import ScanConfig
from .config_audit import audit_config_files
from .discovery import FileDiscovery
from .docker_audit import audit_dockerfiles
from .models import CheckStatus, ScanResult
from .php_rules import run_php_rules
from .runtime import audit_runtime
from .secrets import audit_secrets
from .suppressions import apply_suppressions
from .workflow_audit import audit_workflows


def run_scan(project_path: str, config: ScanConfig) -> ScanResult:
    """Run a full security scan on a PHP project.

    Args:
        project_path: Path to the PHP project to scan.
        config: Scan configuration.

    Returns:
        ScanResult with all findings.
    """
    result = ScanResult(
        project_path=project_path,
        scan_time=datetime.now(UTC).isoformat(),
    )

    # Discover files
    discovery = FileDiscovery(config)
    file_groups = discovery.discover(project_path)

    result.files_scanned = len(file_groups.get("all", []))

    # Run requested checks
    checks = config.checks if config.checks else [
        "php", "secrets", "composer", "runtime", "config", "docker", "workflow"
    ]

    for check in checks:
        if check == "php":
            check_result = _run_php_check(file_groups.get("php", []), project_path)
            result.checks.append(check_result)
        elif check == "secrets":
            check_result = audit_secrets(project_path, file_groups.get("all", []))
            result.checks.append(check_result)
        elif check == "composer":
            check_result = audit_dependencies(
                project_path,
                file_groups.get("composer", []),
                composer_path=config.tools.get("composer_path"),
            )
            result.checks.append(check_result)
        elif check == "runtime":
            check_result = audit_runtime(
                project_path,
                file_groups.get("php", []),
                file_groups.get("composer", []),
                file_groups.get("docker", []),
                php_path=config.tools.get("php_path"),
            )
            result.checks.append(check_result)
        elif check == "config":
            check_result = audit_config_files(
                project_path,
                file_groups.get("config", []),
            )
            result.checks.append(check_result)
        elif check == "docker":
            check_result = audit_dockerfiles(
                project_path,
                file_groups.get("docker", []),
            )
            result.checks.append(check_result)
        elif check == "workflow":
            check_result = audit_workflows(
                project_path,
                file_groups.get("workflow", []),
            )
            result.checks.append(check_result)

    # Collect all findings
    for check in result.checks:
        result.findings.extend(check.findings)

    # Apply suppressions
    result.findings = apply_suppressions(result.findings, config)

    return result


def _run_php_check(php_files: list[str], project_path: str):
    """Run PHP static analysis rules on PHP files."""
    from .models import CheckResult

    check_result = CheckResult(
        name="php",
        status=CheckStatus.COMPLETED,
        files_scanned=len(php_files),
    )

    all_findings: list = []
    for filepath in php_files:
        findings = run_php_rules(filepath)
        all_findings.extend(findings)

    # Adjust file paths to be relative to project root
    import os
    for f in all_findings:
        if os.path.isabs(f.file):
            try:
                f.file = os.path.relpath(f.file, project_path)
            except ValueError:
                pass

    check_result.findings = all_findings
    return check_result
