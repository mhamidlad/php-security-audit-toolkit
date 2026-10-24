"""Configuration auditor — checks PHP configuration files."""

from __future__ import annotations

import os
import re

from .models import CheckResult, CheckStatus, Confidence, Finding, Severity


def _read_file(filepath: str) -> list[str]:
    """Read a file and return lines."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


def audit_config_files(project_path: str, config_files: list[str]) -> CheckResult:
    """Run configuration auditing on config files.

    Checks:
    - Debug mode enabled (.env, php.ini, app config)
    - Error display enabled
    - Insecure session cookie settings
    - Dangerous PHP directives (allow_url_include)
    - Exposed environment files
    """
    result = CheckResult(
        name="config",
        status=CheckStatus.COMPLETED,
        files_scanned=len(config_files),
    )

    findings: list[Finding] = []

    for filepath in config_files:
        filename = os.path.basename(filepath)
        rel_path = os.path.relpath(filepath, project_path)
        lines = _read_file(filepath)

        if not lines:
            continue

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(";") or stripped.startswith("#"):
                continue

            # CFG001: Debug mode enabled
            if re.search(r"APP_DEBUG\s*=\s*(true|1|on)", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="CFG001",
                        title="Debug Mode Enabled",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="Configuration",
                        file=rel_path,
                        line=i,
                        description="Debug mode is enabled. This exposes detailed error messages and stack traces.",
                        evidence=stripped,
                        impact="Debug mode reveals internal paths, database structure, and implementation details to users.",
                        remediation="Set APP_DEBUG=false in production environments.",
                        references=["https://laravel.com/docs/configuration#debug-mode"],
                        detection_method="configuration",
                        manual_verification_required=False,
                    )
                )

            # CFG002: Error display enabled
            if re.search(r"display_errors\s*=\s*(On|1|on|true)", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="CFG002",
                        title="Error Display Enabled",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="Configuration",
                        file=rel_path,
                        line=i,
                        description="display_errors is enabled. PHP errors will be shown to users.",
                        evidence=stripped,
                        impact="Error messages can reveal internal implementation details, file paths, and database information.",
                        remediation="Set display_errors=Off in production. Log errors to files instead.",
                        references=["https://www.php.net/manual/en/errorfunc.configuration.php"],
                        detection_method="configuration",
                        manual_verification_required=False,
                    )
                )

            # CFG003: Insecure session cookie settings
            if re.search(r"session\.cookie_secure\s*=\s*(0|Off|off|false)", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="CFG003",
                        title="Insecure Session Cookie",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="Configuration",
                        file=rel_path,
                        line=i,
                        description="session.cookie_secure is disabled. Session cookies can be sent over unencrypted HTTP.",
                        evidence=stripped,
                        impact="Session cookies transmitted over HTTP can be intercepted by attackers.",
                        remediation="Set session.cookie_secure=1 to ensure cookies are only sent over HTTPS.",
                        references=["https://www.php.net/manual/en/session.security.php"],
                        detection_method="configuration",
                        manual_verification_required=False,
                    )
                )

            if re.search(r"session\.cookie_httponly\s*=\s*(0|Off|off|false)", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="CFG003",
                        title="Insecure Session Cookie",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        category="Configuration",
                        file=rel_path,
                        line=i,
                        description="session.cookie_httponly is disabled. Cookies are accessible via JavaScript.",
                        evidence=stripped,
                        impact="Session cookies could be stolen via XSS attacks.",
                        remediation="Set session.cookie_httponly=1 to prevent JavaScript access to cookies.",
                        references=["https://www.php.net/manual/en/session.security.php"],
                        detection_method="configuration",
                        manual_verification_required=False,
                    )
                )

            # CFG004: Dangerous PHP directive: allow_url_include
            if re.search(r"allow_url_include\s*=\s*(On|1|on|true)", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        rule_id="CFG004",
                        title="Dangerous PHP Directive: allow_url_include",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Configuration",
                        file=rel_path,
                        line=i,
                        description="allow_url_include is enabled. PHP can include files from remote URLs.",
                        evidence=stripped,
                        impact="Remote file inclusion attacks become possible, potentially leading to remote code execution.",
                        remediation="Set allow_url_include=Off. This directive should never be enabled in production.",
                        references=["https://www.php.net/manual/en/filesystem.configuration.php"],
                        detection_method="configuration",
                        manual_verification_required=False,
                    )
                )

            # Check for exposed .env file with credentials
            if filename == ".env":
                if re.search(r"^(DB_PASSWORD|API_KEY|SECRET|APP_KEY)\s*=\s*\S+", stripped, re.IGNORECASE):
                    if not stripped.endswith("[REDACTED]"):
                        findings.append(
                            Finding(
                                rule_id="SEC003",
                                title="Credential in .env File",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                category="Secrets",
                                file=rel_path,
                                line=i,
                                description="A credential is stored in a .env file. Ensure .env is in .gitignore.",
                                evidence="[REDACTED]",
                                impact="If .env is committed to version control, credentials will be exposed.",
                                remediation="Add .env to .gitignore. Never commit environment files to version control.",
                                references=["https://owasp.org/www-community/vulnerabilities/Password_Management_Vulnerabilities"],
                                detection_method="configuration",
                                manual_verification_required=True,
                            )
                        )

    result.findings = findings
    return result
