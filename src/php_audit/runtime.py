"""PHP runtime auditor — version detection and end-of-life checks."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .models import CheckResult, CheckStatus, Confidence, Finding, Severity

# PHP support and end-of-life data (based on php.net release schedule)
# https://www.php.net/supported-versions.php
# Last updated: 2026-10
PHP_SUPPORT_DATA: dict[str, dict] = {
    "8.1": {"eol_date": "2025-12-31", "status": "EOL", "security_eol": "2025-12-31"},
    "8.2": {"eol_date": "2026-12-31", "status": "Security fixes only", "security_eol": "2026-12-31"},
    "8.3": {"eol_date": "2027-12-31", "status": "Active support", "security_eol": "2027-12-31"},
    "8.4": {"eol_date": "2028-12-31", "status": "Active support", "security_eol": "2028-12-31"},
    "7.4": {"eol_date": "2022-11-28", "status": "EOL", "security_eol": "2022-11-28"},
    "7.3": {"eol_date": "2021-12-06", "status": "EOL", "security_eol": "2021-12-06"},
    "7.2": {"eol_date": "2020-11-30", "status": "EOL", "security_eol": "2020-11-30"},
    "7.1": {"eol_date": "2019-12-01", "status": "EOL", "security_eol": "2019-12-01"},
    "7.0": {"eol_date": "2018-12-31", "status": "EOL", "security_eol": "2018-12-31"},
    "5.6": {"eol_date": "2018-12-31", "status": "EOL", "security_eol": "2018-12-31"},
}


def detect_php_version(php_path: str | None = None) -> str | None:
    """Detect the installed PHP CLI version. Returns None if PHP is not found."""
    php_bin = php_path or shutil.which("php")
    if not php_bin:
        return None
    try:
        result = subprocess.run(
            [php_bin, "-v"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        if result.returncode == 0:
            # Output looks like: PHP 8.3.1 (cli) (built: ...)
            match = re.match(r"PHP\s+(\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def parse_composer_php_require(composer_json_path: str) -> str | None:
    """Extract the PHP version constraint from composer.json."""
    try:
        with open(composer_json_path, encoding="utf-8") as f:
            data = json.load(f)
        php_req = data.get("require", {}).get("php", "")
        return php_req if php_req else None
    except (OSError, json.JSONDecodeError):
        return None


def parse_dockerfile_php_version(dockerfile_path: str) -> str | None:
    """Extract the PHP version from a Dockerfile's FROM line."""
    try:
        with open(dockerfile_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("FROM"):
                    # FROM php:8.3-fpm or FROM php:8.3.1-cli
                    match = re.search(r"php:(\d+\.\d+)", line)
                    if match:
                        return match.group(1)
    except OSError:
        pass
    return None


def is_php_eol(version: str) -> tuple[bool, str]:
    """Check whether a PHP version is end-of-life.

    Returns (is_eol, status_message).
    """
    major_minor = ".".join(version.split(".")[:2])
    data = PHP_SUPPORT_DATA.get(major_minor)
    if not data:
        return False, f"PHP {major_minor} — no support data available, cannot determine EOL status"
    status = data["status"]
    eol = data["eol_date"]
    if status == "EOL":
        return True, f"PHP {major_minor} reached end-of-life on {eol}. No security updates are available."
    return False, f"PHP {major_minor}: {status}. Security support until {eol}."


def audit_runtime(project_path: str, php_files: list[str], composer_files: list[str], docker_files: list[str], php_path: str | None = None) -> CheckResult:
    """Run the PHP runtime audit.

    Checks:
    - Whether PHP is installed locally
    - PHP CLI version
    - PHP version constraints in composer.json
    - PHP base-image versions in Dockerfiles
    - End-of-life detection
    - Runtime mismatches
    """
    result = CheckResult(
        name="runtime",
        status=CheckStatus.COMPLETED,
        files_scanned=len(composer_files) + len(docker_files),
    )

    findings: list[Finding] = []

    # Detect local PHP version
    local_php_version = detect_php_version(php_path)

    if not local_php_version:
        result.status = CheckStatus.SKIPPED
        result.message = "PHP is not installed locally. Runtime version check skipped."
        result.findings = findings
        return result

    # Check local PHP version for EOL
    is_eol, status_msg = is_php_eol(local_php_version)
    if is_eol:
        findings.append(
            Finding(
                rule_id="RT001",
                title="End-of-Life PHP Version",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Runtime",
                file="(local PHP installation)",
                line=0,
                description=status_msg,
                evidence=f"Detected PHP CLI version: {local_php_version}",
                impact="Running an EOL PHP version means no security patches are available for known vulnerabilities.",
                remediation="Upgrade to a supported PHP version. See https://www.php.net/supported-versions.php",
                references=["https://www.php.net/supported-versions.php"],
                detection_method="runtime",
                manual_verification_required=True,
            )
        )
        # Note: the local CLI version may differ from the web-server runtime
        findings.append(
            Finding(
                rule_id="RT002",
                title="Runtime Version Mismatch Risk",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="Runtime",
                file="(local PHP installation)",
                line=0,
                description=(
                    f"Local PHP CLI version is {local_php_version}. "
                    "The production web server or PHP-FPM may use a different version."
                ),
                evidence=f"CLI: {local_php_version}",
                impact="Security checks may not reflect the actual production runtime.",
                remediation="Verify the PHP version used by the production web server or PHP-FPM separately.",
                references=["https://www.php.net/manual/en/install.php"],
                detection_method="runtime",
                manual_verification_required=False,
            )
        )

    # Check composer.json PHP constraint
    for cf in composer_files:
        if os.path.basename(cf) == "composer.json":
            php_req = parse_composer_php_require(cf)
            if php_req:
                # Extract version number from constraint like ">=8.1" or "^8.2"
                match = re.search(r"(\d+\.\d+)", php_req)
                if match:
                    req_version = match.group(1)
                    is_req_eol, req_status = is_php_eol(req_version)
                    if is_req_eol:
                        rel_path = os.path.relpath(cf, project_path)
                        findings.append(
                            Finding(
                                rule_id="RT001",
                                title="End-of-Life PHP Version in composer.json",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                category="Runtime",
                                file=rel_path,
                                line=0,
                                description=f"composer.json requires PHP {php_req}. {req_status}",
                                evidence=f'"php": "{php_req}"',
                                impact="The project may be designed for an EOL PHP version with no security updates.",
                                remediation="Update the PHP version constraint to a supported version.",
                                references=["https://www.php.net/supported-versions.php"],
                                detection_method="configuration",
                                manual_verification_required=True,
                            )
                        )

    # Check Dockerfile PHP version
    for df in docker_files:
        if os.path.basename(df).lower() == "dockerfile":
            docker_php = parse_dockerfile_php_version(df)
            if docker_php:
                is_docker_eol, docker_status = is_php_eol(docker_php)
                if is_docker_eol:
                    rel_path = os.path.relpath(df, project_path)
                    findings.append(
                        Finding(
                            rule_id="RT001",
                            title="End-of-Life PHP Version in Dockerfile",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="Runtime",
                            file=rel_path,
                            line=0,
                            description=f"Dockerfile uses PHP {docker_php}. {docker_status}",
                            evidence=f"php:{docker_php}",
                            impact="The Docker image uses an EOL PHP version with no security updates.",
                            remediation="Update the base image to a supported PHP version.",
                            references=["https://www.php.net/supported-versions.php"],
                            detection_method="configuration",
                            manual_verification_required=True,
                        )
                    )

    result.findings = findings
    return result
