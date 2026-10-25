"""Composer dependency auditor — analyzes composer.json and composer.lock."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from .models import CheckResult, CheckStatus, Confidence, Finding, Severity


def parse_composer_json(filepath: str) -> dict | None:
    """Parse a composer.json file."""
    try:
        with open(filepath, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def parse_composer_lock(filepath: str) -> list[dict] | None:
    """Parse a composer.lock file and return the packages list."""
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("packages", [])
    except (OSError, json.JSONDecodeError):
        return None


def run_composer_audit(project_path: str, composer_path: str | None = None) -> list[dict]:
    """Run `composer audit` if available. Returns advisory data.

    Uses Composer's built-in audit. Does NOT run composer install or composer update.
    """
    composer_bin = composer_path or shutil.which("composer")
    if not composer_bin:
        return []

    try:
        result = subprocess.run(
            [composer_bin, "audit", "--format=json"],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
            cwd=project_path,
        )
        if result.returncode == 0 or result.stdout:
            # composer audit returns non-zero if vulns are found
            # but still outputs JSON on stdout
            data = json.loads(result.stdout)
            return data.get("advisories", [])
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, json.JSONDecodeError):
        pass
    return []


def audit_dependencies(
    project_path: str,
    composer_files: list[str],
    composer_path: str | None = None,
) -> CheckResult:
    """Run the Composer dependency audit.

    Checks:
    - composer.json and composer.lock presence
    - Missing or inconsistent lockfile
    - Known vulnerable dependencies via composer audit
    - Risky script configurations
    """
    result = CheckResult(
        name="composer",
        status=CheckStatus.COMPLETED,
        files_scanned=len(composer_files),
    )

    findings: list[Finding] = []

    composer_json_path = None
    composer_lock_path = None

    for cf in composer_files:
        base = os.path.basename(cf)
        if base == "composer.json":
            composer_json_path = cf
        elif base == "composer.lock":
            composer_lock_path = cf

    # Check for missing lockfile
    if composer_json_path and not composer_lock_path:
        rel = os.path.relpath(composer_json_path, project_path)
        findings.append(
            Finding(
                rule_id="DEP002",
                title="Missing Composer Lockfile",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="Dependencies",
                file=rel,
                line=0,
                description="composer.json exists but composer.lock is missing.",
                evidence="composer.lock not found",
                impact="Dependencies may be resolved differently across environments, leading to inconsistent or vulnerable packages.",
                remediation="Run 'composer install' to generate composer.lock and commit it to version control.",
                references=[
                    "https://getcomposer.org/doc/01-basic-usage.md#commit-your-composer-lock-file-to-version-control",
                ],
                detection_method="configuration",
                manual_verification_required=False,
            )
        )

    # Analyze composer.json for risky scripts
    if composer_json_path:
        data = parse_composer_json(composer_json_path)
        if data:
            scripts = data.get("scripts", {})
            risky_script_keys = ["pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd"]
            for key in risky_script_keys:
                if key in scripts:
                    script_val = scripts[key]
                    if isinstance(script_val, list):
                        for idx, cmd in enumerate(script_val):
                            # Flag scripts that execute external commands
                            if any(
                                dangerous in str(cmd).lower()
                                for dangerous in ["exec", "system", "eval", "shell", "rm ", "chmod"]
                            ):
                                rel = os.path.relpath(composer_json_path, project_path)
                                findings.append(
                                    Finding(
                                        rule_id="DEP003",
                                        title="Risky Composer Script",
                                        severity=Severity.MEDIUM,
                                        confidence=Confidence.LOW,
                                        category="Dependencies",
                                        file=rel,
                                        line=0,
                                        description=f"Composer script '{key}' contains a potentially risky command.",
                                        evidence="[REDACTED]",
                                        impact="Composer scripts execute automatically during install/update and could run arbitrary commands.",
                                        remediation="Review composer scripts carefully. Avoid executing external commands in post-install/post-update scripts.",
                                        references=[
                                            "https://getcomposer.org/doc/articles/scripts.md",
                                        ],
                                        detection_method="configuration",
                                        manual_verification_required=True,
                                    )
                                )

    # Run composer audit for known vulnerabilities
    advisories = run_composer_audit(project_path, composer_path)
    if advisories:
        for adv in advisories:
            pkg_name = adv.get("packageName", "unknown")
            adv_id = adv.get("advisoryId", "")
            link = adv.get("link", "")
            title = adv.get("title", "Vulnerable dependency")
            cve = adv.get("cve", "")
            affected = adv.get("affectedVersions", "")

            desc = f"{title}. Affected versions: {affected}."
            if cve:
                desc += f" CVE: {cve}."
            refs = [link] if link else []
            refs.append(f"https://packagist.org/packages/{pkg_name}")
            if adv_id:
                refs.append(f"Advisory: {adv_id}")

            findings.append(
                Finding(
                    rule_id="DEP001",
                    title=f"Vulnerable Dependency: {pkg_name}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Dependencies",
                    file="composer.lock",
                    line=0,
                    description=desc,
                    evidence=f"Package: {pkg_name}, Versions: {affected}",
                    impact="The installed version of this package has a known security vulnerability.",
                    remediation="Update the package to a patched version. Run 'composer update <package>' or check the advisory for fix details.",
                    references=refs,
                    detection_method="composer-audit",
                    manual_verification_required=False,
                )
            )
    elif composer_path is None and not shutil.which("composer"):
        result.status = CheckStatus.SKIPPED
        result.message = "Composer is not installed. Dependency audit skipped."

    result.findings = findings
    return result
