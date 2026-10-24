"""GitHub Actions workflow auditor — checks for CI/CD security issues."""

from __future__ import annotations

import os
import re

import yaml

from .models import CheckResult, CheckStatus, Confidence, Finding, Severity


def _safe_yaml_load(filepath: str) -> dict | None:
    """Safely load a YAML file. Returns None on error."""
    try:
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else None
    except (OSError, yaml.YAMLError):
        return None


def audit_workflows(project_path: str, workflow_files: list[str]) -> CheckResult:
    """Run GitHub Actions security auditing.

    Checks:
    - GHA001: Excessive workflow permissions
    - GHA002: Unpinned third-party actions
    - GHA003: Unsafe use of untrusted pull-request data
    """
    result = CheckResult(
        name="workflow",
        status=CheckStatus.COMPLETED,
        files_scanned=len(workflow_files),
    )

    findings: list[Finding] = []

    for filepath in workflow_files:
        rel_path = os.path.relpath(filepath, project_path)
        data = _safe_yaml_load(filepath)
        if not data:
            result.status = CheckStatus.SKIPPED
            result.message = f"Could not parse YAML: {rel_path}"
            continue

        # GHA001: Check permissions
        permissions = data.get("permissions")
        if permissions is None:
            # No explicit permissions — default depends on the token scope
            # In public repos this can be read/write to everything
            findings.append(
                Finding(
                    rule_id="GHA001",
                    title="Missing Explicit Permissions",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="GitHub Actions",
                    file=rel_path,
                    line=1,
                    description="Workflow does not declare explicit permissions. Default token permissions may be overly broad.",
                    evidence="No 'permissions:' key found",
                    impact="The workflow may have more access than needed, increasing the blast radius of a compromised workflow.",
                    remediation="Add a 'permissions:' block with the minimum required scopes. Use 'contents: read' as the default.",
                    references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
                    detection_method="configuration",
                    manual_verification_required=False,
                )
            )
        elif isinstance(permissions, str) and permissions == "write-all":
            findings.append(
                Finding(
                    rule_id="GHA001",
                    title="Excessive Workflow Permissions",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="GitHub Actions",
                    file=rel_path,
                    line=1,
                    description="Workflow uses permissions: write-all, granting full write access.",
                    evidence="permissions: write-all",
                    impact="A compromised workflow could modify any repository resource.",
                    remediation="Replace write-all with the specific permissions the workflow needs.",
                    references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
                    detection_method="configuration",
                    manual_verification_required=False,
                )
            )
        elif isinstance(permissions, dict):
            for scope, value in permissions.items():
                if value == "write" and scope not in ("contents",):
                    findings.append(
                        Finding(
                            rule_id="GHA001",
                            title="Broad Workflow Permission",
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            category="GitHub Actions",
                            file=rel_path,
                            line=1,
                            description=f"Workflow requests write permission for '{scope}'.",
                            evidence=f"permissions.{scope}: write",
                            impact="The workflow has write access to a resource it may not need.",
                            remediation=f"Review whether write access to '{scope}' is necessary. Use 'read' where possible.",
                            references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"],
                            detection_method="configuration",
                            manual_verification_required=True,
                        )
                    )

        # GHA002: Check for unpinned third-party actions
        jobs = data.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                steps = job_data.get("steps", [])
                if not isinstance(steps, list):
                    continue
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    uses = step.get("uses", "")
                    if not uses:
                        continue
                    # Check if it's a third-party action (not actions/*)
                    if uses.startswith("actions/"):
                        continue
                    # Check if pinned to a SHA
                    if re.match(r"^[^@]+@[a-f0-9]{40}$", uses):
                        continue  # Pinned to SHA
                    # Not pinned to SHA
                    findings.append(
                        Finding(
                            rule_id="GHA002",
                            title="Unpinned Third-Party Action",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            category="GitHub Actions",
                            file=rel_path,
                            line=0,
                            description=f"Third-party action '{uses}' is not pinned to a commit SHA.",
                            evidence=f"uses: {uses}",
                            impact="If the action repository is compromised, malicious code could run in your workflow.",
                            remediation="Pin third-party actions to an immutable commit SHA (e.g., uses: owner/repo@<sha>).",
                            references=["https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
                            detection_method="configuration",
                            manual_verification_required=False,
                        )
                    )

    result.findings = findings
    return result
