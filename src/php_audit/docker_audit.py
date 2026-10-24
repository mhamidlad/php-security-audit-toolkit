"""Docker auditor — inspects Dockerfiles for security issues."""

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


def audit_dockerfiles(project_path: str, docker_files: list[str]) -> CheckResult:
    """Run Docker security auditing on Dockerfiles.

    Checks:
    - DOCKER001: Unpinned base image tags (e.g., php:latest, php:8-fpm without patch version)
    - DOCKER002: Running as root (no USER directive)
    - DOCKER003: Secret file copied into image (COPY .env, COPY *.key)
    """
    result = CheckResult(
        name="docker",
        status=CheckStatus.COMPLETED,
        files_scanned=len(docker_files),
    )

    findings: list[Finding] = []

    for filepath in docker_files:
        rel_path = os.path.relpath(filepath, project_path)
        lines = _read_file(filepath)
        if not lines:
            continue

        has_user_directive = False
        from_line_num = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # DOCKER001: Unpinned or mutable base image tag
            if stripped.startswith("FROM"):
                from_line_num = i
                # Check for mutable tags
                if "latest" in stripped.lower():
                    findings.append(
                        Finding(
                            rule_id="DOCKER001",
                            title="Mutable Base Image Tag",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="Docker",
                            file=rel_path,
                            line=i,
                            description="Dockerfile uses 'latest' tag, which is mutable and not reproducible.",
                            evidence=stripped,
                            impact="Builds may use different images over time, making security verification unreliable.",
                            remediation="Pin the base image to a specific version tag (e.g., php:8.3.1-fpm).",
                            references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                            detection_method="configuration",
                            manual_verification_required=False,
                        )
                    )
                # Check for tags without patch version (e.g., php:8.3-fpm)
                match = re.search(r"php:(\d+)\.(\d+)(?:\.(\d+))?", stripped)
                if match and not match.group(3):
                    findings.append(
                        Finding(
                            rule_id="DOCKER001",
                            title="Unpinned Base Image Version",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            category="Docker",
                            file=rel_path,
                            line=i,
                            description="Base image tag does not include a patch version.",
                            evidence=stripped,
                            impact="Minor version updates may introduce unexpected changes.",
                            remediation="Pin to a specific patch version (e.g., php:8.3.1-fpm).",
                            references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"],
                            detection_method="configuration",
                            manual_verification_required=False,
                        )
                    )

            # DOCKER003: Secret file copied into image
            if stripped.startswith("COPY") or stripped.startswith("ADD"):
                if re.search(r"\.env|\.key|\.pem|secret|credential", stripped, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id="DOCKER003",
                            title="Secret File Copied into Image",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            category="Docker",
                            file=rel_path,
                            line=i,
                            description="A potential secret file is copied into the Docker image.",
                            evidence="[REDACTED]",
                            impact="Secrets baked into images can be extracted by anyone with access to the image layers.",
                            remediation="Mount secrets at runtime using environment variables, Docker secrets, or a secrets manager. Never COPY secret files into images.",
                            references=["https://docs.docker.com/engine/swarm/secrets/"],
                            detection_method="configuration",
                            manual_verification_required=True,
                        )
                    )

            # Track USER directive
            if stripped.startswith("USER "):
                has_user_directive = True

        # DOCKER002: Running as root (no USER directive found)
        if not has_user_directive and from_line_num > 0:
            findings.append(
                Finding(
                    rule_id="DOCKER002",
                    title="Container Runs as Root",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="Docker",
                    file=rel_path,
                    line=from_line_num,
                    description="No USER directive found. The container will run as root by default.",
                    evidence="No USER directive in Dockerfile",
                    impact="If an attacker exploits a vulnerability in the application, they gain root access inside the container.",
                    remediation="Add a USER directive with a non-root user. Example: `RUN useradd -m app && USER app`",
                    references=[
                        "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user",
                    ],
                    detection_method="configuration",
                    manual_verification_required=False,
                )
            )

    result.findings = findings
    return result
