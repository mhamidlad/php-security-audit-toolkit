"""Secret detection — scans for credentials in project files."""

from __future__ import annotations

import os
import re

from .models import CheckResult, CheckStatus, Confidence, Finding, Severity


# Secret detection patterns
SECRET_PATTERNS: list[dict] = [
    {
        "rule_id": "SEC001",
        "name": "API Key",
        "severity": Severity.HIGH,
        "patterns": [
            r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
            r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*([A-Za-z0-9_\-]{20,})",
        ],
        "description": "A potential API key is hardcoded in the source code.",
        "impact": "An attacker with access to the source could use the API key to access external services.",
        "remediation": "Move the API key to an environment variable or a secret manager. Never commit real credentials.",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Password_Management_Vulnerabilities",
        ],
    },
    {
        "rule_id": "SEC002",
        "name": "Private Key",
        "severity": Severity.CRITICAL,
        "patterns": [
            r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----",
            r"(?i)(?:private[_-]?key|priv[_-]?key)\s*[=:]\s*['\"]([A-Za-z0-9+/=]{40,})['\"]",
        ],
        "description": "A private key is present in the source code.",
        "impact": "A leaked private key could allow an attacker to impersonate a service or decrypt sensitive data.",
        "remediation": "Remove the private key from source code immediately. Store it in a secure key management system.",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Password_Management_Vulnerabilities",
        ],
    },
    {
        "rule_id": "SEC003",
        "name": "Database Credential",
        "severity": Severity.HIGH,
        "patterns": [
            r"(?i)(?:db[_-]?(?:password|passwd|pass)|database[_-]?password)\s*[=:]\s*['\"]([^'\"]{3,})['\"]",
            r"(?i)(?:mysql|postgres|mongodb|redis)://[^:]+:([^@]{3,})@",
        ],
        "description": "A database password is hardcoded in the source code.",
        "impact": "An attacker could use the credential to access the database directly.",
        "remediation": "Move database credentials to environment variables or a secrets manager.",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Password_Management_Vulnerabilities",
        ],
    },
    {
        "rule_id": "SEC004",
        "name": "Access Token",
        "severity": Severity.HIGH,
        "patterns": [
            r"(?i)(?:access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]",
            # AWS access keys
            r"AKIA[0-9A-Z]{16}",
            # GitHub tokens
            r"ghp_[A-Za-z0-9]{36}",
            r"github_pat_[A-Za-z0-9_]{82}",
            # Slack tokens
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
        ],
        "description": "An access token is hardcoded in the source code.",
        "impact": "An attacker could use the token to access the associated service or API.",
        "remediation": "Revoke the token immediately if it has been committed. Use environment variables or a secrets manager.",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Password_Management_Vulnerabilities",
        ],
    },
]


def _redact_secret(value: str) -> str:
    """Redact a secret value, showing only first/last 2 chars."""
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:2]}{'*' * 8}{value[-2:]}"


def scan_file_for_secrets(filepath: str, project_root: str) -> list[Finding]:
    """Scan a single file for secrets. Returns findings with redacted evidence."""
    findings: list[Finding] = []

    try:
        rel_path = os.path.relpath(filepath, project_root)
    except ValueError:
        # On Windows, relpath fails across drives — use the filename
        rel_path = os.path.basename(filepath)

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for i, line in enumerate(lines, 1):
        for rule in SECRET_PATTERNS:
            for pattern in rule["patterns"]:
                match = re.search(pattern, line)
                if match:
                    # Extract the matched secret for redaction
                    secret_value = match.group(0)
                    if match.groups():
                        secret_value = match.group(1)

                    redacted = _redact_secret(secret_value)
                    findings.append(
                        Finding(
                            rule_id=rule["rule_id"],
                            title=rule["name"],
                            severity=rule["severity"],
                            confidence=Confidence.MEDIUM,
                            category="Secrets",
                            file=rel_path,
                            line=i,
                            description=rule["description"],
                            evidence=f"Value: {redacted}",
                            impact=rule["impact"],
                            remediation=rule["remediation"],
                            references=rule["references"],
                            detection_method="pattern",
                            manual_verification_required=True,
                        )
                    )
                    break  # Only report one finding per pattern per line
            else:
                continue
            break  # Found a match, move to next line

    return findings


def audit_secrets(project_path: str, all_files: list[str]) -> CheckResult:
    """Run secret detection on all project files."""
    result = CheckResult(
        name="secrets",
        status=CheckStatus.COMPLETED,
        files_scanned=len(all_files),
    )

    findings: list[Finding] = []

    for filepath in all_files:
        # Skip binary files
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(1024)
                if b"\x00" in chunk:
                    continue  # Binary file
        except OSError:
            continue

        file_findings = scan_file_for_secrets(filepath, project_path)
        findings.extend(file_findings)

    result.findings = findings
    return result
