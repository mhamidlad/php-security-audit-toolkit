"""Tests for the reporters."""

from __future__ import annotations

import json

from php_audit.models import (
    CheckResult,
    CheckStatus,
    Confidence,
    Finding,
    ScanResult,
    Severity,
)
from php_audit.reporters.json_report import render_json
from php_audit.reporters.markdown_report import render_markdown
from php_audit.reporters.sarif_report import render_sarif


def _create_test_result() -> ScanResult:
    """Create a test ScanResult with sample findings."""
    finding = Finding(
        rule_id="PHP001",
        title="SQL Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        category="SQL Injection",
        file="test.php",
        line=18,
        description="Untrusted input concatenated into SQL query",
        evidence="$query = \"SELECT * FROM ... WHERE email = '\" . $email",
        impact="Database data exposure",
        remediation="Use parameterized queries",
        references=["https://www.php.net/manual/en/pdo.prepared-statements.php"],
        detection_method="pattern",
        manual_verification_required=True,
    )
    check = CheckResult(
        name="php",
        status=CheckStatus.COMPLETED,
        findings=[finding],
        files_scanned=1,
    )
    return ScanResult(
        project_path="/tmp/test",
        scan_time="2026-10-25T02:00:00Z",
        files_scanned=1,
        checks=[check],
        findings=[finding],
    )


class TestJsonReport:
    def test_valid_json(self):
        result = _create_test_result()
        output = render_json(result)
        data = json.loads(output)
        assert data["tool"] == "php-security-audit-toolkit"
        assert data["version"] == "0.1.0"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "PHP001"

    def test_summary_has_all_severities(self):
        result = _create_test_result()
        output = render_json(result)
        data = json.loads(output)
        summary = data["summary"]["findings"]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in summary

    def test_no_unredacted_secrets(self):
        """Ensure evidence does not contain full secret values in JSON output."""
        finding = Finding(
            rule_id="SEC001",
            title="API Key",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category="Secrets",
            file="config.php",
            line=1,
            description="API key found",
            evidence="sk-1234567890abcdefghijklmnop",
            impact="Credential exposure",
            remediation="Move to env var",
        )
        result = ScanResult(
            project_path="/tmp",
            scan_time="2026-01-01T00:00:00Z",
            findings=[finding],
        )
        output = render_json(result)
        data = json.loads(output)
        evidence = data["findings"][0]["evidence"]
        assert "sk-1234567890abcdefghijklmnop" not in evidence


class TestSarifReport:
    def test_valid_sarif_structure(self):
        result = _create_test_result()
        output = render_sarif(result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run

    def test_sarif_has_rules(self):
        result = _create_test_result()
        output = render_sarif(result)
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1

    def test_sarif_has_results(self):
        result = _create_test_result()
        output = render_sarif(result)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) >= 1
        assert results[0]["ruleId"] == "PHP001"


class TestMarkdownReport:
    def test_markdown_has_title(self):
        result = _create_test_result()
        output = render_markdown(result)
        assert "PHP Security Audit Report" in output

    def test_markdown_has_finding(self):
        result = _create_test_result()
        output = render_markdown(result)
        assert "PHP001" in output
        assert "SQL Injection" in output

    def test_markdown_has_summary(self):
        result = _create_test_result()
        output = render_markdown(result)
        assert "Summary" in output
        assert "Files scanned" in output

    def test_markdown_has_limitations(self):
        result = _create_test_result()
        output = render_markdown(result)
        assert "Limitations" in output
