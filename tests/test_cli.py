"""Tests for the CLI."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from php_audit.cli import app

runner = CliRunner()


class TestCli:
    def test_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_scan_nonexistent_path(self):
        result = runner.invoke(app, ["scan", "/nonexistent/path/12345"])
        assert result.exit_code == 2

    def test_scan_json_output(self, tmp_path):
        # Create a simple vulnerable PHP file
        vuln_dir = tmp_path / "project"
        vuln_dir.mkdir()
        (vuln_dir / "test.php").write_text(
            '<?php\n$query = "SELECT * FROM users WHERE email = \'" . $email;\n',
            encoding="utf-8",
        )
        output_file = tmp_path / "report.json"

        result = runner.invoke(app, [
            "scan", str(vuln_dir),
            "--format", "json",
            "--output", str(output_file),
        ])

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["tool"] == "php-security-audit-toolkit"
        assert data["version"] == "0.1.0"
        assert len(data["findings"]) > 0

    def test_scan_sarif_output(self, tmp_path):
        vuln_dir = tmp_path / "project"
        vuln_dir.mkdir()
        (vuln_dir / "test.php").write_text(
            '<?php\n$hashed = md5($password);\n',
            encoding="utf-8",
        )
        output_file = tmp_path / "report.sarif"

        result = runner.invoke(app, [
            "scan", str(vuln_dir),
            "--format", "sarif",
            "--output", str(output_file),
        ])

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) > 0

    def test_scan_markdown_output(self, tmp_path):
        vuln_dir = tmp_path / "project"
        vuln_dir.mkdir()
        (vuln_dir / "test.php").write_text(
            '<?php\n$data = unserialize($input);\n',
            encoding="utf-8",
        )
        output_file = tmp_path / "report.md"

        result = runner.invoke(app, [
            "scan", str(vuln_dir),
            "--format", "markdown",
            "--output", str(output_file),
        ])

        assert output_file.exists()
        content = output_file.read_text()
        assert "PHP Security Audit Report" in content
        assert "PHP004" in content

    def test_rules_list(self):
        result = runner.invoke(app, ["rules", "list"])
        assert result.exit_code == 0
        assert "PHP001" in result.output

    def test_rules_show(self):
        result = runner.invoke(app, ["rules", "show", "--id", "PHP001"])
        assert result.exit_code == 0
        assert "SQL Injection" in result.output

    def test_config_validate_valid(self, tmp_path):
        config_file = tmp_path / "php-audit.toml"
        config_file.write_text(
            '[scan]\nchecks = ["php", "secrets"]\nseverity = "medium"\n',
            encoding="utf-8",
        )
        result = runner.invoke(app, ["config", "validate", str(config_file)])
        assert result.exit_code == 0

    def test_config_validate_invalid(self, tmp_path):
        config_file = tmp_path / "php-audit.toml"
        config_file.write_text(
            '[scan]\nchecks = ["invalid_check"]\n',
            encoding="utf-8",
        )
        result = runner.invoke(app, ["config", "validate", str(config_file)])
        assert result.exit_code == 2
