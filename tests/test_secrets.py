"""Tests for secret detection."""

from __future__ import annotations

from php_audit.secrets import audit_secrets, scan_file_for_secrets


class TestSecretDetection:
    def test_detects_api_key(self, tmp_path):
        f = tmp_path / "test.php"
        f.write_text('<?php\n$api_key = "sk-1234567890abcdefghijklmnop";\n')
        findings = scan_file_for_secrets(str(f), str(tmp_path))
        assert any(find.rule_id == "SEC001" for find in findings)

    def test_detects_private_key(self, tmp_path):
        f = tmp_path / "test.php"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n")
        findings = scan_file_for_secrets(str(f), str(tmp_path))
        assert any(find.rule_id == "SEC002" for find in findings)

    def test_detects_database_password(self, tmp_path):
        f = tmp_path / "test.php"
        f.write_text('<?php\n$db_password = "my_secret_db_pass";\n')
        findings = scan_file_for_secrets(str(f), str(tmp_path))
        assert any(find.rule_id == "SEC003" for find in findings)

    def test_detects_github_token(self, tmp_path):
        f = tmp_path / "test.php"
        f.write_text('<?php\n$token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";\n')
        findings = scan_file_for_secrets(str(f), str(tmp_path))
        assert any(find.rule_id == "SEC004" for find in findings)

    def test_secret_values_are_redacted(self, tmp_path):
        """Ensure that no secret value appears in full in findings."""
        f = tmp_path / "test.php"
        f.write_text('<?php\n$api_key = "sk-verysecretkey1234567890abcd";\n')
        findings = scan_file_for_secrets(str(f), str(tmp_path))
        for finding in findings:
            assert "sk-verysecretkey1234567890abcd" not in finding.evidence

    def test_skips_binary_files(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b'\x00\x01\x02\x03api_key = "sk-test1234567890abcdefghij"')
        # audit_secrets checks for binary files before scanning
        result = audit_secrets(str(tmp_path), [str(f)])
        assert len(result.findings) == 0

    def test_audit_secrets_finds_credentials(self, tmp_path):
        f = tmp_path / "config.php"
        f.write_text('<?php\n$api_key = "sk-1234567890abcdefghijklmnop";\n')
        result = audit_secrets(str(tmp_path), [str(f)])
        assert len(result.findings) > 0
