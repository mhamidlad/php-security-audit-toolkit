"""Tests for the PHP security rules."""

from __future__ import annotations

from pathlib import Path

from php_audit.php_rules import (
    PHP_RULES,
    rule_php001_sql_injection,
    rule_php002_command_injection,
    rule_php003_xss,
    rule_php004_unsafe_deserialization,
    rule_php005_file_inclusion,
    rule_php006_path_traversal,
    rule_php007_weak_crypto,
    rule_php008_insecure_randomness,
    rule_php009_weak_password_hashing,
    rule_php010_unsafe_redirect,
    rule_php012_debug_exposure,
    run_php_rules,
)

VULNERABLE_FILE = Path(__file__).parent.parent / "examples" / "vulnerable" / "vulnerable.php"
SECURE_FILE = Path(__file__).parent.parent / "examples" / "secure" / "secure.php"


def _read_lines(filepath):
    with open(filepath, encoding="utf-8") as f:
        return f.readlines()


class TestSqlInjection:
    def test_detects_sql_injection(self):
        lines = ['$query = "SELECT * FROM users WHERE email = \'" . $email;']
        findings = rule_php001_sql_injection("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP001"

    def test_does_not_flag_prepared_statement(self):
        lines = ['$stmt = $db->prepare("SELECT * FROM users WHERE email = ?");']
        findings = rule_php001_sql_injection("test.php", lines)
        assert len(findings) == 0

    def test_does_not_flag_comment(self):
        lines = ["// $query = \"SELECT * FROM users WHERE email = '\" . $email;"]
        findings = rule_php001_sql_injection("test.php", lines)
        assert len(findings) == 0


class TestCommandInjection:
    def test_detects_shell_exec_with_variable(self):
        lines = ['$output = shell_exec("ping " . $user_input);']
        findings = rule_php002_command_injection("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP002"

    def test_does_not_flag_escapeshellarg(self):
        lines = ['$output = shell_exec("ping " . escapeshellarg($user_input));']
        findings = rule_php002_command_injection("test.php", lines)
        assert len(findings) == 0


class TestXss:
    def test_detects_echo_superglobal(self):
        lines = ['echo $_GET["name"];']
        findings = rule_php003_xss("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP003"

    def test_does_not_flag_htmlspecialchars(self):
        lines = ['echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");']
        findings = rule_php003_xss("test.php", lines)
        assert len(findings) == 0


class TestUnsafeDeserialization:
    def test_detects_unserialize(self):
        lines = ['$data = unserialize($input);']
        findings = rule_php004_unsafe_deserialization("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP004"


class TestFileInclusion:
    def test_detects_dynamic_include(self):
        lines = ['include($page . ".php");']
        findings = rule_php005_file_inclusion("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP005"


class TestPathTraversal:
    def test_detects_superglobal_in_file_op(self):
        lines = ['$content = file_get_contents($_GET["file"]);']
        findings = rule_php006_path_traversal("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP006"


class TestWeakCrypto:
    def test_detects_md5(self):
        lines = ['$hash = md5($data);']
        findings = rule_php007_weak_crypto("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP007"


class TestInsecureRandomness:
    def test_detects_mt_rand_for_token(self):
        lines = ['$token = mt_rand();']
        findings = rule_php008_insecure_randomness("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP008"

    def test_does_not_flag_random_bytes(self):
        lines = ['$token = bin2hex(random_bytes(32));']
        findings = rule_php008_insecure_randomness("test.php", lines)
        assert len(findings) == 0


class TestWeakPasswordHashing:
    def test_detects_md5_password(self):
        lines = ['$hashed = md5($password);']
        findings = rule_php009_weak_password_hashing("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP009"


class TestUnsafeRedirect:
    def test_detects_header_redirect_with_superglobal(self):
        lines = ['header("Location: " . $_GET["url"]);']
        findings = rule_php010_unsafe_redirect("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP010"


class TestDebugExposure:
    def test_detects_display_errors(self):
        lines = ["ini_set('display_errors', '1');"]
        findings = rule_php012_debug_exposure("test.php", lines)
        assert len(findings) >= 1
        assert findings[0].rule_id == "PHP012"

    def test_detects_app_debug_true(self):
        lines = ["APP_DEBUG=true"]
        findings = rule_php012_debug_exposure(".env", lines)
        assert len(findings) >= 1


class TestFullFileScan:
    def test_vulnerable_file_has_findings(self):
        findings = run_php_rules(str(VULNERABLE_FILE))
        rule_ids = {f.rule_id for f in findings}
        assert "PHP001" in rule_ids
        assert "PHP003" in rule_ids
        assert "PHP004" in rule_ids

    def test_secure_file_has_fewer_findings(self):
        findings = run_php_rules(str(SECURE_FILE))
        # The secure file should have far fewer findings
        assert len(findings) < 5

    def test_all_rules_are_registered(self):
        assert len(PHP_RULES) == 12
        for i in range(1, 13):
            assert f"PHP{i:03d}" in PHP_RULES

    def test_findings_have_redacted_evidence(self):
        """Ensure potential secrets in evidence are redacted."""
        from php_audit.php_rules import _redact_evidence

        evidence = '$api_key = "sk-1234567890abcdefghijklmnop";'
        redacted = _redact_evidence(evidence)
        assert "[REDACTED]" in redacted
        assert "sk-1234" not in redacted
