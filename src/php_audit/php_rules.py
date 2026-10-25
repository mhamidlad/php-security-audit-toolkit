"""PHP security detection rules — static analysis patterns."""

from __future__ import annotations

import re

from .models import Confidence, Finding, Severity


def read_file_lines(filepath: str) -> list[str]:
    """Read a file and return its lines. Returns empty list on error."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except (OSError, UnicodeDecodeError):
        return []


def _make_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    category: str,
    file_path: str,
    line_num: int,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: list[str],
    detection_method: str = "pattern",
    manual_verification_required: bool = True,
) -> Finding:
    """Helper to create a Finding."""
    # Redact evidence — strip potential secrets from code snippets
    redacted = _redact_evidence(evidence)
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        category=category,
        file=str(file_path),
        line=line_num,
        description=description,
        evidence=redacted,
        impact=impact,
        remediation=remediation,
        references=references,
        detection_method=detection_method,
        manual_verification_required=manual_verification_required,
    )


def _redact_evidence(evidence: str) -> str:
    """Redact potential secrets from evidence strings."""
    # Redact API key patterns
    evidence = re.sub(
        r"(api[_-]?key|apikey|secret|password|token)\s*[=:]\s*['\"][^'\"]+['\"]",
        r"\1 = '[REDACTED]'",
        evidence,
        flags=re.IGNORECASE,
    )
    # Redact AWS keys
    evidence = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED]", evidence)
    # Truncate long evidence
    if len(evidence) > 200:
        evidence = evidence[:200] + "..."
    return evidence


# ============================================================================
# Rule definitions: each rule is a function that takes (filepath, lines) and
# returns a list of Findings.
# ============================================================================


def rule_php001_sql_injection(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP001: SQL Injection — dynamic SQL construction with untrusted input."""
    findings: list[Finding] = []
    # Patterns: string concatenation in SQL queries
    patterns = [
        r"(query|execute|exec|prepare)\s*\(\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*['\"]\s*\.\s*\$",
        r"\$\w+\s*=\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*['\"]\s*\.\s*\$",
        r"['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{?\$\w+\}?.*['\"]",
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern in patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                findings.append(
                    _make_finding(
                        rule_id="PHP001",
                        title="SQL Injection",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.MEDIUM,
                        category="SQL Injection",
                        file_path=filepath,
                        line_num=i,
                        description="Untrusted input appears to be concatenated directly into a SQL query.",
                        evidence=stripped,
                        impact="An attacker could manipulate the query to read, modify, or delete database data.",
                        remediation="Use parameterized queries with PDO prepared statements. Never concatenate user input into SQL.",
                        references=[
                            "https://www.php.net/manual/en/pdo.prepared-statements.php",
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                        ],
                    )
                )
                break  # Only report once per line
    return findings


def rule_php002_command_injection(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP002: Command Injection — unsafe shell execution functions."""
    findings: list[Finding] = []
    dangerous_functions = [
        (r"\bshell_exec\s*\(\s*[^)]*\$[^)]*\)", "shell_exec"),
        (r"\bexec\s*\(\s*[^)]*\$[^)]*\)", "exec"),
        (r"\bsystem\s*\(\s*[^)]*\$[^)]*\)", "system"),
        (r"\bpassthru\s*\(\s*[^)]*\$[^)]*\)", "passthru"),
        (r"\bproc_open\s*\(\s*[^)]*\$[^)]*\)", "proc_open"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern, func_name in dangerous_functions:
            if re.search(pattern, stripped):
                # Check if escapeshellarg/escapeshellcmd is used
                if "escapeshellarg" in stripped or "escapeshellcmd" in stripped:
                    continue
                findings.append(
                    _make_finding(
                        rule_id="PHP002",
                        title="Command Injection",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="Command Injection",
                        file_path=filepath,
                        line_num=i,
                        description=f"User input is passed to {func_name}() without proper escaping.",
                        evidence=stripped,
                        impact="An attacker could execute arbitrary commands on the server.",
                        remediation=(
                            "Use escapeshellarg() for individual arguments, escapeshellcmd() for entire commands, "
                            "or avoid shell execution entirely by using PHP's built-in functions."
                        ),
                        references=[
                            "https://www.php.net/manual/en/function.escapeshellarg.php",
                            "https://owasp.org/www-community/attacks/Command_Injection",
                        ],
                    )
                )
                break
    return findings


def rule_php003_xss(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP003: Cross-Site Scripting — unescaped output of untrusted data."""
    findings: list[Finding] = []
    # echo/print of $_GET/$_POST/$_REQUEST/$_SERVER without htmlspecialchars
    output_patterns = [
        r"\becho\s+\$(_GET|_POST|_REQUEST|_SERVER|_COOKIE)\b",
        r"\bprint\s+\$(_GET|_POST|_REQUEST|_SERVER|_COOKIE)\b",
        r"\becho\s+\$[a-z_]+\s*\.\s*\$(_GET|_POST|_REQUEST|_SERVER|_COOKIE)\b",
        r"\<\?=\s*\$(_GET|_POST|_REQUEST|_SERVER|_COOKIE)\b",
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern in output_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                # Check if htmlspecialchars is used
                if "htmlspecialchars" in stripped or "htmlentities" in stripped:
                    continue
                findings.append(
                    _make_finding(
                        rule_id="PHP003",
                        title="Cross-Site Scripting",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="Cross-Site Scripting",
                        file_path=filepath,
                        line_num=i,
                        description="Potentially untrusted data is output without HTML escaping.",
                        evidence=stripped,
                        impact="An attacker could inject malicious scripts that execute in users' browsers.",
                        remediation=(
                            "Use htmlspecialchars() for HTML context, or context-specific encoding "
                            "for JavaScript, CSS, or URL output. Consider using a template engine with auto-escaping."
                        ),
                        references=[
                            "https://www.php.net/manual/en/function.htmlspecialchars.php",
                            "https://owasp.org/www-community/attacks/xss/",
                        ],
                    )
                )
                break
    return findings


def rule_php004_unsafe_deserialization(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP004: Unsafe Deserialization — unserialize() on untrusted data."""
    findings: list[Finding] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if re.search(r"\bunserialize\s*\(", stripped):
            findings.append(
                _make_finding(
                    rule_id="PHP004",
                    title="Unsafe Deserialization",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Unsafe Deserialization",
                    file_path=filepath,
                    line_num=i,
                    description="unserialize() is called, which can lead to PHP object injection if the input is untrusted.",
                    evidence=stripped,
                    impact="An attacker could exploit PHP object injection to execute arbitrary code or cause denial of service.",
                    remediation=(
                        "Use json_decode() instead of unserialize() for untrusted data. "
                        "If unserialize() is unavoidable, use the allowed_classes option to restrict deserialized types."
                    ),
                    references=[
                        "https://www.php.net/manual/en/function.unserialize.php",
                        "https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection",
                    ],
                )
            )
    return findings


def rule_php005_file_inclusion(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP005: File Inclusion — dynamic paths in include/require."""
    findings: list[Finding] = []
    patterns = [
        r"\b(include|include_once|require|require_once)\s*\(?\s*\$",
        r"\b(include|include_once|require|require_once)\s*\(?\s*['\"][^'\"]*['\"]?\s*\.\s*\$",
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern in patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                findings.append(
                    _make_finding(
                        rule_id="PHP005",
                        title="File Inclusion",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="File Inclusion",
                        file_path=filepath,
                        line_num=i,
                        description="A dynamic path is used in an include/require statement.",
                        evidence=stripped,
                        impact="An attacker could manipulate the path to include arbitrary files (LFI/RFI).",
                        remediation=(
                            "Avoid dynamic file paths in include/require statements. Use a whitelist of allowed files, "
                            "or validate the path against a known directory."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://www.php.net/manual/en/security.filesystem.php",
                        ],
                    )
                )
                break
    return findings


def rule_php006_path_traversal(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP006: Path Traversal — untrusted paths in file operations."""
    findings: list[Finding] = []
    file_funcs = r"\b(file_get_contents|file_put_contents|fopen|readfile|unlink|copy|rename|move_uploaded_file)\s*\("
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if re.search(file_funcs, stripped):
            # Check if superglobal is used
            if re.search(r"\$(_GET|_POST|_REQUEST|_COOKIE)\b", stripped):
                findings.append(
                    _make_finding(
                        rule_id="PHP006",
                        title="Path Traversal",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="Path Traversal",
                        file_path=filepath,
                        line_num=i,
                        description="User input from a superglobal is used in a file operation without path validation.",
                        evidence=stripped,
                        impact="An attacker could read or modify arbitrary files on the server.",
                        remediation=(
                            "Validate and sanitize file paths using realpath() and basename(). "
                            "Ensure the path stays within an expected directory."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://www.php.net/manual/en/function.realpath.php",
                        ],
                    )
                )
    return findings


def rule_php007_weak_crypto(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP007: Weak Cryptography — legacy hash functions for security purposes."""
    findings: list[Finding] = []
    weak_hashes = r"\b(md5|sha1)\s*\("
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if re.search(weak_hashes, stripped, re.IGNORECASE):
            # Check if this looks like it's for passwords or security
            context_keywords = ["password", "pass", "secret", "token", "auth", "hash", "crypt"]
            looks_security_related = any(
                kw in stripped.lower() for kw in context_keywords
            )
            findings.append(
                _make_finding(
                    rule_id="PHP007",
                    title="Weak Cryptography",
                    severity=Severity.MEDIUM if looks_security_related else Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    category="Weak Cryptography",
                    file_path=filepath,
                    line_num=i,
                    description=(
                        "A legacy hash function is used"
                        + (" in a security-sensitive context." if looks_security_related else ".")
                    ),
                    evidence=stripped,
                    impact="Legacy hash functions are vulnerable to collision and preimage attacks.",
                    remediation=(
                        "Use password_hash() for password storage, hash() with SHA-256 or SHA-3 for general hashing. "
                        "For password verification, use password_verify()."
                    ),
                    references=[
                        "https://www.php.net/manual/en/function.password-hash.php",
                        "https://owasp.org/www-community/controls/Hashing",
                    ],
                )
            )
    return findings


def rule_php008_insecure_randomness(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP008: Insecure Randomness — predictable randomness for security tokens."""
    findings: list[Finding] = []
    weak_random = r"\b(rand|mt_rand|mt_srand|srand)\s*\("
    security_context = ["token", "password", "secret", "session", "reset", "otp", "nonce", "key"]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if re.search(weak_random, stripped, re.IGNORECASE):
            is_security = any(kw in stripped.lower() for kw in security_context)
            if is_security:
                findings.append(
                    _make_finding(
                        rule_id="PHP008",
                        title="Insecure Randomness",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="Insecure Randomness",
                        file_path=filepath,
                        line_num=i,
                        description="A predictable random function is used in a security-sensitive context.",
                        evidence=stripped,
                        impact="Tokens generated with predictable randomness can be guessed by attackers.",
                        remediation=(
                            "Use random_bytes() or random_int() for security-sensitive randomness. "
                            "These use a cryptographically secure random number generator."
                        ),
                        references=[
                            "https://www.php.net/manual/en/function.random-bytes.php",
                            "https://www.php.net/manual/en/function.random-int.php",
                        ],
                    )
                )
    return findings


def rule_php009_weak_password_hashing(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP009: Weak Password Hashing — plaintext or inappropriate password storage."""
    findings: list[Finding] = []
    # Check for md5/sha1 used with "password" context
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        lower = stripped.lower()
        # Direct md5/sha1 of password variable
        if re.search(r"\b(md5|sha1)\s*\(\s*\$.*password", lower):
            findings.append(
                _make_finding(
                    rule_id="PHP009",
                    title="Weak Password Hashing",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="Authentication",
                    file_path=filepath,
                    line_num=i,
                    description="Passwords are hashed using a legacy algorithm instead of password_hash().",
                    evidence=stripped,
                    impact="Password hashes may be cracked if the database is compromised.",
                    remediation=(
                        "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID for password storage, "
                        "and password_verify() for password verification."
                    ),
                    references=[
                        "https://www.php.net/manual/en/function.password-hash.php",
                        "https://www.php.net/manual/en/function.password-verify.php",
                    ],
                )
            )
    return findings


def rule_php010_unsafe_redirect(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP010: Unsafe Redirects — redirects using untrusted input."""
    findings: list[Finding] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if re.search(r"\bheader\s*\(\s*[^)]*\$(_GET|_POST|_REQUEST)", stripped, re.IGNORECASE):
            findings.append(
                _make_finding(
                    rule_id="PHP010",
                    title="Unsafe Redirect",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="Unsafe Redirect",
                    file_path=filepath,
                    line_num=i,
                    description="A redirect uses untrusted user input without validation.",
                    evidence=stripped,
                    impact="An attacker could redirect users to malicious sites (open redirect).",
                    remediation=(
                        "Validate the redirect URL against a whitelist of allowed destinations. "
                        "Use relative paths or absolute URLs from a trusted list."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                    ],
                )
            )
    return findings


def rule_php011_ssrf(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP011: SSRF — network requests with user-controlled URLs."""
    findings: list[Finding] = []
    network_funcs = r"\b(curl_setopt|file_get_contents|fopen|stream_context_create)\s*\("
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        if re.search(network_funcs, stripped):
            if re.search(r"\$(_GET|_POST|_REQUEST|_COOKIE)\b", stripped):
                findings.append(
                    _make_finding(
                        rule_id="PHP011",
                        title="Server-Side Request Forgery",
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,
                        category="SSRF",
                        file_path=filepath,
                        line_num=i,
                        description="A network request appears to use a user-controlled URL.",
                        evidence=stripped,
                        impact="An attacker could make the server send requests to internal services or arbitrary hosts.",
                        remediation=(
                            "Validate and restrict URLs to allowed hosts and protocols. "
                            "Block internal IP ranges and use a whitelist of permitted destinations."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SSRF",
                        ],
                        manual_verification_required=True,
                    )
                )
    return findings


def rule_php012_debug_exposure(filepath: str, lines: list[str]) -> list[Finding]:
    """PHP012: Debug Exposure — production debug/error settings in PHP code."""
    findings: list[Finding] = []
    debug_patterns = [
        (r"\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"](?:1|on|On|true)['\"]", "display_errors enabled"),
        (r"\bini_set\s*\(\s*['\"]error_reporting['\"]\s*,\s*['\"]E_ALL['\"]", "error_reporting set to E_ALL"),
        (r"\berror_reporting\s*\(\s*E_ALL\s*\)", "error_reporting set to E_ALL"),
        (r"APP_DEBUG.*true", "Laravel APP_DEBUG set to true"),
        (r"APP_ENV.*dev", "Laravel APP_ENV set to dev"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern, desc in debug_patterns:
            if re.search(pattern, stripped):
                findings.append(
                    _make_finding(
                        rule_id="PHP012",
                        title="Debug Exposure",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="Configuration",
                        file_path=filepath,
                        line_num=i,
                        description=f"{desc} — this may expose sensitive information in production.",
                        evidence=stripped,
                        impact="Error messages can reveal internal paths, database structure, and implementation details.",
                        remediation=(
                            "Disable display_errors and APP_DEBUG in production. "
                            "Log errors to files instead of displaying them to users."
                        ),
                        references=[
                            "https://www.php.net/manual/en/errorfunc.configuration.php",
                        ],
                        manual_verification_required=False,
                    )
                )
                break
    return findings


# Registry of all PHP rules
PHP_RULES: dict[str, dict] = {
    "PHP001": {
        "title": "SQL Injection",
        "severity": Severity.CRITICAL,
        "category": "SQL Injection",
        "description": "Detects dynamic SQL construction with untrusted input.",
        "func": rule_php001_sql_injection,
    },
    "PHP002": {
        "title": "Command Injection",
        "severity": Severity.HIGH,
        "category": "Command Injection",
        "description": "Detects unsafe shell execution functions.",
        "func": rule_php002_command_injection,
    },
    "PHP003": {
        "title": "Cross-Site Scripting",
        "severity": Severity.HIGH,
        "category": "Cross-Site Scripting",
        "description": "Detects unescaped output of untrusted data.",
        "func": rule_php003_xss,
    },
    "PHP004": {
        "title": "Unsafe Deserialization",
        "severity": Severity.HIGH,
        "category": "Unsafe Deserialization",
        "description": "Detects unserialize() calls on potentially untrusted data.",
        "func": rule_php004_unsafe_deserialization,
    },
    "PHP005": {
        "title": "File Inclusion",
        "severity": Severity.HIGH,
        "category": "File Inclusion",
        "description": "Detects dynamic paths in include/require statements.",
        "func": rule_php005_file_inclusion,
    },
    "PHP006": {
        "title": "Path Traversal",
        "severity": Severity.HIGH,
        "category": "Path Traversal",
        "description": "Detects untrusted paths in file operations.",
        "func": rule_php006_path_traversal,
    },
    "PHP007": {
        "title": "Weak Cryptography",
        "severity": Severity.MEDIUM,
        "category": "Weak Cryptography",
        "description": "Detects legacy hash functions in security contexts.",
        "func": rule_php007_weak_crypto,
    },
    "PHP008": {
        "title": "Insecure Randomness",
        "severity": Severity.HIGH,
        "category": "Insecure Randomness",
        "description": "Detects predictable randomness for security tokens.",
        "func": rule_php008_insecure_randomness,
    },
    "PHP009": {
        "title": "Weak Password Hashing",
        "severity": Severity.HIGH,
        "category": "Authentication",
        "description": "Detects plaintext or inappropriate password storage.",
        "func": rule_php009_weak_password_hashing,
    },
    "PHP010": {
        "title": "Unsafe Redirect",
        "severity": Severity.MEDIUM,
        "category": "Unsafe Redirect",
        "description": "Detects redirects using untrusted input.",
        "func": rule_php010_unsafe_redirect,
    },
    "PHP011": {
        "title": "Server-Side Request Forgery",
        "severity": Severity.HIGH,
        "category": "SSRF",
        "description": "Detects network requests with user-controlled URLs.",
        "func": rule_php011_ssrf,
    },
    "PHP012": {
        "title": "Debug Exposure",
        "severity": Severity.MEDIUM,
        "category": "Configuration",
        "description": "Detects production debug/error settings in PHP code.",
        "func": rule_php012_debug_exposure,
    },
}


def run_php_rules(filepath: str) -> list[Finding]:
    """Run all PHP rules on a single file."""
    lines = read_file_lines(filepath)
    if not lines:
        return []
    all_findings: list[Finding] = []
    for rule_id, rule_info in PHP_RULES.items():
        func = rule_info["func"]
        try:
            findings = func(filepath, lines)
            all_findings.extend(findings)
        except Exception:
            # A rule error should not stop the scan
            continue
    return all_findings
