"""Remediation guidance for findings."""

from __future__ import annotations

REMEDIATION_GUIDES: dict[str, dict] = {
    "PHP001": {
        "title": "SQL Injection",
        "vulnerable": 'query = "SELECT * FROM users WHERE email = \'"+ email + "\'"',
        "secure": "cursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))",
        "explanation": (
            "Parameterized queries separate SQL structure from data, preventing "
            "user input from being interpreted as SQL commands."
        ),
    },
    "PHP002": {
        "title": "Command Injection",
        "vulnerable": 'shell_exec("ping " + $user_input)',
        "secure": 'shell_exec("ping " . escapeshellarg($user_input))',
        "explanation": (
            "escapeshellarg() escapes single quotes and wraps the argument in single quotes, "
            "preventing shell metacharacter injection."
        ),
    },
    "PHP003": {
        "title": "Cross-Site Scripting",
        "vulnerable": 'echo $_GET["name"];',
        "secure": 'echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");',
        "explanation": (
            "htmlspecialchars() converts special characters to HTML entities, "
            "preventing script execution in the browser."
        ),
    },
    "PHP004": {
        "title": "Unsafe Deserialization",
        "vulnerable": '$data = unserialize($user_input);',
        "secure": '$data = json_decode($user_input, true);',
        "explanation": (
            "json_decode() does not allow code execution. If unserialize() is unavoidable, "
            "use the allowed_classes option."
        ),
    },
    "PHP009": {
        "title": "Weak Password Hashing",
        "vulnerable": '$hashed = md5($password);',
        "secure": '$hashed = password_hash($password, PASSWORD_BCRYPT);',
        "explanation": (
            "password_hash() uses bcrypt (or Argon2) with automatic salt generation "
            "and adjustable cost factor. password_verify() handles verification."
        ),
    },
}


def get_remediation_guide(rule_id: str) -> dict | None:
    """Get remediation guide for a rule ID."""
    return REMEDIATION_GUIDES.get(rule_id)
