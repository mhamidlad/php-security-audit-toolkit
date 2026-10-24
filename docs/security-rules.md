# Security Rules

## PHP Static Analysis Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| PHP001 | SQL Injection | CRITICAL | Detects dynamic SQL construction with untrusted input |
| PHP002 | Command Injection | HIGH | Detects unsafe shell execution functions with user input |
| PHP003 | Cross-Site Scripting | HIGH | Detects unescaped output of untrusted data |
| PHP004 | Unsafe Deserialization | HIGH | Detects unserialize() calls |
| PHP005 | File Inclusion | HIGH | Detects dynamic paths in include/require statements |
| PHP006 | Path Traversal | HIGH | Detects untrusted paths in file operations |
| PHP007 | Weak Cryptography | MEDIUM | Detects legacy hash functions (MD5, SHA1) |
| PHP008 | Insecure Randomness | HIGH | Detects predictable randomness in security contexts |
| PHP009 | Weak Password Hashing | HIGH | Detects plaintext or inappropriate password storage |
| PHP010 | Unsafe Redirect | MEDIUM | Detects redirects using untrusted input |
| PHP011 | SSRF | HIGH | Detects network requests with user-controlled URLs |
| PHP012 | Debug Exposure | MEDIUM | Detects production debug/error settings |

## Runtime Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| RT001 | End-of-Life PHP Version | HIGH | Reports PHP versions that have reached end-of-life |
| RT002 | Runtime Version Mismatch | LOW | Warns about CLI vs production runtime differences |

## Dependency Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| DEP001 | Vulnerable Dependency | HIGH | Known vulnerable Composer packages |
| DEP002 | Missing Lockfile | MEDIUM | composer.lock is missing |
| DEP003 | Risky Composer Script | MEDIUM | Potentially dangerous Composer scripts |

## Secret Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| SEC001 | API Key | HIGH | Hardcoded API keys |
| SEC002 | Private Key | CRITICAL | Private keys in source code |
| SEC003 | Database Credential | HIGH | Hardcoded database passwords |
| SEC004 | Access Token | HIGH | Hardcoded access tokens |

## Configuration Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| CFG001 | Debug Mode Enabled | MEDIUM | APP_DEBUG or debug settings enabled |
| CFG002 | Error Display Enabled | MEDIUM | display_errors enabled |
| CFG003 | Insecure Session Cookie | MEDIUM/LOW | Insecure cookie settings |
| CFG004 | Dangerous PHP Directive | HIGH | allow_url_include or similar enabled |

## Docker Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| DOCKER001 | Unpinned Base Image | LOW/MEDIUM | Mutable or unpinned image tags |
| DOCKER002 | Container Runs as Root | MEDIUM | No USER directive in Dockerfile |
| DOCKER003 | Secret File in Image | HIGH | Secret files copied into image |

## GitHub Actions Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| GHA001 | Excessive Permissions | MEDIUM/HIGH | Broad or missing workflow permissions |
| GHA002 | Unpinned Action | LOW | Third-party actions not pinned to SHA |

## Confidence Levels

- **HIGH**: The finding is based on a confirmed configuration fact or known advisory.
- **MEDIUM**: The finding is based on a pattern that is likely a real issue.
- **LOW**: The finding is based on a pattern that requires manual verification.

## Detection Methods

- **pattern**: Rule-based pattern matching on source code.
- **configuration**: Analysis of configuration files.
- **runtime**: Detection of runtime environment properties.
- **composer-audit**: Integration with Composer's audit feature.
