# False Positives

## How the toolkit handles false positives

The toolkit distinguishes between:

1. **Confirmed configuration facts** — e.g., debug mode is enabled.
2. **Known vulnerable dependencies** — e.g., a package version matching an advisory.
3. **Suspicious code patterns** — e.g., SQL string concatenation that may or may not be exploitable.
4. **Findings requiring manual verification** — marked with `manual_verification_required: true`.
5. **Checks that could not run** — e.g., Composer not installed.

Pattern-based rules inherently produce some false positives because they
cannot determine data flow or context without runtime analysis.

## Suppressing known false positives

Add a suppression entry to your configuration file:

```toml
[[suppressions.entries]]
rule_id = "PHP007"
file = "src/Legacy/hash.php"
reason = "MD5 used for non-security file checksum, not password storage"
```

Suppressed findings are listed in the report as "suppressed" — they are never
silently hidden. Each suppression must include a reason.

## Common false positive scenarios

### PHP007: Weak Cryptography

MD5 or SHA1 may be used for non-security purposes such as:
- File checksums for download verification
- Cache keys
- Content addressing (e.g., Git-style hashing)

These are not security vulnerabilities. Suppress them if the hash is not used
for passwords, tokens, or other security-sensitive data.

### PHP003: Cross-Site Scripting

The rule may flag output that is already escaped through a framework's
auto-escaping mechanism (e.g., Blade's `{{ }}` syntax in Laravel). If the
output is already escaped, suppress the finding.

### PHP005: File Inclusion

Dynamic includes using a whitelist or constant mapping are safe. If the
included path is validated against an allowlist, suppress the finding.
