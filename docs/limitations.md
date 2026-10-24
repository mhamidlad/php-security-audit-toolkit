# Limitations

## What this tool is NOT

This tool is **not a substitute for**:
- Professional penetration testing
- Manual security code review
- A comprehensive security assessment
- Runtime vulnerability scanning
- Infrastructure or network security testing

## What it does not do

- It does not execute scanned PHP code.
- It does not evaluate PHP configuration files at runtime.
- It does not install or execute project dependencies.
- It does not perform data-flow analysis (in this version).
- It does not detect every vulnerability.
- It does not prove that an application is secure.

## Pattern-based detection

Rules like SQL injection and XSS detection use pattern matching. These
patterns identify suspicious code but cannot determine with certainty whether
the code is exploitable. Findings from these rules are marked as requiring
manual verification.

A clean scan means no configured checks detected a finding — **not** that the
application is free of vulnerabilities.

## Advisory data

PHP runtime advisory data is based on publicly available support and security
information from php.net. If advisory data cannot be verified, the check is
reported as inconclusive rather than fabricating a finding.

The local PHP CLI version may differ from the production web-server runtime.
The toolkit reports this mismatch risk but cannot determine the production
runtime version remotely.

## Framework-specific behavior

PHP frameworks (Laravel, Symfony, WordPress) have different conventions for
configuration, templating, and security. Rules may produce false positives
on framework-specific patterns. Use suppressions to handle known false
positives in your codebase.

## Coverage

This version covers common PHP security patterns. It does not cover:
- Framework-specific vulnerabilities (Laravel, Symfony, WordPress)
- Business logic flaws
- Race conditions
- Timing attacks
- Memory corruption
- Server configuration beyond PHP directives
