# PHP Security Audit Toolkit

**Find PHP security risks. Understand the findings. Fix them. Verify the results.**

A developer-focused security auditing toolkit for PHP applications. It inspects
PHP source code, Composer manifests, Dockerfiles, GitHub Actions workflows,
configuration files, and project metadata — then produces structured,
actionable security findings.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Problems It Solves](#2-problems-it-solves)
3. [Features](#3-features)
4. [Supported Checks](#4-supported-checks)
5. [Installation](#5-installation)
6. [Quick Start](#6-quick-start)
7. [Example Output](#7-example-output)
8. [Report Formats](#8-report-formats)
9. [Severity Definitions](#9-severity-definitions)
10. [Configuration](#10-configuration)
11. [False-Positive Handling](#11-false-positive-handling)
12. [Security Limitations](#12-security-limitations)
13. [Privacy Commitments](#13-privacy-commitments)
14. [Contributing](#14-contributing)
15. [Responsible Disclosure](#15-responsible-disclosure)
16. [Roadmap](#16-roadmap)
17. [License](#17-license)
18. [Contact](#18-contact)

---

## 1. Overview

The PHP Security Audit Toolkit is a command-line tool that scans local PHP
projects for common security weaknesses. It is built for developers, security
engineers, software agencies, and organizations that need to identify security
risks in PHP codebases before deployment.

The toolkit performs genuine static analysis — it is not a mockup or a
demonstration-only CLI. Every check is backed by implemented logic, automated
tests, and documented remediation guidance.

**The tool does not prove that an application is secure.** A clean scan means
no configured checks detected a finding — not that the application is free of
vulnerabilities.

---

## 2. Problems It Solves

AI coding assistants and rapid development practices can introduce security
weaknesses into PHP applications:

- SQL injection through dynamic query construction
- Command injection through unsafe shell execution
- Cross-site scripting through unescaped output
- Unsafe deserialization of untrusted data
- Hardcoded credentials in source code
- End-of-life PHP runtime versions
- Known vulnerable Composer dependencies
- Insecure Docker and CI/CD configurations
- Weak cryptographic practices

This toolkit identifies these risks locally, explains them, and provides
remediation guidance — without uploading your code to external services.

---

## 3. Features

- **PHP static analysis** — 12+ detection rules covering SQL injection,
  command injection, XSS, deserialization, file inclusion, path traversal,
  weak cryptography, insecure randomness, password handling, unsafe redirects,
  SSRF, and debug exposure.
- **PHP runtime auditing** — Detects installed PHP versions, checks
  end-of-life status, identifies runtime mismatches.
- **Composer dependency auditing** — Analyzes `composer.json` and
  `composer.lock`, integrates with `composer audit`.
- **Secret detection** — Scans for API keys, private keys, database credentials,
  access tokens, and cloud credentials. All secrets are redacted in output.
- **Configuration auditing** — Checks for debug mode, error display, insecure
  session cookies, and dangerous PHP directives.
- **Docker auditing** — Inspects Dockerfiles for unpinned base images,
  root execution, and secret file copying.
- **GitHub Actions auditing** — Checks for excessive permissions, unpinned
  third-party actions, and unsafe pull-request handling.
- **Multiple report formats** — Terminal, JSON, Markdown, and SARIF 2.1.0.
- **Finding suppression** — Documented configuration mechanism for known
  false positives.
- **Secret redaction** — No secret values appear in any report format.
- **No external transmission** — All scanning is local. No code, credentials,
  or results are sent to external services.

---

## 4. Supported Checks

| Rule ID | Category | Description |
|---------|----------|-------------|
| PHP001 | SQL Injection | Dynamic SQL construction with untrusted input |
| PHP002 | Command Injection | Unsafe shell execution functions |
| PHP003 | Cross-Site Scripting | Unescaped output of untrusted data |
| PHP004 | Unsafe Deserialization | `unserialize()` on untrusted data |
| PHP005 | File Inclusion | Dynamic paths in include/require |
| PHP006 | Path Traversal | Untrusted paths in file operations |
| PHP007 | Weak Cryptography | Legacy hash functions (MD5, SHA1) for security purposes |
| PHP008 | Insecure Randomness | `rand()` / `mt_rand()` for security tokens |
| PHP009 | Weak Password Hashing | Plaintext or inappropriate password storage |
| PHP010 | Unsafe Redirects | Redirects using untrusted input |
| PHP011 | SSRF | Network requests with user-controlled URLs |
| PHP012 | Debug Exposure | Production debug/error settings |
| RT001 | Runtime | End-of-life PHP version |
| RT002 | Runtime | PHP version mismatch between config and runtime |
| DEP001 | Dependencies | Known vulnerable Composer package |
| DEP002 | Dependencies | Missing or inconsistent lockfile |
| SEC001 | Secrets | Hardcoded API key |
| SEC002 | Secrets | Private key in source |
| SEC003 | Secrets | Database credential in source |
| SEC004 | Secrets | Access token in source |
| CFG001 | Configuration | Debug mode enabled |
| CFG002 | Configuration | Error display enabled |
| CFG003 | Configuration | Insecure session cookie settings |
| CFG004 | Configuration | Dangerous PHP directive (`allow_url_include`) |
| DOCKER001 | Docker | Unpinned base image tag |
| DOCKER002 | Docker | Running as root |
| DOCKER003 | Docker | Secret file copied into image |
| GHA001 | GitHub Actions | Excessive workflow permissions |
| GHA002 | GitHub Actions | Unpinned third-party action |

---

## 5. Installation

### Requirements

- Python 3.11 or later
- PHP (optional — enables runtime version detection)
- Composer (optional — enables dependency auditing)
- Semgrep (optional — enables enhanced PHP static analysis)

### Install from source

```bash
git clone https://github.com/mhamidlad/php-security-audit-toolkit.git
cd php-security-audit-toolkit
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
pip install -e ".[dev]"
```

### Verify installation

```bash
php-security-audit --version
```

### Optional: Install external tools

**PHP:** https://www.php.net/manual/en/install.php

**Composer:** https://getcomposer.org/download/

**Semgrep:** https://semgrep.dev/docs/getting-started/

If an optional tool is not installed, the toolkit reports the check as
skipped and explains how to install the missing tool.

---

## 6. Quick Start

### Scan a PHP project

```bash
php-security-audit scan ./my-php-project
```

### Generate JSON output

```bash
php-security-audit scan ./my-php-project --format json --output report.json
```

### Generate Markdown report

```bash
php-security-audit scan ./my-php-project --format markdown --output report.md
```

### Generate SARIF for GitHub code scanning

```bash
php-security-audit scan ./my-php-project --format sarif --output report.sarif
```

### Select specific checks

```bash
php-security-audit scan ./my-php-project --checks runtime,composer,secrets,php
```

### Set minimum severity

```bash
php-security-audit scan ./my-php-project --severity high
```

### List available rules

```bash
php-security-audit rules list
```

### Show rule details

```bash
php-security-audit rules show PHP001
```

---

## 7. Example Output

```text
PHP Security Audit Toolkit
=========================

Project: ./examples/vulnerable
Files scanned: 12
Checks completed: 7
Checks skipped: 2 (Semgrep not installed, Composer not installed)

Findings by severity:
  CRITICAL: 1
  HIGH:     3
  MEDIUM:   2
  LOW:      1

CRITICAL  PHP001  SQL Injection
  File: examples/vulnerable/db.php:18
  Untrusted input appears to be concatenated directly into a SQL query.
  Remediation: Use parameterized queries with PDO prepared statements.
  References: https://www.php.net/manual/en/pdo.prepared-statements.php
  Manual verification required: Yes

HIGH  SEC001  Hardcoded API Key
  File: examples/vulnerable/config.php:24
  Value: [REDACTED]
  Remediation: Move the credential to an environment variable or secret manager.
  Manual verification required: Yes

HIGH  PHP002  Command Injection
  File: examples/vulnerable/ping.php:12
  User input is passed to shell_exec() without validation.
  Remediation: Use escapeshellarg() or avoid shell execution entirely.
  Manual verification required: Yes

Scan completed. 7 findings reported.
Exit code: 1 (findings met the failure threshold)
```

This is illustrative output. Actual findings depend on the scanned project.

---

## 8. Report Formats

### Terminal

Readable summary with findings grouped by severity, file locations, and
remediation guidance. Color-coded for quick scanning.

### JSON

Stable schema suitable for CI/CD integration:

```json
{
  "tool": "php-security-audit-toolkit",
  "version": "0.1.0",
  "project_path": "./my-project",
  "scan_time": "2026-10-25T02:30:00Z",
  "summary": {
    "files_scanned": 12,
    "checks_completed": 7,
    "checks_skipped": 2,
    "findings": {
      "critical": 1,
      "high": 3,
      "medium": 2,
      "low": 1,
      "info": 0
    }
  },
  "findings": [
    {
      "rule_id": "PHP001",
      "title": "SQL Injection",
      "severity": "CRITICAL",
      "confidence": "MEDIUM",
      "category": "SQL Injection",
      "file": "db.php",
      "line": 18,
      "description": "Untrusted input concatenated into SQL query",
      "evidence": "[REDACTED]",
      "impact": "Database data exposure or modification",
      "remediation": "Use parameterized queries with PDO prepared statements",
      "references": ["https://www.php.net/manual/en/pdo.prepared-statements.php"],
      "detection_method": "pattern",
      "manual_verification_required": true
    }
  ]
}
```

### Markdown

Human-readable report for developers and security reviewers. Includes
findings, severity, evidence, remediation, and limitations.

### SARIF 2.1.0

Valid SARIF report compatible with GitHub code scanning:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [...]
}
```

Validate the SARIF output using the [SARIF validator](https://github.com/microsoft/sarif-tools).

---

## 9. Severity Definitions

| Severity | Description |
|----------|-------------|
| CRITICAL | Immediate risk of data compromise, code execution, or full system access |
| HIGH | Serious vulnerability likely exploitable with moderate effort |
| MEDIUM | Vulnerability requiring specific conditions or partial impact |
| LOW | Minor issue or defense-in-depth concern |
| INFO | Informational note — not a vulnerability by itself |

A severity level is a prioritization aid, not a risk score. Actual risk
depends on the application context, environment, and threat model.

---

## 10. Configuration

Create a configuration file `php-audit.toml` to customize behavior:

```toml
[scan]
checks = ["php", "secrets", "composer", "runtime", "config", "docker", "workflow"]
severity = "medium"
exclude = ["vendor/", "node_modules/", "storage/", "*.log"]
max_file_size = "1MB"

[suppressions]
[[suppressions.entries]]
rule_id = "PHP007"
file = "src/Legacy/hash.php"
reason = "MD5 used for non-security file checksum, not password storage"

[tools]
semgrep_path = "semgrep"
composer_path = "composer"
php_path = "php"
```

Validate configuration:

```bash
php-security-audit config validate ./php-audit.toml
```

---

## 11. False-Positive Handling

The toolkit distinguishes between:

1. **Confirmed configuration facts** — e.g., debug mode is enabled in a config file.
2. **Known vulnerable dependencies** — e.g., a package version matching an advisory.
3. **Suspicious code patterns** — e.g., SQL string concatenation that may or may not be exploitable.
4. **Findings requiring manual verification** — marked with `manual_verification_required: true`.
5. **Checks that could not run** — e.g., Composer not installed.

Pattern-based rules inherently produce some false positives because they
cannot determine data flow or context without runtime analysis.

### Suppressing known false positives

Add a suppression entry to your configuration file:

```toml
[[suppressions.entries]]
rule_id = "PHP007"
file = "src/Legacy/hash.php"
reason = "MD5 used for non-security file checksum"
```

Suppressed findings are listed in the report as "suppressed" — they are never
silently hidden. Each suppression must include a reason.

---

## 12. Security Limitations

This tool is **not a substitute for**:

- Professional penetration testing
- Manual security code review
- A comprehensive security assessment
- Runtime vulnerability scanning
- Infrastructure or network security testing

### What it does not do

- It does not execute scanned PHP code.
- It does not evaluate PHP configuration files at runtime.
- It does not install or execute project dependencies.
- It does not perform data-flow analysis (in this version).
- It does not detect every vulnerability.
- It does not prove that an application is secure.

### Pattern-based detection

Rules like SQL injection and XSS detection use pattern matching. These
patterns identify suspicious code but cannot determine with certainty whether
the code is exploitable. Findings from these rules are marked as requiring
manual verification.

### Advisory data

PHP runtime advisory data is based on publicly available support and security
information. If advisory data cannot be verified, the check is reported as
inconclusive rather than fabricating a finding.

---

## 13. Privacy Commitments

- **No code is uploaded.** All scanning is local.
- **No credentials are transmitted.** Detected secrets are redacted in all
  output formats.
- **No external API calls** are made during scanning (unless you explicitly
  enable an optional network-based check).
- **No analytics or telemetry** are collected.
- **Symlink following** is restricted to the scan root directory.

---

## 14. Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards,
and pull request guidelines.

---

## 15. Responsible Disclosure

If you discover a security vulnerability in this toolkit, please follow the
process described in [SECURITY.md](SECURITY.md).

Contact: WhatsApp +92 316 7417135

Do not open public GitHub issues for security vulnerabilities.

---

## 16. Roadmap

- [ ] Data-flow analysis for reduced false positives
- [ ] Laravel-specific security rules
- [ ] WordPress-specific security rules
- [ ] Symfony-specific security rules
- [ ] PHPStan integration for enhanced type-aware analysis
- [ ] Incremental scanning for CI integration
- [ ] Baseline comparison between scans
- [ ] HTML report format
- [ ] Pre-commit hook integration

---

## 17. License

MIT License — see [LICENSE](LICENSE).

---

## 18. Contact

**WhatsApp:** +92 316 7417135

**GitHub:** https://github.com/mhamidlad/php-security-audit-toolkit

---

### Need Help Securing Your Application?

This project demonstrates practical approaches to identifying and mitigating
application security risks.

I also work on security reviews and remediation for real-world applications,
including PHP security, API security, dependency risks, and CI/CD pipelines.

If your team needs help with:

- Reviewing PHP or AI-generated code for security vulnerabilities
- Investigating and fixing security findings
- Improving automated security testing
- Hardening GitHub Actions and deployment pipelines
- Assessing the security of AI-powered applications

Contact: **WhatsApp +92 316 7417135**

For consulting inquiries, please include a short description of your
application, technology stack, and security objectives.

Security testing is performed only on systems for which appropriate
authorization has been obtained.

---

*Security First. Evidence Over Assumptions. Fixes Over Findings.*
