# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added
- CLI interface with `scan`, `rules list`, `rules show`, and `config validate` commands.
- PHP static analysis rules: SQL injection, command injection, XSS, unsafe
  deserialization, file inclusion, path traversal, weak cryptography, insecure
  randomness, weak password hashing, unsafe redirects, SSRF, and debug exposure.
- PHP runtime auditor: version detection, end-of-life checks, advisory data.
- Composer dependency auditor: lockfile analysis, vulnerable dependency detection.
- Secret detection: API keys, private keys, database credentials, access tokens.
- Configuration auditor: debug mode, error display, session cookie settings,
  dangerous PHP directives.
- Docker auditor: unpinned base images, running as root, secret file copying.
- GitHub Actions auditor: excessive permissions, unpinned third-party actions.
- Report formats: terminal, JSON, Markdown, SARIF 2.1.0.
- Finding suppression via configuration file.
- Secret redaction in all report formats.
- Comprehensive pytest test suite with positive and negative test cases.
- GitHub Actions CI workflow.
- Documentation: installation, usage, security rules, remediation, privacy,
  limitations, false-positive handling.
