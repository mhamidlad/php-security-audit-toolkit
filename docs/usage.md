# Usage

## Scan a PHP project

```bash
php-security-audit scan ./my-php-project
```

## Output formats

### JSON (for CI integration)
```bash
php-security-audit scan ./my-php-project --format json --output report.json
```

### Markdown (for code review)
```bash
php-security-audit scan ./my-php-project --format markdown --output report.md
```

### SARIF (for GitHub code scanning)
```bash
php-security-audit scan ./my-php-project --format sarif --output report.sarif
```

## Select specific checks

```bash
php-security-audit scan ./my-php-project --checks php,secrets,composer
```

Available checks: `php`, `secrets`, `composer`, `runtime`, `config`, `docker`, `workflow`

## Set minimum severity

```bash
php-security-audit scan ./my-php-project --severity high
```

Severity levels: `info`, `low`, `medium`, `high`, `critical`

## List rules

```bash
php-security-audit rules list
```

## Show rule details

```bash
php-security-audit rules show --id PHP001
```

## Validate configuration

```bash
php-security-audit config validate ./php-audit.toml
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed with no findings meeting the threshold |
| 1 | Scan completed with findings meeting the threshold |
| 2 | Invalid arguments, configuration error, or operational error |

A exit code of 0 does **not** mean the application is secure.
