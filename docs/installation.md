# Installation

## Requirements

- **Python 3.11 or later**
- PHP (optional — enables runtime version detection)
- Composer (optional — enables dependency auditing)
- Semgrep (optional — enables enhanced PHP static analysis)

## Install from source

```bash
git clone https://github.com/mhamidlad/php-security-audit-toolkit.git
cd php-security-audit-toolkit
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
pip install -e ".[dev]"
```

## Verify installation

```bash
php-security-audit --version
```

## Optional: Install external tools

### PHP
https://www.php.net/manual/en/install.php

### Composer
https://getcomposer.org/download/

### Semgrep
https://semgrep.dev/docs/getting-started/

If an optional tool is not installed, the toolkit reports the check as skipped
and explains how to install the missing tool. The core scanner works without
any external tools.
