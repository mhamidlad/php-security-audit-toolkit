# Contributing

Thank you for your interest in contributing to the PHP Security Audit Toolkit.

## Getting Started

1. Fork the repository.
2. Clone your fork locally.
3. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .venv\Scripts\activate     # Windows
   ```
4. Install in development mode:
   ```bash
   pip install -e ".[dev]"
   ```
5. Create a feature branch:
   ```bash
   git checkout -b your-feature-name
   ```

## Development Standards

### Code Quality

- Run `ruff check .` before submitting. Fix all reported issues.
- Run `pytest` before submitting. All tests must pass.
- Follow the existing code style and structure.

### Security Rules

When adding a new detection rule:

1. Assign a stable rule identifier (e.g., `PHP015`).
2. Implement at least one positive test and one negative test.
3. Document the rule in `docs/security-rules.md`.
4. Provide remediation guidance.
5. Mark findings that require manual verification as such.

### Tests

- Use synthetic data only. Never use real credentials.
- Use `pytest` temporary directories for isolation.
- Every rule must have positive and negative test cases.

## Pull Request Process

1. Ensure tests pass: `pytest`
2. Ensure linting passes: `ruff check .`
3. Write a clear commit message describing what changed and why.
4. Reference any relevant issue numbers.
5. Do not force-push or rewrite history after review begins.

## Code of Conduct

Be respectful and professional. Harassment or abuse will not be tolerated.
