"""Configuration management for the PHP Security Audit Toolkit."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    checks: list[str] = field(
        default_factory=lambda: ["php", "secrets", "composer", "runtime", "config", "docker", "workflow"]
    )
    severity_threshold: str = "low"
    exclude: list[str] = field(
        default_factory=lambda: [
            "vendor/",
            "node_modules/",
            ".git/",
            "storage/",
            "*.log",
            "*.cache",
        ]
    )
    max_file_size: int = 1_048_576  # 1 MB
    follow_symlinks: bool = False
    tools: dict[str, str] = field(default_factory=dict)
    suppressions: list[dict[str, str]] = field(default_factory=list)

    def is_excluded(self, path: str) -> bool:
        """Check whether a path matches an exclusion pattern."""
        normalized = path.replace("\\", "/")
        for pattern in self.exclude:
            if pattern.endswith("/"):
                if pattern.rstrip("/") in normalized.split("/"):
                    return True
            elif pattern.startswith("*."):
                ext = pattern[1:]
                if normalized.endswith(ext):
                    return True
            else:
                if pattern in normalized:
                    return True
        return False

    def is_suppressed(self, rule_id: str, file_path: str) -> tuple[bool, str | None]:
        """Check whether a finding should be suppressed.

        Returns (suppressed, reason).
        """
        normalized_file = file_path.replace("\\", "/")
        for entry in self.suppressions:
            if entry.get("rule_id") != rule_id:
                continue
            entry_file = entry.get("file", "").replace("\\", "/")
            # Match exact or suffix
            if entry_file == normalized_file or normalized_file.endswith(entry_file):
                reason = entry.get("reason", "No reason provided")
                return True, reason
        return False, None

    def should_include_finding(self, severity: str) -> bool:
        """Check whether a finding meets the severity threshold."""
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold_idx = order.index(self.severity_threshold.upper()) if self.severity_threshold.upper() in order else 1
        finding_idx = order.index(severity.upper()) if severity.upper() in order else 0
        return finding_idx >= threshold_idx


def load_config(config_path: str | None = None) -> ScanConfig:
    """Load configuration from a TOML file or return defaults.

    Uses Python's built-in tomllib (3.11+) for parsing.
    """
    config = ScanConfig()

    if config_path is None:
        return config

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            # No TOML parser available — return defaults
            return config

    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Parse [scan] section
    scan = data.get("scan", {})
    if "checks" in scan:
        config.checks = scan["checks"]
    if "severity" in scan:
        config.severity_threshold = scan["severity"]
    if "exclude" in scan:
        config.exclude = scan["exclude"]
    if "max_file_size" in scan:
        size_str = str(scan["max_file_size"])
        config.max_file_size = parse_size(size_str)
    if "follow_symlinks" in scan:
        config.follow_symlinks = scan["follow_symlinks"]

    # Parse [tools] section
    tools = data.get("tools", {})
    config.tools = tools

    # Parse [suppressions] section
    supps = data.get("suppressions", {})
    config.suppressions = supps.get("entries", [])

    return config


def parse_size(size_str: str) -> int:
    """Parse a human-readable size string into bytes."""
    size_str = size_str.strip().upper()
    match = re.match(r"^(\d+(?:\.\d+)?)\s*(KB|MB|GB|B)?$", size_str)
    if not match:
        return 1_048_576  # Default 1MB
    value = float(match.group(1))
    unit = match.group(2) or "B"
    multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
    return int(value * multipliers[unit])


def validate_config(config_path: str) -> tuple[bool, list[str]]:
    """Validate a configuration file. Returns (valid, errors)."""
    errors: list[str] = []

    path = Path(config_path)
    if not path.exists():
        return False, [f"File not found: {config_path}"]

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            errors.append("No TOML parser available (requires Python 3.11+)")
            return False, errors

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        errors.append(f"Failed to parse TOML: {e}")
        return False, errors

    # Validate [scan] section
    scan = data.get("scan", {})
    valid_checks = {"php", "secrets", "composer", "runtime", "config", "docker", "workflow"}
    if "checks" in scan:
        checks = scan["checks"]
        if not isinstance(checks, list):
            errors.append("scan.checks must be a list")
        else:
            for c in checks:
                if c not in valid_checks:
                    errors.append(f"Unknown check: '{c}'. Valid: {', '.join(sorted(valid_checks))}")

    if "severity" in scan:
        sev = str(scan["severity"]).upper()
        valid_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if sev not in valid_severities:
            errors.append(f"Invalid severity: '{sev}'. Valid: {', '.join(sorted(valid_severities))}")

    # Validate [suppressions] section
    supps = data.get("suppressions", {})
    entries = supps.get("entries", [])
    for i, entry in enumerate(entries):
        if "rule_id" not in entry:
            errors.append(f"suppressions.entries[{i}] missing 'rule_id'")
        if "file" not in entry:
            errors.append(f"suppressions.entries[{i}] missing 'file'")
        if "reason" not in entry:
            errors.append(f"suppressions.entries[{i}] missing 'reason'")

    return len(errors) == 0, errors
