"""JSON reporter — stable schema for CI integration."""

from __future__ import annotations

import json
import re

from ..models import ScanResult


def _redact_evidence(text: str) -> str:
    """Redact potential secrets in evidence strings."""
    # Redact API keys, passwords, tokens
    text = re.sub(
        r"(sk-|ghp_|gho_|github_pat_|AKIA|xox[baprs]-)[A-Za-z0-9]{10,}",
        "[REDACTED]",
        text,
    )
    text = re.sub(
        r"(password|secret|token|api_key)\s*[=:]\s*['\"][^'\"]+['\"]",
        r"\1 = '[REDACTED]'",
        text,
        flags=re.IGNORECASE,
    )
    return text


def render_json(result: ScanResult, indent: int = 2) -> str:
    """Render a scan result as a JSON string."""
    data = result.to_dict()
    # Redact evidence in all findings
    for finding in data.get("findings", []):
        finding["evidence"] = _redact_evidence(finding.get("evidence", ""))
    return json.dumps(data, indent=indent, ensure_ascii=False)
