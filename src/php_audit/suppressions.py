"""Finding suppression logic."""

from __future__ import annotations

from .config import ScanConfig
from .models import Finding


def apply_suppressions(findings: list[Finding], config: ScanConfig) -> list[Finding]:
    """Apply suppression rules to findings.

    Suppressed findings are marked but not removed. They appear in reports
    as "suppressed" with the configured reason.
    """
    for finding in findings:
        suppressed, reason = config.is_suppressed(finding.rule_id, finding.file)
        if suppressed:
            finding.suppressed = True
            finding.suppression_reason = reason
    return findings
