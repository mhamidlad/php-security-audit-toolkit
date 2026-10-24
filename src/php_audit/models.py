"""Finding and reporting models for the PHP Security Audit Toolkit."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    """Severity levels for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Create a Severity from a string (case-insensitive)."""
        return cls(value.upper())

    @classmethod
    def meets_threshold(cls, finding_severity: Severity, threshold: Severity) -> bool:
        """Check whether a finding severity meets or exceeds a threshold."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(finding_severity) >= order.index(threshold)


class Confidence(str, enum.Enum):
    """Confidence levels for findings."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class CheckStatus(str, enum.Enum):
    """Status of a completed or skipped check."""

    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class Finding:
    """A single security finding produced by a detection rule."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    file: str
    line: int
    description: str
    evidence: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    detection_method: str = "pattern"
    manual_verification_required: bool = True
    suppressed: bool = False
    suppression_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for JSON/SARIF reporting."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "detection_method": self.detection_method,
            "manual_verification_required": self.manual_verification_required,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }


@dataclass
class CheckResult:
    """The result of running a check category during a scan."""

    name: str
    status: CheckStatus
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    files_scanned: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "files_scanned": self.files_scanned,
            "findings_count": len(self.findings),
        }


@dataclass
class ScanResult:
    """The complete result of a scan."""

    project_path: str
    scan_time: str
    files_scanned: int = 0
    checks: list[CheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped_checks: list[str] = field(default_factory=list)

    @property
    def checks_completed(self) -> int:
        """Number of checks that completed successfully."""
        return sum(1 for c in self.checks if c.status == CheckStatus.COMPLETED)

    @property
    def checks_skipped(self) -> int:
        """Number of checks that were skipped."""
        return sum(1 for c in self.checks if c.status in (CheckStatus.SKIPPED, CheckStatus.INCONCLUSIVE))

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Count of non-suppressed findings grouped by severity."""
        counts: dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        for f in self.findings:
            if not f.suppressed:
                counts[f.severity.value] += 1
        return counts

    @property
    def total_findings(self) -> int:
        """Total non-suppressed findings."""
        return sum(1 for f in self.findings if not f.suppressed)

    def all_findings(self) -> list[Finding]:
        """Return all findings including suppressed ones."""
        return self.findings

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary for JSON reporting."""
        return {
            "tool": "php-security-audit-toolkit",
            "version": "0.1.0",
            "project_path": self.project_path,
            "scan_time": self.scan_time,
            "summary": {
                "files_scanned": self.files_scanned,
                "checks_completed": self.checks_completed,
                "checks_skipped": self.checks_skipped,
                "findings": self.findings_by_severity,
                "total_findings": self.total_findings,
            },
            "checks": [c.to_dict() for c in self.checks],
            "findings": [f.to_dict() for f in self.findings],
        }
