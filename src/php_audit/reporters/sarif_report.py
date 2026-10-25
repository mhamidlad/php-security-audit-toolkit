"""SARIF 2.1.0 reporter — compatible with GitHub code scanning."""

from __future__ import annotations

import json

from ..models import ScanResult, Severity

SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def render_sarif(result: ScanResult) -> str:
    """Render a scan result as SARIF 2.1.0 JSON."""
    # Build rules
    rules: list[dict] = []
    rule_index: dict[str, int] = {}

    for f in result.findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": f.references[0] if f.references else "",
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")
                },
                "properties": {
                    "category": f.category,
                    "confidence": f.confidence.value,
                    "manual_verification_required": f.manual_verification_required,
                },
            })

    # Build results
    results: list[dict] = []
    for f in result.findings:
        if f.suppressed:
            # Suppressed findings are reported with level "none"
            level = "none"
        else:
            level = SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")

        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f.file,
                },
            },
        }
        if f.line > 0:
            location["physicalLocation"]["region"] = {
                "startLine": f.line,
            }

        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": level,
            "message": {"text": f.description},
            "locations": [location],
            "partialFingerprints": {
                "primaryLocationLineHash": f"{f.file}:{f.line}:{f.rule_id}",
            },
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "impact": f.impact,
                "remediation": f.remediation,
                "detection_method": f.detection_method,
                "manual_verification_required": f.manual_verification_required,
                "suppressed": f.suppressed,
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "php-security-audit-toolkit",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/mhamidlad/php-security-audit-toolkit",
                        "rules": rules,
                    },
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
