"""JSON report serializer."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from alnur.core.models import ScanResult


def render(result: ScanResult) -> str:
    return json.dumps(_to_dict(result), indent=2, default=str)


def write(result: ScanResult, output_path: Path) -> None:
    output_path.write_text(render(result), encoding="utf-8")


def _to_dict(result: ScanResult) -> Dict[str, Any]:
    return {
        "alnur_version": "1.0.0",
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "target_path": result.target_path,
        "project_types": [pt.value for pt in result.project_types],
        "scan_duration_seconds": round(result.scan_duration, 3),
        "risk_summary": {
            "score": result.risk_score,
            "grade": result.risk_grade,
            "total_issues": result.total_issues,
            "vulnerabilities": {
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "total": len(result.vulnerabilities),
            },
            "secrets": len(result.secrets),
            "architecture_issues": len(result.architecture_findings),
            "standards_pass_rate": result.standards_pass_rate,
            "port_risks": len(result.port_findings),
        },
        "vulnerabilities": [
            {
                "id": v.id,
                "aliases": v.aliases,
                "package": v.package,
                "version": v.version,
                "ecosystem": v.ecosystem,
                "severity": v.severity.value,
                "cvss_score": v.cvss_score,
                "summary": v.summary,
                "details": v.details,
                "fixed_versions": v.fixed_versions,
                "published": v.published,
                "references": v.references,
                "is_dev_dependency": v.is_dev,
            }
            for v in sorted(result.vulnerabilities, key=lambda x: x.severity.weight, reverse=True)
        ],
        "secrets": [
            {
                "file": s.file_path,
                "line": s.line_number,
                "type": s.secret_type,
                "severity": s.severity.value,
                "description": s.description,
                "preview": s.match_preview,
            }
            for s in sorted(result.secrets, key=lambda x: x.severity.weight, reverse=True)
        ],
        "architecture_findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category,
                "severity": f.severity.value,
                "description": f.description,
                "file": f.file_path,
                "line": f.line_number,
                "recommendation": f.recommendation,
                "cwe": f.cwe,
            }
            for f in sorted(result.architecture_findings, key=lambda x: x.severity.weight, reverse=True)
        ],
        "standards_findings": [
            {
                "check_id": f.check_id,
                "check_name": f.check_name,
                "passed": f.passed,
                "severity": f.severity.value,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in result.standards_findings
        ],
        "port_findings": [
            {
                "source_file": f.source_file,
                "port": f.port,
                "service": f.service,
                "protocol": f.protocol,
                "risk": f.risk.value,
                "description": f.description,
                "recommendation": f.recommendation,
                "binding": f.binding,
            }
            for f in sorted(result.port_findings, key=lambda x: x.risk.weight, reverse=True)
        ],
        "llm_insight": (
            {
                "provider": result.llm_insight.provider,
                "model": result.llm_insight.model,
                "executive_summary": result.llm_insight.executive_summary,
                "priority_actions": result.llm_insight.priority_actions,
                "false_positive_notes": result.llm_insight.false_positive_notes,
            }
            if result.llm_insight else None
        ),
        "errors": result.errors,
        "packages_scanned": len(result.packages),
    }
