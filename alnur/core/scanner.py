"""Main scan orchestrator — coordinates all detectors and analyzers."""
from __future__ import annotations

import time
from pathlib import Path

from alnur.analyzers import agentic, architecture, cve, llm_enhancer, ports, secrets, standards
from alnur.core.models import ScanConfig, ScanResult, Severity
from alnur.detectors import dependency, project_type


def run(path: Path, config: ScanConfig) -> ScanResult:
    start = time.monotonic()
    result = ScanResult(target_path=str(path.resolve()))

    # ── 1. Detect project type(s) ─────────────────────────────────────────
    result.project_types = project_type.detect(path)

    # ── 2. Extract dependencies ───────────────────────────────────────────
    result.packages = dependency.extract(path, include_dev=config.include_dev_deps)

    # ── 3. CVE scan ───────────────────────────────────────────────────────
    if not config.skip_cve and result.packages:
        try:
            vulns = cve.scan(result.packages)
            result.vulnerabilities = [
                v for v in vulns if v.severity >= config.min_severity
            ]
        except Exception as exc:
            result.errors.append(f"CVE scan error: {exc}")

    # ── 4. Secrets detection ──────────────────────────────────────────────
    if not config.skip_secrets:
        try:
            found = secrets.scan(path, config.max_file_size_bytes)
            result.secrets = [s for s in found if s.severity >= config.min_severity]
        except Exception as exc:
            result.errors.append(f"Secrets scan error: {exc}")

    # ── 5. Architecture analysis ──────────────────────────────────────────
    if not config.skip_architecture:
        try:
            arch = architecture.scan(path, config.max_file_size_bytes)
            result.architecture_findings = [
                f for f in arch if f.severity >= config.min_severity
            ]
        except Exception as exc:
            result.errors.append(f"Architecture scan error: {exc}")

    # ── 6. Agentic AI security analysis ──────────────────────────────────
    if not config.skip_agentic:
        try:
            agent_findings = agentic.scan(path, config.max_file_size_bytes)
            result.architecture_findings += [
                f for f in agent_findings if f.severity >= config.min_severity
            ]
        except Exception as exc:
            result.errors.append(f"Agentic scan error: {exc}")

    # ── 7. Standards compliance ───────────────────────────────────────────
    if not config.skip_standards:
        try:
            result.standards_findings = standards.scan(path, result.project_types)
        except Exception as exc:
            result.errors.append(f"Standards scan error: {exc}")

    # ── 8. Port risk analysis ─────────────────────────────────────────────
    if not config.skip_ports:
        try:
            port_findings = ports.scan(path)
            result.port_findings = [
                f for f in port_findings if f.risk >= config.min_severity
            ]
        except Exception as exc:
            result.errors.append(f"Ports scan error: {exc}")

    # ── 9. LLM-enhanced analysis (optional, requires env key) ────────────────
    if not config.skip_llm:
        result.llm_insight = llm_enhancer.analyze(result)

    result.scan_duration = time.monotonic() - start
    return result
