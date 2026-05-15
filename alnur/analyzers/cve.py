"""Query the OSV.dev batch API to find CVEs for extracted packages."""
from __future__ import annotations

import time
from typing import List, Optional

import requests

from alnur.core.models import Package, Severity, Vulnerability

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_BATCH_SIZE = 100
_TIMEOUT = 30
_RETRY_DELAY = 2


def scan(packages: List[Package]) -> List[Vulnerability]:
    if not packages:
        return []

    vulnerabilities: List[Vulnerability] = []
    batches = [packages[i : i + _BATCH_SIZE] for i in range(0, len(packages), _BATCH_SIZE)]

    for batch in batches:
        queries = [
            {
                "package": {"name": pkg.name, "ecosystem": pkg.ecosystem},
                "version": pkg.version,
            }
            for pkg in batch
            if pkg.version and pkg.version != "latest"
        ]
        if not queries:
            continue

        results = _query_osv({"queries": queries})
        if results is None:
            continue

        for idx, result in enumerate(results.get("results", [])):
            if idx >= len(batch):
                break
            pkg = batch[idx]
            for vuln in result.get("vulns", []):
                vulnerabilities.append(_parse_vuln(vuln, pkg))

    return vulnerabilities


def _query_osv(payload: dict) -> Optional[dict]:
    for attempt in range(3):
        try:
            resp = requests.post(
                _OSV_BATCH_URL,
                json=payload,
                timeout=_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                time.sleep(_RETRY_DELAY * (attempt + 1))
                continue
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            if attempt < 2:
                time.sleep(_RETRY_DELAY)
                continue
            return None
        except Exception:
            return None
    return None


def _parse_vuln(vuln: dict, pkg: Package) -> Vulnerability:
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = vuln.get("summary", "No summary available")
    details = vuln.get("details", "")
    aliases = vuln.get("aliases", [])
    published = vuln.get("published", "")

    cvss_score = _extract_cvss(vuln)
    severity = _extract_severity(vuln, cvss_score)
    fixed_versions = _extract_fixed_versions(vuln, pkg)

    references = [
        ref.get("url", "")
        for ref in vuln.get("references", [])
        if ref.get("url")
    ]

    return Vulnerability(
        id=vuln_id,
        package=pkg.name,
        version=pkg.version,
        ecosystem=pkg.ecosystem,
        severity=severity,
        summary=summary,
        details=details[:500] if details else "",
        fixed_versions=fixed_versions,
        cvss_score=cvss_score,
        aliases=aliases,
        references=references[:5],
        published=published[:10] if published else "",
        is_dev=pkg.is_dev,
    )


def _extract_cvss(vuln: dict) -> Optional[float]:
    for sev in vuln.get("severity", []):
        sev_type = sev.get("type", "")
        score_str = sev.get("score", "")
        if sev_type in ("CVSS_V3", "CVSS_V2") and score_str:
            # CVSS vectors look like "CVSS:3.1/AV:N/AC:L/..." — extract base score
            if "/" in score_str:
                try:
                    return _compute_cvss_base_score(score_str)
                except Exception:
                    pass
            try:
                return float(score_str)
            except (ValueError, TypeError):
                pass
    # Try database-specific fields
    for db_sev in vuln.get("database_specific", {}).get("severity", []):
        pass
    # Check affected[].ecosystem_specific for CVSS
    for affected in vuln.get("affected", []):
        db_spec = affected.get("database_specific", {})
        cvss = db_spec.get("cvss_v3", db_spec.get("cvss"))
        if cvss:
            try:
                return float(cvss)
            except (ValueError, TypeError):
                pass
    return None


def _extract_severity(vuln: dict, cvss_score: Optional[float]) -> Severity:
    if cvss_score is not None:
        return Severity.from_cvss(cvss_score)

    # Check OSV severity field
    for sev in vuln.get("severity", []):
        rating = sev.get("score", "").upper()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if level in rating:
                return Severity(level)

    # Check database_specific
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if isinstance(db_sev, str):
        db_sev = db_sev.upper()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if level in db_sev:
                return Severity(level)

    return Severity.MEDIUM


def _extract_fixed_versions(vuln: dict, pkg: Package) -> List[str]:
    fixed: List[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed_ver = event.get("fixed")
                if fixed_ver:
                    fixed.append(fixed_ver)
    return list(dict.fromkeys(fixed))


def _compute_cvss_base_score(vector: str) -> float:
    """Approximate CVSS 3.x base score from vector string."""
    if not vector.startswith("CVSS:3"):
        raise ValueError("Not a CVSS 3.x vector")
    parts = dict(item.split(":") for item in vector.split("/")[1:])

    av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_scores = {"L": 0.77, "H": 0.44}
    pr_u_scores = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c_scores = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_scores = {"N": 0.85, "R": 0.62}

    scope_changed = parts.get("S") == "C"
    pr_scores = pr_c_scores if scope_changed else pr_u_scores

    av = av_scores.get(parts.get("AV", "N"), 0.85)
    ac = ac_scores.get(parts.get("AC", "L"), 0.77)
    pr = pr_scores.get(parts.get("PR", "N"), 0.85)
    ui = ui_scores.get(parts.get("UI", "N"), 0.85)

    exploitability = 8.22 * av * ac * pr * ui

    c_score_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    c = c_score_map.get(parts.get("C", "N"), 0.0)
    i = c_score_map.get(parts.get("I", "N"), 0.0)
    a = c_score_map.get(parts.get("A", "N"), 0.0)

    if scope_changed:
        iscbase = 7.52 * (c + i + a) - 3.25 * ((c + i + a - 0.02) ** 15)
        impact = 7.52 * (iscbase / 7.52) if iscbase > 0 else 0
    else:
        iscbase = 1 - (1 - c) * (1 - i) * (1 - a)
        impact = 6.42 * iscbase

    if impact == 0:
        return 0.0

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10)
    else:
        base = min(impact + exploitability, 10)

    return round(base, 1)
