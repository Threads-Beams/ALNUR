"""Self-contained HTML security report generator."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List

from alnur.core.models import (
    ArchitectureFinding,
    PortFinding,
    ScanResult,
    SecretFinding,
    Severity,
    StandardsFinding,
    Vulnerability,
)

_SEV_CSS = {
    Severity.CRITICAL: "#ff4d4f",
    Severity.HIGH: "#fa8c16",
    Severity.MEDIUM: "#fadb14",
    Severity.LOW: "#52c41a",
    Severity.INFO: "#8c8c8c",
}

_SEV_BG = {
    Severity.CRITICAL: "#2a1215",
    Severity.HIGH: "#2b1d11",
    Severity.MEDIUM: "#2b2111",
    Severity.LOW: "#162312",
    Severity.INFO: "#1f1f1f",
}

_GRADE_COLOR = {"A": "#52c41a", "B": "#73d13d", "C": "#fadb14", "D": "#fa8c16", "F": "#ff4d4f"}


def render(result: ScanResult) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    grade = result.risk_grade
    grade_color = _GRADE_COLOR.get(grade, "#fff")

    vuln_rows = _vuln_rows(result.vulnerabilities)
    secret_rows = _secret_rows(result.secrets)
    arch_rows = _arch_rows(result.architecture_findings)
    std_rows = _std_rows(result.standards_findings)
    port_rows = _port_rows(result.port_findings)

    project_types = ", ".join(pt.value for pt in result.project_types)
    pass_rate = result.standards_pass_rate

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ALNUR Security Report — {result.target_path}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --text-muted: #8b949e;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --yellow: #d29922; --orange: #db6d28;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    --mono: 'SF Mono', 'Fira Code', Consolas, monospace;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}

  /* Header */
  .header {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 32px; margin-bottom: 24px; text-align: center; }}
  .header h1 {{ font-size: 2.5rem; font-weight: 700; letter-spacing: 0.15em; color: var(--accent); font-family: var(--mono); }}
  .header .subtitle {{ color: var(--text-muted); margin-top: 4px; font-size: 0.9rem; }}
  .header .meta {{ margin-top: 16px; color: var(--text-muted); font-size: 0.85rem; }}

  /* Summary cards */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
  .card .card-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 8px; }}
  .card .card-value {{ font-size: 2rem; font-weight: 700; font-family: var(--mono); }}
  .card .card-sub {{ font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; }}
  .card.critical {{ border-color: #ff4d4f44; background: #2a121588; }}
  .card.high {{ border-color: #fa8c1644; background: #2b1d1188; }}
  .card.grade {{ border-color: #58a6ff44; }}

  /* Grade */
  .grade-circle {{ display: inline-block; width: 64px; height: 64px; line-height: 64px; border-radius: 50%; font-size: 2rem; font-weight: 900; border: 3px solid; }}

  /* Sections */
  .section {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; overflow: hidden; }}
  .section-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; cursor: pointer; user-select: none; }}
  .section-header h2 {{ font-size: 1rem; font-weight: 600; }}
  .section-header .badge {{ font-size: 0.75rem; padding: 2px 8px; border-radius: 12px; font-weight: 600; }}
  .section-body {{ padding: 0; overflow-x: auto; }}
  .section-body.collapsed {{ display: none; }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  thead th {{ padding: 10px 16px; text-align: left; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); border-bottom: 1px solid var(--border); background: var(--bg3); }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background 0.1s; }}
  tbody tr:hover {{ background: var(--bg3); }}
  tbody tr:last-child {{ border-bottom: none; }}
  td {{ padding: 10px 16px; vertical-align: top; }}
  .mono {{ font-family: var(--mono); font-size: 0.8rem; }}
  .text-muted {{ color: var(--text-muted); }}
  .text-sm {{ font-size: 0.8rem; }}
  .rec {{ color: var(--text-muted); font-size: 0.8rem; margin-top: 4px; padding: 6px 10px; background: var(--bg3); border-left: 3px solid var(--border); border-radius: 0 4px 4px 0; }}

  /* Severity badges */
  .sev {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; }}
  .sev-CRITICAL {{ background: #2a1215; color: #ff4d4f; border: 1px solid #ff4d4f44; }}
  .sev-HIGH {{ background: #2b1d11; color: #fa8c16; border: 1px solid #fa8c1644; }}
  .sev-MEDIUM {{ background: #2b2111; color: #fadb14; border: 1px solid #fadb1444; }}
  .sev-LOW {{ background: #162312; color: #52c41a; border: 1px solid #52c41a44; }}
  .sev-INFO {{ background: #1f1f1f; color: #8c8c8c; border: 1px solid #8c8c8c44; }}

  /* Standards check */
  .check-pass {{ color: var(--green); }}
  .check-fail {{ color: var(--red); }}

  /* Pass rate bar */
  .progress-bar {{ background: var(--bg3); border-radius: 4px; height: 8px; overflow: hidden; margin: 4px 0; }}
  .progress-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}

  /* Footer */
  .footer {{ text-align: center; padding: 24px; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 24px; }}
  .success-panel {{ padding: 24px; text-align: center; color: var(--green); font-size: 1rem; }}

  @media print {{
    body {{ background: white; color: black; }}
    .section-body.collapsed {{ display: block !important; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <h1>ALNUR</h1>
    <div class="subtitle">Open-Source End-to-End Vulnerability Scanner</div>
    <div class="meta">
      <strong>Target:</strong> {_esc(result.target_path)} &nbsp;·&nbsp;
      <strong>Type:</strong> {_esc(project_types)} &nbsp;·&nbsp;
      <strong>Scanned:</strong> {now} &nbsp;·&nbsp;
      <strong>Duration:</strong> {result.scan_duration:.2f}s
    </div>
  </div>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card {'critical' if result.critical_count > 0 else ''}">
      <div class="card-label">Critical CVEs</div>
      <div class="card-value" style="color: #ff4d4f">{result.critical_count}</div>
      <div class="card-sub">of {len(result.vulnerabilities)} total vulns</div>
    </div>
    <div class="card {'high' if result.high_count > 0 else ''}">
      <div class="card-label">High CVEs</div>
      <div class="card-value" style="color: #fa8c16">{result.high_count}</div>
      <div class="card-sub">{result.medium_count} medium, {result.low_count} low</div>
    </div>
    <div class="card">
      <div class="card-label">Secret Leaks</div>
      <div class="card-value" style="color: {'#ff4d4f' if result.secrets else '#3fb950'}">{len(result.secrets)}</div>
      <div class="card-sub">hardcoded credentials</div>
    </div>
    <div class="card">
      <div class="card-label">Arch Issues</div>
      <div class="card-value" style="color: {'#fa8c16' if result.architecture_findings else '#3fb950'}">{len(result.architecture_findings)}</div>
      <div class="card-sub">security code patterns</div>
    </div>
    <div class="card">
      <div class="card-label">Standards</div>
      <div class="card-value" style="color: {'#3fb950' if pass_rate >= 80 else '#d29922' if pass_rate >= 60 else '#f85149'}">{pass_rate:.0f}%</div>
      <div class="card-sub">compliance rate</div>
    </div>
    <div class="card grade">
      <div class="card-label">Risk Score</div>
      <div class="card-value" style="color: {grade_color}">{result.risk_score}</div>
      <div class="card-sub">Grade: <span style="color:{grade_color};font-weight:700">{grade}</span></div>
    </div>
  </div>

  <!-- CVE Vulnerabilities -->
  {_section("CVE Vulnerabilities", vuln_rows, len(result.vulnerabilities), Severity.CRITICAL if result.critical_count else (Severity.HIGH if result.high_count else None), "vuln-section")}

  <!-- Secrets -->
  {_section("Secret Leaks", secret_rows, len(result.secrets), Severity.CRITICAL if result.secrets else None, "secret-section")}

  <!-- Architecture -->
  {_section("Architecture Issues", arch_rows, len(result.architecture_findings), None, "arch-section")}

  <!-- Standards -->
  {_std_section(result)}

  <!-- Ports -->
  {_section("Port Risk Analysis", port_rows, len(result.port_findings), None, "port-section")}

  <div class="footer">
    <strong>ALNUR</strong> — Open-Source Security Scanner v1.0.1<br>
    Report generated {now} · Risk Score: {result.risk_score}/1000 · Grade: {grade}<br>
    <em>This report is for informational purposes. Always verify findings before remediation.</em>
  </div>

</div>
<script>
  document.querySelectorAll('.section-header').forEach(h => {{
    h.addEventListener('click', () => {{
      const body = h.nextElementSibling;
      body.classList.toggle('collapsed');
      const arrow = h.querySelector('.arrow');
      if (arrow) arrow.textContent = body.classList.contains('collapsed') ? '▶' : '▼';
    }});
  }});
</script>
</body>
</html>"""


def _section(title: str, rows: str, count: int, top_sev: object, section_id: str) -> str:
    badge_color = "#ff4d4f" if count > 0 else "#3fb950"
    badge_bg = "#2a1215" if count > 0 else "#162312"
    badge = f'<span class="badge" style="background:{badge_bg};color:{badge_color}">{count}</span>'
    empty_msg = '<div class="success-panel">✓ None found</div>'
    return f"""
  <div class="section" id="{section_id}">
    <div class="section-header">
      <h2>{_esc(title)} {badge}</h2>
      <span class="arrow">▼</span>
    </div>
    <div class="section-body">
      {rows if rows else empty_msg}
    </div>
  </div>"""


def _vuln_rows(vulns: List[Vulnerability]) -> str:
    if not vulns:
        return ""
    rows = ""
    for v in sorted(vulns, key=lambda x: x.severity.weight, reverse=True):
        fixed = v.fixed_versions[0] if v.fixed_versions else "<span class='text-muted'>No fix</span>"
        cvss = f" ({v.cvss_score:.1f})" if v.cvss_score else ""
        aliases = " ".join(f"<code class='mono'>{a}</code>" for a in v.aliases[:2])
        ref = f'<a href="{_esc(v.references[0])}" target="_blank">↗</a>' if v.references else ""
        rows += f"""<tr>
      <td><span class="sev sev-{v.severity.value}">{v.severity.value}</span></td>
      <td class="mono">{_esc(v.id)}{cvss} {ref}</td>
      <td class="mono">{_esc(v.package)}</td>
      <td class="mono">{_esc(v.version)}</td>
      <td class="mono" style="color:#3fb950">{_esc(str(fixed)) if isinstance(fixed, str) else fixed}</td>
      <td>{_esc(v.summary[:100])}{f'<div class="text-muted text-sm">{_esc(v.details[:150])}</div>' if v.details else ''}</td>
    </tr>"""
    return f"""<table>
    <thead><tr>
      <th>Severity</th><th>CVE ID</th><th>Package</th><th>Version</th><th>Fixed In</th><th>Summary</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>"""


def _secret_rows(findings: List[SecretFinding]) -> str:
    if not findings:
        return ""
    rows = ""
    for f in sorted(findings, key=lambda x: x.severity.weight, reverse=True):
        rows += f"""<tr>
      <td><span class="sev sev-{f.severity.value}">{f.severity.value}</span></td>
      <td>{_esc(f.secret_type)}</td>
      <td class="mono">{_esc(f.file_path)}</td>
      <td class="mono" style="text-align:right">{f.line_number}</td>
      <td class="mono text-muted">{_esc(f.match_preview)}</td>
      <td>{_esc(f.description)}</td>
    </tr>"""
    return f"""<table>
    <thead><tr>
      <th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>Preview</th><th>Description</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>"""


def _arch_rows(findings: List[ArchitectureFinding]) -> str:
    if not findings:
        return ""
    rows = ""
    for f in sorted(findings, key=lambda x: x.severity.weight, reverse=True):
        cwe = f"<span class='mono text-muted'>{_esc(f.cwe)}</span>" if f.cwe else ""
        file_line = f"{_esc(f.file_path or '')}:{f.line_number}" if f.file_path else "<span class='text-muted'>—</span>"
        rec = f'<div class="rec">→ {_esc(f.recommendation)}</div>' if f.recommendation else ""
        rows += f"""<tr>
      <td><span class="sev sev-{f.severity.value}">{f.severity.value}</span></td>
      <td class="mono">{_esc(f.rule_id)} {cwe}</td>
      <td>{_esc(f.category)}</td>
      <td class="mono">{file_line}</td>
      <td>{_esc(f.description)}{rec}</td>
    </tr>"""
    return f"""<table>
    <thead><tr>
      <th>Severity</th><th>Rule</th><th>Category</th><th>Location</th><th>Finding</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>"""


def _std_rows(findings: List[StandardsFinding]) -> str:
    if not findings:
        return ""
    rows = ""
    for f in sorted(findings, key=lambda x: (x.passed, -x.severity.weight)):
        icon = "✓" if f.passed else "✗"
        icon_cls = "check-pass" if f.passed else "check-fail"
        sev = "" if f.passed else f"<span class='sev sev-{f.severity.value}'>{f.severity.value}</span>"
        rec = f'<div class="rec">→ {_esc(f.recommendation)}</div>' if f.recommendation and not f.passed else ""
        rows += f"""<tr>
      <td class="{icon_cls}" style="font-size:1.1rem;font-weight:700">{icon}</td>
      <td>{_esc(f.check_name)}</td>
      <td>{sev}</td>
      <td>{_esc(f.description)}{rec}</td>
    </tr>"""
    return f"""<table>
    <thead><tr><th>Status</th><th>Check</th><th>Severity</th><th>Details</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>"""


def _std_section(result: ScanResult) -> str:
    passed = sum(1 for f in result.standards_findings if f.passed)
    total = len(result.standards_findings)
    pass_rate = result.standards_pass_rate
    color = "#3fb950" if pass_rate >= 80 else "#d29922" if pass_rate >= 60 else "#f85149"
    badge = f'<span class="badge" style="background:#161b22;color:{color}">{passed}/{total} passed</span>'
    bar = f'<div class="progress-bar" style="width:200px;display:inline-block;vertical-align:middle;margin-left:8px"><div class="progress-fill" style="width:{pass_rate:.0f}%;background:{color}"></div></div>'
    rows = _std_rows(result.standards_findings)
    empty_msg = '<div class="success-panel">✓ All checks passed</div>'

    return f"""
  <div class="section" id="std-section">
    <div class="section-header">
      <h2>Standards Compliance {badge}{bar}</h2>
      <span class="arrow">▼</span>
    </div>
    <div class="section-body">
      {rows if rows else empty_msg}
    </div>
  </div>"""


def _port_rows(findings: List[PortFinding]) -> str:
    if not findings:
        return ""
    rows = ""
    for f in sorted(findings, key=lambda x: x.risk.weight, reverse=True):
        rec = f'<div class="rec">→ {_esc(f.recommendation)}</div>' if f.recommendation else ""
        binding = f"<span class='mono text-muted'>{_esc(f.binding)}</span>" if f.binding else ""
        rows += f"""<tr>
      <td><span class="sev sev-{f.risk.value}">{f.risk.value}</span></td>
      <td class="mono">{f.port if f.port else '?'}</td>
      <td>{_esc(f.service)}</td>
      <td class="mono">{_esc(f.protocol)}</td>
      <td>{binding}</td>
      <td class="mono">{_esc(f.source_file)}</td>
      <td>{_esc(f.description)}{rec}</td>
    </tr>"""
    return f"""<table>
    <thead><tr>
      <th>Risk</th><th>Port</th><th>Service</th><th>Protocol</th><th>Binding</th><th>Source</th><th>Finding</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>"""


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def write(result: ScanResult, output_path: Path) -> None:
    output_path.write_text(render(result), encoding="utf-8")
