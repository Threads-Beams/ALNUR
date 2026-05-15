"""Detect risky port configurations in source files, Dockerfiles, and compose files."""
from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from alnur.core.models import PortFinding, Severity

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", "target", "vendor",
})

# Well-known dangerous ports: (service, protocol, risk, description, recommendation)
_KNOWN_PORTS: Dict[int, Tuple[str, str, Severity, str, str]] = {
    20: ("FTP Data", "TCP", Severity.HIGH, "FTP data transfer port — plaintext protocol, susceptible to sniffing", "Replace FTP with SFTP (port 22) or FTPS"),
    21: ("FTP Control", "TCP", Severity.HIGH, "FTP control port — plaintext credentials and data", "Replace FTP with SFTP (port 22) or FTPS"),
    23: ("Telnet", "TCP", Severity.CRITICAL, "Telnet transmits all data including credentials in plaintext", "Replace Telnet with SSH (port 22)"),
    25: ("SMTP", "TCP", Severity.MEDIUM, "SMTP port — ensure TLS is enforced, not optional", "Use SMTPS (port 465) or STARTTLS"),
    53: ("DNS", "UDP/TCP", Severity.MEDIUM, "DNS port exposed — potential for DNS amplification attacks if open externally", "Restrict DNS to internal networks; enable DNSSEC"),
    80: ("HTTP", "TCP", Severity.MEDIUM, "Plain HTTP exposed — traffic not encrypted", "Redirect all HTTP to HTTPS (port 443)"),
    110: ("POP3", "TCP", Severity.HIGH, "POP3 transmits credentials in plaintext", "Use POP3S (port 995) with TLS"),
    143: ("IMAP", "TCP", Severity.MEDIUM, "IMAP without TLS exposes email credentials", "Use IMAPS (port 993) with TLS"),
    389: ("LDAP", "TCP", Severity.HIGH, "LDAP plaintext directory access — credential exposure risk", "Use LDAPS (port 636) with TLS"),
    445: ("SMB", "TCP", Severity.CRITICAL, "SMB exposed — known attack vector (EternalBlue, WannaCry, etc.)", "Block SMB from internet exposure; use VPN for internal access"),
    1433: ("MSSQL", "TCP", Severity.HIGH, "Microsoft SQL Server port exposed — should not be internet-facing", "Restrict MSSQL to localhost or internal network behind firewall"),
    1521: ("Oracle DB", "TCP", Severity.HIGH, "Oracle Database port exposed — should not be internet-facing", "Restrict to localhost or internal network"),
    2375: ("Docker API (unauth)", "TCP", Severity.CRITICAL, "Docker daemon HTTP API (unauthenticated) — full host compromise", "Never expose Docker daemon on 2375; use 2376 with TLS"),
    2376: ("Docker API (TLS)", "TCP", Severity.MEDIUM, "Docker daemon TLS API exposed — ensure client cert authentication", "Restrict access to trusted IPs; use mutual TLS"),
    3306: ("MySQL/MariaDB", "TCP", Severity.HIGH, "MySQL/MariaDB database port — should not be internet-facing", "Bind MySQL to 127.0.0.1; use SSH tunneling or VPN for remote access"),
    3389: ("RDP", "TCP", Severity.CRITICAL, "Remote Desktop Protocol exposed — frequent attack target", "Place RDP behind VPN; enable Network Level Authentication"),
    4200: ("Angular Dev Server", "TCP", Severity.LOW, "Angular development server — should not run in production", "Use a production web server (nginx, Apache) instead"),
    4443: ("HTTPS Alt", "TCP", Severity.LOW, "Alternate HTTPS port — ensure TLS is properly configured", "Use standard port 443 when possible"),
    5000: ("Flask Dev / Docker Registry", "TCP", Severity.MEDIUM, "Flask development server or Docker registry — verify intended use", "Do not expose Flask dev server in production"),
    5432: ("PostgreSQL", "TCP", Severity.HIGH, "PostgreSQL database port — should not be internet-facing", "Bind PostgreSQL to localhost; use SSH tunneling for remote access"),
    5900: ("VNC", "TCP", Severity.CRITICAL, "VNC remote desktop — often has weak authentication", "Disable VNC or restrict to VPN; use SSH port forwarding"),
    6379: ("Redis", "TCP", Severity.CRITICAL, "Redis has no authentication by default — critical data exposure", "Bind Redis to 127.0.0.1; enable requirepass; use AUTH"),
    7000: ("Cassandra", "TCP", Severity.HIGH, "Apache Cassandra inter-node port — should not be publicly accessible", "Restrict Cassandra ports to cluster network"),
    7474: ("Neo4j HTTP", "TCP", Severity.HIGH, "Neo4j browser/HTTP API exposed", "Restrict Neo4j to localhost; use authentication"),
    8080: ("HTTP Alt", "TCP", Severity.LOW, "Alternate HTTP port — verify TLS if serving production traffic", "Consider using HTTPS with standard port 443"),
    8443: ("HTTPS Alt", "TCP", Severity.LOW, "Alternate HTTPS port — verify TLS configuration", "Prefer standard port 443"),
    9000: ("PHP-FPM / SonarQube", "TCP", Severity.MEDIUM, "PHP-FPM or SonarQube port — should not be publicly accessible", "Restrict PHP-FPM to local socket or internal network"),
    9200: ("Elasticsearch HTTP", "TCP", Severity.CRITICAL, "Elasticsearch HTTP API with no auth by default — frequent data breach source", "Enable X-Pack security; bind to localhost; use TLS"),
    9300: ("Elasticsearch Transport", "TCP", Severity.CRITICAL, "Elasticsearch cluster transport — sensitive internal API", "Never expose Elasticsearch transport port to internet"),
    27017: ("MongoDB", "TCP", Severity.CRITICAL, "MongoDB default port — no authentication by default in older versions", "Enable MongoDB auth; bind to localhost; restrict network access"),
    27018: ("MongoDB Shard", "TCP", Severity.HIGH, "MongoDB shard port — internal cluster communication", "Restrict to internal network only"),
    28017: ("MongoDB Web", "TCP", Severity.HIGH, "MongoDB HTTP admin interface (deprecated)", "Disable MongoDB HTTP interface"),
    50000: ("Jenkins", "TCP", Severity.HIGH, "Jenkins agent port exposed — can allow code execution", "Restrict Jenkins to localhost or VPN"),
}


def scan(root: Path) -> List[PortFinding]:
    findings: List[PortFinding] = []

    findings.extend(_scan_dockerfile(root))
    findings.extend(_scan_docker_compose(root))
    findings.extend(_scan_env_files(root))
    findings.extend(_scan_config_files(root))
    findings.extend(_scan_bind_addresses(root))

    return _deduplicate(findings)


def _scan_dockerfile(root: Path) -> List[PortFinding]:
    findings: List[PortFinding] = []
    for df in list(root.glob("**/Dockerfile")) + list(root.glob("**/*.dockerfile")):
        if any(part in _SKIP_DIRS for part in df.parts):
            continue
        try:
            text = df.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for lineno, line in enumerate(text.splitlines(), 1):
            match = re.match(r"^\s*EXPOSE\s+([\d\s/]+)", line, re.IGNORECASE)
            if not match:
                continue
            for token in match.group(1).split():
                port_str = token.split("/")[0]
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                if port in _KNOWN_PORTS:
                    svc, proto, risk, desc, rec = _KNOWN_PORTS[port]
                    findings.append(PortFinding(
                        source_file=str(df),
                        port=port,
                        service=svc,
                        protocol=proto,
                        risk=risk,
                        description=f"Dockerfile EXPOSEs port {port} ({svc}): {desc}",
                        recommendation=rec,
                        binding="0.0.0.0",
                    ))
    return findings


def _scan_docker_compose(root: Path) -> List[PortFinding]:
    findings: List[PortFinding] = []
    compose_files = (
        list(root.glob("**/docker-compose*.yml"))
        + list(root.glob("**/docker-compose*.yaml"))
        + list(root.glob("**/compose*.yml"))
        + list(root.glob("**/compose*.yaml"))
    )
    for cf in compose_files:
        if any(part in _SKIP_DIRS for part in cf.parts):
            continue
        try:
            text = cf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Parse port mappings: "HOST:CONTAINER" or bare port numbers
        for match in re.finditer(
            r'["\'`]?\s*-\s*["\'`]?(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):)?(\d+):(\d+)',
            text,
        ):
            bind_ip = match.group(1) or "0.0.0.0"
            host_port_str = match.group(2)
            container_port_str = match.group(3)
            try:
                container_port = int(container_port_str)
            except ValueError:
                continue

            info = _KNOWN_PORTS.get(container_port)
            if info:
                svc, proto, risk, desc, rec = info
                # Binding to 0.0.0.0 makes it publicly accessible
                if bind_ip == "0.0.0.0":
                    findings.append(PortFinding(
                        source_file=str(cf),
                        port=container_port,
                        service=svc,
                        protocol=proto,
                        risk=risk,
                        description=f"docker-compose exposes port {container_port} ({svc}) on all interfaces: {desc}",
                        recommendation=rec + "; bind to 127.0.0.1 in docker-compose: '127.0.0.1:PORT:PORT'",
                        binding=bind_ip,
                    ))
                else:
                    findings.append(PortFinding(
                        source_file=str(cf),
                        port=container_port,
                        service=svc,
                        protocol=proto,
                        risk=Severity.LOW,
                        description=f"docker-compose exposes port {container_port} ({svc}) bound to {bind_ip}",
                        recommendation=rec,
                        binding=bind_ip,
                    ))
    return findings


def _scan_env_files(root: Path) -> List[PortFinding]:
    findings: List[PortFinding] = []
    env_files = list(root.glob(".env*")) + list(root.glob("**/.env*"))
    for ef in env_files:
        if ef.is_dir() or any(part in _SKIP_DIRS for part in ef.parts):
            continue
        if ef.name.endswith(".example"):
            continue
        try:
            text = ef.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for lineno, line in enumerate(text.splitlines(), 1):
            match = re.match(r"^[A-Z_]*PORT\s*=\s*(\d+)", line)
            if match:
                try:
                    port = int(match.group(1))
                except ValueError:
                    continue
                if port in _KNOWN_PORTS:
                    svc, proto, risk, desc, rec = _KNOWN_PORTS[port]
                    findings.append(PortFinding(
                        source_file=str(ef),
                        port=port,
                        service=svc,
                        protocol=proto,
                        risk=risk,
                        description=f".env configures port {port} ({svc}): {desc}",
                        recommendation=rec,
                    ))
    return findings


def _scan_config_files(root: Path) -> List[PortFinding]:
    findings: List[PortFinding] = []
    config_globs = [
        "**/application.yml", "**/application.yaml",
        "**/application.properties",
        "**/appsettings.json", "**/appsettings.*.json",
        "**/config.json", "**/config.yaml", "**/config.yml",
        "**/settings.py",
    ]
    port_pattern = re.compile(r"(?i)(?:port|listen)\s*[=:]\s*(\d{2,5})")

    for glob in config_globs:
        for cfg_path in list(root.glob(glob))[:20]:
            if any(part in _SKIP_DIRS for part in cfg_path.parts):
                continue
            try:
                text = cfg_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for match in port_pattern.finditer(text):
                try:
                    port = int(match.group(1))
                except ValueError:
                    continue
                if port < 1 or port > 65535:
                    continue
                if port in _KNOWN_PORTS:
                    svc, proto, risk, desc, rec = _KNOWN_PORTS[port]
                    findings.append(PortFinding(
                        source_file=str(cfg_path),
                        port=port,
                        service=svc,
                        protocol=proto,
                        risk=risk,
                        description=f"Config file references port {port} ({svc}): {desc}",
                        recommendation=rec,
                    ))
    return findings


def _scan_bind_addresses(root: Path) -> List[PortFinding]:
    """Flag 0.0.0.0 bindings in application code."""
    findings: List[PortFinding] = []
    bind_all = re.compile(
        r"""(?:host|bind|address|listen)\s*[=:]\s*['"]0\.0\.0\.0['"]"""
    )
    port_pattern = re.compile(r"(?i)(?:port)\s*[=:,\s]\s*(\d{2,5})")

    src_globs = ["**/*.py", "**/*.js", "**/*.ts", "**/*.rb", "**/*.go"]
    for glob in src_globs:
        for src_path in list(root.glob(glob))[:50]:
            if any(part in _SKIP_DIRS for part in src_path.parts):
                continue
            try:
                text = src_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if bind_all.search(text):
                # Try to find nearby port
                port_match = port_pattern.search(text)
                port = int(port_match.group(1)) if port_match else 0
                svc = _KNOWN_PORTS.get(port, ("Unknown", "TCP", Severity.MEDIUM, "", ""))[0]
                findings.append(PortFinding(
                    source_file=str(src_path),
                    port=port if port else 0,
                    service=svc if port else "Application",
                    protocol="TCP",
                    risk=Severity.MEDIUM,
                    description=f"Application binds to 0.0.0.0 — listens on all network interfaces",
                    recommendation="Bind to 127.0.0.1 in development; use a reverse proxy (nginx) in production",
                    binding="0.0.0.0",
                ))
    return findings


def _deduplicate(findings: List[PortFinding]) -> List[PortFinding]:
    seen: set = set()
    unique: List[PortFinding] = []
    for f in findings:
        key = (f.source_file, f.port, f.description[:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
