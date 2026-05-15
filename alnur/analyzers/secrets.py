"""Detect hardcoded secrets, credentials, and high-entropy strings in source files."""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from alnur.core.models import SecretFinding, Severity

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".mypy_cache",
    "venv", ".venv", "env", "virtualenv",
    "dist", "build", ".tox", ".pytest_cache",
    "vendor", "target", ".idea", ".vscode",
})

_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".wav", ".ogg",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo",
    ".lock",  # lockfiles have hashes, not secrets
    ".min.js", ".min.css",
})

_SKIP_FILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "poetry.lock", "Pipfile.lock", "composer.lock",
    "Gemfile.lock", "go.sum",
})

_MAX_FILE_BYTES = 1_048_576  # 1MB
_MAX_LINE_LENGTH = 2000
_MIN_ENTROPY_LEN = 20
_HIGH_ENTROPY_THRESHOLD = 4.5

# (pattern, secret_type, severity, description)
_PATTERNS: List[Tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"-----BEGIN\s(?:RSA\s|DSA\s|EC\s|OPENSSH\s|PGP\s)?PRIVATE KEY", re.IGNORECASE),
        "Private Key",
        Severity.CRITICAL,
        "Private cryptographic key embedded in source code",
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Access Key ID",
        Severity.CRITICAL,
        "AWS Access Key ID found — grants AWS API access",
    ),
    (
        re.compile(r"(?i)aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "AWS Secret Access Key",
        Severity.CRITICAL,
        "AWS Secret Access Key found — full AWS API authentication",
    ),
    (
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "GitHub Personal Access Token",
        Severity.CRITICAL,
        "GitHub Personal Access Token (classic) found",
    ),
    (
        re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        "GitHub Fine-Grained Token",
        Severity.CRITICAL,
        "GitHub Fine-Grained Personal Access Token found",
    ),
    (
        re.compile(r"gho_[A-Za-z0-9]{36}"),
        "GitHub OAuth Token",
        Severity.CRITICAL,
        "GitHub OAuth access token found",
    ),
    (
        re.compile(r"ghs_[A-Za-z0-9]{36}"),
        "GitHub App Token",
        Severity.HIGH,
        "GitHub App installation token found",
    ),
    (
        re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
        "Stripe Secret Key",
        Severity.CRITICAL,
        "Stripe secret API key found — can process payments",
    ),
    (
        re.compile(r"rk_(?:live|test)_[0-9a-zA-Z]{24,}"),
        "Stripe Restricted Key",
        Severity.HIGH,
        "Stripe restricted API key found",
    ),
    (
        re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
        "SendGrid API Key",
        Severity.HIGH,
        "SendGrid API key found — can send emails",
    ),
    (
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Google API Key",
        Severity.HIGH,
        "Google API key found",
    ),
    (
        re.compile(r"ya29\.[0-9A-Za-z\-_]{50,}"),
        "Google OAuth Token",
        Severity.HIGH,
        "Google OAuth access token found",
    ),
    (
        re.compile(r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"),
        "Slack Token",
        Severity.HIGH,
        "Slack API token found",
    ),
    (
        re.compile(r"AC[a-z0-9]{32}"),
        "Twilio Account SID",
        Severity.MEDIUM,
        "Twilio Account SID found",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
        "JWT Token",
        Severity.HIGH,
        "Hardcoded JWT token found — may contain sensitive claims",
    ),
    (
        re.compile(
            r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp|rabbitmq)"
            r"://[^:@\s]{1,50}:[^@\s]{1,100}@[^\s'\"]{3,}"
        ),
        "Database Connection String",
        Severity.CRITICAL,
        "Database connection string with embedded credentials",
    ),
    (
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]"),
        "Hardcoded Password",
        Severity.HIGH,
        "Hardcoded password value found in source",
    ),
    (
        re.compile(r"(?i)(?:secret_key|secret|api_secret)\s*[=:]\s*['\"]([^'\"\s]{12,})['\"]"),  # alnur: ignore
        "Hardcoded Secret",
        Severity.HIGH,
        "Hardcoded secret/key value found in source",
    ),
    (
        re.compile(r"(?i)(?:private_key|privatekey)\s*[=:]\s*['\"]([^'\"\s]{16,})['\"]"),  # alnur: ignore
        "Hardcoded Private Key Value",
        Severity.HIGH,
        "Hardcoded private key value found in source",
    ),
    (
        re.compile(r"(?i)BEGIN CERTIFICATE"),
        "Embedded Certificate",
        Severity.INFO,
        "Embedded X.509 certificate in source — verify it's not private",
    ),
]

# Keyword context for entropy-based detection
_ENTROPY_KEYWORDS = re.compile(
    r"(?i)(?:api_?key|secret[_-]?key|auth[_-]?token|access[_-]?token|"
    r"private[_-]?key|signing[_-]?key|encryption[_-]?key|bearer|password|passwd|pwd)"
)

# Patterns that are clearly not secrets (placeholder values)
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:your[-_]?|<[^>]+>|{[^}]+}|example|placeholder|changeme|todo|fixme|"
    r"xxx+|yyy+|zzz+|test|demo|sample|fake|dummy|none|null|true|false|"
    r"pass(?:word)?|secret|key|token|\*+)$"
)


def scan(root: Path, max_file_bytes: int = _MAX_FILE_BYTES) -> List[SecretFinding]:
    findings: List[SecretFinding] = []

    for file_path in _iter_source_files(root, max_file_bytes):
        findings.extend(_scan_file(file_path))

    return findings


def _iter_source_files(root: Path, max_bytes: int):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name in _SKIP_FILES:
            continue
        if any(path.name.endswith(ext) for ext in _SKIP_EXTENSIONS):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        yield path


def _scan_file(path: Path) -> List[SecretFinding]:
    findings: List[SecretFinding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = text.splitlines()
    is_env_file = path.name.startswith(".env") or path.suffix == ".env"

    for lineno, line in enumerate(lines, start=1):
        if len(line) > _MAX_LINE_LENGTH:
            continue
        if "# alnur: ignore" in line:
            continue
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--", ";")):
            continue

        for pattern, secret_type, severity, description in _PATTERNS:
            match = pattern.search(line)
            if match:
                matched_value = match.group(0)
                # Skip placeholder-looking values
                captured = match.group(1) if match.lastindex else matched_value
                if _PLACEHOLDER_RE.match(captured.strip()):
                    continue
                preview = _redact(matched_value)
                findings.append(SecretFinding(
                    file_path=str(path),
                    line_number=lineno,
                    secret_type=secret_type,
                    severity=severity,
                    description=description,
                    match_preview=preview,
                ))

        # Entropy-based detection for keyword-adjacent strings
        if _ENTROPY_KEYWORDS.search(line):
            for token in _extract_string_values(line):
                if len(token) < _MIN_ENTROPY_LEN:
                    continue
                if _PLACEHOLDER_RE.match(token.strip()):
                    continue
                if _shannon_entropy(token) >= _HIGH_ENTROPY_THRESHOLD:
                    findings.append(SecretFinding(
                        file_path=str(path),
                        line_number=lineno,
                        secret_type="High-Entropy Secret",
                        severity=Severity.MEDIUM,
                        description=(
                            "High-entropy string near sensitive keyword — "
                            "possible hardcoded credential"
                        ),
                        match_preview=_redact(token),
                    ))
                    break  # one per line to avoid noise

        # .env specific: flag non-empty, non-commented assignments
        if is_env_file:
            env_match = re.match(r"^([A-Z_][A-Z0-9_]*)=(.+)$", stripped)
            if env_match:
                key, val = env_match.group(1), env_match.group(2).strip("'\"")
                if (
                    val
                    and not _PLACEHOLDER_RE.match(val)
                    and any(kw in key for kw in (
                        "SECRET", "KEY", "TOKEN", "PASSWORD", "PASSWD",
                        "PRIVATE", "CREDENTIAL", "AUTH", "API",
                    ))
                ):
                    # Only flag if .env is not in .gitignore
                    if not _is_gitignored(path):
                        findings.append(SecretFinding(
                            file_path=str(path),
                            line_number=lineno,
                            secret_type="Exposed .env Secret",
                            severity=Severity.CRITICAL,
                            description=(
                                f".env file with secret variable '{key}' is not in .gitignore "
                                "and may be committed to version control"
                            ),
                            match_preview=f"{key}=***",
                        ))

    return _deduplicate(findings)


def _extract_string_values(line: str) -> List[str]:
    tokens: List[str] = []
    for match in re.finditer(r"""['"]([\x20-\x7E]{10,})['""]""", line):
        tokens.append(match.group(1))
    # Also match unquoted assignments
    for match in re.finditer(r"=\s*([A-Za-z0-9+/=_\-]{20,})\b", line):
        tokens.append(match.group(1))
    return tokens


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "***"
    visible = min(4, len(value) // 4)
    return value[:visible] + "***" + value[-visible:]


def _is_gitignored(env_path: Path) -> bool:
    gitignore = env_path.parent / ".gitignore"
    if not gitignore.exists():
        gitignore = env_path.parent.parent / ".gitignore"
    if not gitignore.exists():
        return False
    try:
        content = gitignore.read_text(encoding="utf-8", errors="ignore")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line in (".env", "*.env", ".env*") or env_path.name == line.lstrip("/"):
                return True
    except Exception:
        pass
    return False


def _deduplicate(findings: List[SecretFinding]) -> List[SecretFinding]:
    seen: set = set()
    unique: List[SecretFinding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.secret_type)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
