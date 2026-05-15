"""Static analysis rules for common security architecture flaws."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from alnur.core.models import ArchitectureFinding, Severity

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".mypy_cache",
    "venv", ".venv", "env", "virtualenv",
    "dist", "build", ".tox", ".pytest_cache",
    "vendor", "target", ".idea", ".vscode",
})

_MAX_FILE_BYTES = 1_048_576


@dataclass
class Rule:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    description: str
    recommendation: str
    file_globs: Tuple[str, ...]
    cwe: Optional[str] = None
    negative_lookahead: Optional[re.Pattern] = None


def _rule(
    rule_id: str,
    category: str,
    severity: str,
    pattern: str,
    description: str,
    recommendation: str,
    globs: Tuple[str, ...],
    cwe: Optional[str] = None,
    negative: Optional[str] = None,
) -> Rule:
    return Rule(
        id=rule_id,
        category=category,
        severity=Severity(severity),
        pattern=re.compile(pattern, re.MULTILINE),
        description=description,
        recommendation=recommendation,
        file_globs=globs,
        cwe=cwe,
        negative_lookahead=re.compile(negative) if negative else None,
    )


_RULES: List[Rule] = [
    # ── Injection ──────────────────────────────────────────────────────────
    _rule(
        "INJ001", "Injection", "HIGH",
        r"cursor\.execute\s*\(\s*[f\"'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)",
        "Potential SQL injection via string formatting in cursor.execute()",
        "Use parameterized queries: cursor.execute('SELECT ... WHERE id=%s', (value,))",
        ("*.py",), "CWE-89",
    ),
    _rule(
        "INJ002", "Injection", "HIGH",
        r"cursor\.execute\s*\(\s*(?:[\"'].*\+|.*\.format\(|f[\"'])",
        "SQL query constructed via string concatenation or .format()",
        "Use parameterized queries instead of string formatting",
        ("*.py",), "CWE-89",
    ),
    _rule(
        "INJ003", "Injection", "HIGH",
        r"os\.system\s*\(.*(?:request|req|input|param|query|body)",
        "Possible command injection: os.system() with user-controlled input",
        "Use subprocess with a list of arguments and avoid shell=True",
        ("*.py",), "CWE-78",
    ),
    _rule(
        "INJ004", "Injection", "HIGH",
        r"subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
        "subprocess called with shell=True — enables shell injection",
        "Pass command as a list and remove shell=True unless absolutely required",
        ("*.py",), "CWE-78",
    ),
    _rule(
        "INJ005", "Injection", "HIGH",
        r"eval\s*\(\s*(?:request\.|req\.|input\(|params|body|query|argv)",
        "eval() called with user-controlled data — remote code execution risk",
        "Never pass user input to eval(). Use safe alternatives like ast.literal_eval()",
        ("*.py",), "CWE-94",
    ),
    _rule(
        "INJ006", "Injection", "CRITICAL",
        r"eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)",
        "PHP eval() with user input — direct remote code execution",
        "Remove eval() with user input entirely; redesign the logic",
        ("*.php",), "CWE-94",
    ),
    _rule(
        "INJ007", "Injection", "HIGH",
        r"(?:system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(GET|POST|REQUEST)",
        "PHP shell execution function called with raw user input",
        "Validate and sanitize all shell arguments; prefer PHP built-in functions",
        ("*.php",), "CWE-78",
    ),
    _rule(
        "INJ008", "Injection", "HIGH",
        r"(?:child_process\.exec|execSync)\s*\([^)]*\$\{",
        "Node.js exec() with template literal — possible command injection",
        "Use execFile() with an array of arguments instead of exec() with strings",
        ("*.js", "*.ts", "*.mjs", "*.cjs"), "CWE-78",
    ),
    _rule(
        "INJ009", "Injection", "MEDIUM",
        r"\.query\s*\(\s*[`\"'].*\$\{(?:req\.|request\.|params\.|body\.|query\.)",
        "SQL query with template literal interpolation of request data",
        "Use parameterized queries with placeholders (?, $1, etc.)",
        ("*.js", "*.ts", "*.mjs"), "CWE-89",
    ),

    # ── Deserialization ────────────────────────────────────────────────────
    _rule(
        "DESER001", "Insecure Deserialization", "HIGH",
        r"pickle\.loads?\s*\(",
        "pickle.load()/loads() deserializes arbitrary Python objects — RCE risk",
        "Never deserialize untrusted data with pickle. Use JSON or restrict to trusted sources",
        ("*.py",), "CWE-502",
    ),
    _rule(
        "DESER002", "Insecure Deserialization", "HIGH",
        r"yaml\.load\s*\([^)]*\)",
        "yaml.load() without Loader= is unsafe — can execute arbitrary code",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        ("*.py",), "CWE-502",
        negative=r"yaml\.load\s*\([^)]*Loader\s*=",
    ),
    _rule(
        "DESER003", "Insecure Deserialization", "MEDIUM",
        r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "PHP unserialize() on user input — object injection risk",
        "Avoid unserialize() on untrusted data; use JSON instead",
        ("*.php",), "CWE-502",
    ),

    # ── Cryptography ───────────────────────────────────────────────────────
    _rule(
        "CRYPTO001", "Weak Cryptography", "HIGH",
        r"hashlib\.(?:md5|sha1)\s*\(",
        "MD5/SHA1 is cryptographically weak — do not use for passwords or signatures",
        "Use hashlib.sha256() or better; for passwords use bcrypt/argon2/scrypt",
        ("*.py",), "CWE-328",
    ),
    _rule(
        "CRYPTO002", "Weak Cryptography", "MEDIUM",
        r"(?:DES|3DES|RC2|RC4)\s*(?:\(|\.)",
        "Weak cipher algorithm detected (DES/3DES/RC2/RC4)",
        "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption",
        ("*.py", "*.js", "*.ts", "*.php", "*.java"), "CWE-327",
    ),
    _rule(
        "CRYPTO003", "Weak Cryptography", "MEDIUM",
        r"random\.(?:random|randint|choice|randrange)\s*\(",
        "Python random module is not cryptographically secure",
        "Use secrets.token_bytes() or os.urandom() for security-sensitive randomness",
        ("*.py",), "CWE-338",
    ),
    _rule(
        "CRYPTO004", "Weak Cryptography", "HIGH",
        r"(?i)md5\s*\(\s*\$?(?:password|passwd|pwd)",
        "MD5 used for password hashing",
        "Use bcrypt, argon2, or scrypt for password hashing",
        ("*.php", "*.py", "*.js", "*.rb"), "CWE-916",
    ),

    # ── SSL/TLS ────────────────────────────────────────────────────────────
    _rule(
        "TLS001", "TLS/SSL Misconfiguration", "HIGH",
        r"verify\s*=\s*False",
        "SSL certificate verification disabled in HTTP request",
        "Remove verify=False; configure proper CA bundle if needed",
        ("*.py",), "CWE-295",
    ),
    _rule(
        "TLS002", "TLS/SSL Misconfiguration", "HIGH",
        r"rejectUnauthorized\s*:\s*false",
        "Node.js TLS certificate verification disabled",
        "Remove rejectUnauthorized: false; fix the certificate chain",
        ("*.js", "*.ts", "*.mjs", "*.cjs"), "CWE-295",
    ),
    _rule(
        "TLS003", "TLS/SSL Misconfiguration", "MEDIUM",
        r"(?i)ssl_verify\s*=\s*(?:false|0|no)",
        "SSL verification disabled in configuration",
        "Enable SSL verification; use a valid certificate",
        ("*.py", "*.cfg", "*.ini", "*.conf"), "CWE-295",
    ),
    _rule(
        "TLS004", "TLS/SSL Misconfiguration", "MEDIUM",
        r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|(?:www\.)?(?:w3\.org|maven\.apache\.org|xmlsoap\.org|springframework\.org|schemas\.microsoft\.com|dublincore\.org|purl\.org))[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}",
        "External URL uses plain HTTP — data transmitted unencrypted",
        "Use HTTPS for all external communications",
        ("*.py", "*.js", "*.ts", "*.php", "*.rb", "*.java", "*.go"), "CWE-319",
    ),

    # ── Django-specific ────────────────────────────────────────────────────
    _rule(
        "DJANGO001", "Framework Misconfiguration", "HIGH",
        r"DEBUG\s*=\s*True",
        "Django DEBUG=True exposes stack traces, settings, and SQL queries to attackers",
        "Set DEBUG=False in production; use environment variables to control this",
        ("*.py",), "CWE-209",
    ),
    _rule(
        "DJANGO002", "Framework Misconfiguration", "HIGH",
        r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]",
        "Django ALLOWED_HOSTS=['*'] allows HTTP Host header injection",
        "Set ALLOWED_HOSTS to specific domain names in production",
        ("*.py",), "CWE-20",
    ),
    _rule(
        "DJANGO003", "Framework Misconfiguration", "HIGH",
        r"SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]",
        "Django SECRET_KEY hardcoded in source — rotate immediately if exposed",
        "Load SECRET_KEY from environment variables, never commit it to source control",
        ("*.py",), "CWE-798",
    ),
    _rule(
        "DJANGO004", "Framework Misconfiguration", "MEDIUM",
        r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True",
        "CORS configured to allow all origins — bypasses same-origin protection",
        "Set CORS_ALLOWED_ORIGINS to specific trusted domains",
        ("*.py",), "CWE-942",
    ),
    _rule(
        "DJANGO005", "Framework Misconfiguration", "MEDIUM",
        r"CSRF_COOKIE_HTTPONLY\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False",
        "Django CSRF cookie not set as HttpOnly/Secure",
        "Set CSRF_COOKIE_HTTPONLY=True and CSRF_COOKIE_SECURE=True",
        ("*.py",), "CWE-614",
    ),

    # ── Flask-specific ─────────────────────────────────────────────────────
    _rule(
        "FLASK001", "Framework Misconfiguration", "HIGH",
        r"app\.(?:run|debug)\s*\([^)]*debug\s*=\s*True",
        "Flask running with debug=True — Werkzeug debugger allows RCE",
        "Never enable debug mode in production",
        ("*.py",), "CWE-94",
    ),
    _rule(
        "FLASK002", "Framework Misconfiguration", "HIGH",
        r"app\.secret_key\s*=\s*['\"][^'\"]{1,16}['\"]",
        "Flask secret_key is very short or hardcoded — session forgery risk",
        "Use a long random secret key loaded from environment variables",
        ("*.py",), "CWE-798",
    ),
    _rule(
        "FLASK003", "XSS", "MEDIUM",
        r"Markup\s*\(\s*(?:request\.|g\.|session\.|f['\"])",
        "Flask Markup() applied to user input bypasses auto-escaping — XSS risk",
        "Never pass untrusted data to Markup()",
        ("*.py",), "CWE-79",
    ),

    # ── Express.js / Node ──────────────────────────────────────────────────
    _rule(
        "NODE001", "Framework Misconfiguration", "MEDIUM",
        r"app\.disable\s*\(['\"]x-powered-by['\"]",
        "Express x-powered-by header is disabled (this is actually good practice)",
        "Good: disabling x-powered-by hides technology fingerprint",
        ("*.js", "*.ts", "*.mjs"),
    ),
    _rule(
        "NODE002", "Framework Misconfiguration", "HIGH",
        r"helmet\s*\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false",
        "Content Security Policy disabled in Helmet.js configuration",
        "Enable CSP with appropriate directives to prevent XSS",
        ("*.js", "*.ts", "*.mjs"), "CWE-1021",
    ),
    _rule(
        "NODE003", "Injection", "HIGH",
        r"new\s+Function\s*\([^)]*(?:req\.|request\.|body\.|params\.|query\.)",
        "Dynamic Function() construction with user input — code injection risk",
        "Never construct functions from user-controlled strings",
        ("*.js", "*.ts"), "CWE-94",
    ),
    _rule(
        "NODE004", "Path Traversal", "HIGH",
        r"(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)",
        "File read with user-controlled path — directory traversal risk",
        "Validate and sanitize file paths; use path.resolve() and check the result",
        ("*.js", "*.ts", "*.mjs"), "CWE-22",
    ),

    # ── Path Traversal ────────────────────────────────────────────────────
    _rule(
        "PATH001", "Path Traversal", "HIGH",
        r"open\s*\(\s*(?:request\.|req\.|input|params|os\.path\.join[^)]*(?:request|req|input))",
        "File opened with user-controlled path — path traversal risk",
        "Use os.path.realpath() and verify the result is within an allowed directory",
        ("*.py",), "CWE-22",
    ),
    _rule(
        "PATH002", "Path Traversal", "HIGH",
        r"(?:include|require|require_once)\s*\(\s*\$_(GET|POST|REQUEST)",
        "PHP file inclusion with user input — local/remote file inclusion risk",
        "Never use user input in include/require; use a whitelist of allowed files",
        ("*.php",), "CWE-98",
    ),

    # ── Open Redirect ─────────────────────────────────────────────────────
    _rule(
        "REDIR001", "Open Redirect", "MEDIUM",
        r"(?:redirect|header\s*\(\s*['\"]Location)\s*[:()\s]*(?:\$_(?:GET|POST|REQUEST|SERVER)|request\.|req\.)",
        "Redirect using unvalidated user input — open redirect vulnerability",
        "Validate redirect URLs against a whitelist of allowed destinations",
        ("*.php", "*.py", "*.js", "*.ts", "*.rb"), "CWE-601",
    ),

    # ── XSS ───────────────────────────────────────────────────────────────
    _rule(
        "XSS001", "XSS", "HIGH",
        r"(?:innerHTML|outerHTML|document\.write)\s*[+=]\s*(?:.*(?:req\.|request\.|params\.|query\.|body\.|\$_(GET|POST|REQUEST)))",
        "innerHTML/document.write with potentially user-controlled data — XSS risk",
        "Use textContent instead of innerHTML; sanitize HTML if markup is required",
        ("*.js", "*.ts", "*.mjs", "*.html"), "CWE-79",
    ),
    _rule(
        "XSS002", "XSS", "HIGH",
        r"echo\s+\$_(GET|POST|REQUEST|COOKIE)",
        "PHP echo with raw user input — reflected XSS vulnerability",
        "Use htmlspecialchars($_GET[...], ENT_QUOTES, 'UTF-8') before echoing",
        ("*.php",), "CWE-79",
    ),

    # ── Docker / Infrastructure ────────────────────────────────────────────
    _rule(
        "DOCKER001", "Container Security", "MEDIUM",
        r"^FROM\s+\S+:latest",
        "Docker image uses :latest tag — non-deterministic builds, possible supply chain risk",
        "Pin Docker images to a specific digest or version tag",
        ("Dockerfile", "*.dockerfile"), "CWE-1104",
    ),
    _rule(
        "DOCKER002", "Container Security", "HIGH",
        r"^USER\s+root\b",
        "Docker container runs as root — privilege escalation risk if container is compromised",
        "Add a non-root USER instruction before CMD/ENTRYPOINT",
        ("Dockerfile", "*.dockerfile"), "CWE-250",
    ),
    _rule(
        "DOCKER003", "Container Security", "MEDIUM",
        r"^RUN\s+.*chmod\s+(?:777|a\+[rwx])",
        "Docker layer sets world-writable permissions",
        "Use minimal permissions (chmod 755 or 644) instead of 777",
        ("Dockerfile", "*.dockerfile"), "CWE-732",
    ),

    # ── Miscellaneous ──────────────────────────────────────────────────────
    _rule(
        "MISC001", "Insecure Configuration", "MEDIUM",
        r"(?i)FLASK_ENV\s*=\s*development|NODE_ENV\s*=\s*development",
        "Development environment mode set — may enable debug features",
        "Ensure NODE_ENV=production or FLASK_ENV=production in deployment configs",
        ("*.env", ".env", "*.env.*"), "CWE-209",
    ),
    _rule(
        "MISC002", "Prototype Pollution", "HIGH",
        r"(?:__proto__|constructor\s*\[|prototype\s*\[)",
        "Possible prototype pollution pattern detected",
        "Avoid mutating Object.prototype; validate keys before assignment",
        ("*.js", "*.ts", "*.mjs"), "CWE-1321",
    ),
    _rule(
        "MISC003", "Mass Assignment", "MEDIUM",
        r"(?:\.save\s*\(\s*\$_(?:POST|REQUEST)|Model\.create\s*\(\s*request\.(?:POST|data|json))",
        "Possible mass assignment — user input directly passed to model save()/create()",
        "Explicitly specify allowed fields; use Django's fields= or DRF serializer validation",
        ("*.py", "*.php"), "CWE-915",
    ),
    _rule(
        "MISC004", "Hardcoded Credentials", "HIGH",
        r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
        "Hardcoded password literal found in source code",
        "Load credentials from environment variables or a secrets manager",
        ("*.py", "*.js", "*.ts", "*.php", "*.java", "*.go", "*.rb", "*.cs"), "CWE-798",
        negative=r"(?i)(?:test|sample|example|placeholder|default|changeme|dummy)",
    ),
]


def scan(root: Path, max_file_bytes: int = _MAX_FILE_BYTES) -> List[ArchitectureFinding]:
    findings: List[ArchitectureFinding] = []

    for path in _iter_files(root, max_file_bytes):
        applicable_rules = [r for r in _RULES if _matches_globs(path, r.file_globs)]
        if not applicable_rules:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        lines = text.splitlines()
        for rule in applicable_rules:
            for match in rule.pattern.finditer(text):
                if rule.negative_lookahead and rule.negative_lookahead.search(match.group(0)):
                    continue
                lineno = text[: match.start()].count("\n") + 1
                if lineno <= len(lines) and "# alnur: ignore" in lines[lineno - 1]:
                    continue
                line_preview = lines[lineno - 1].strip()[:120] if lineno <= len(lines) else ""
                findings.append(ArchitectureFinding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    file_path=str(path),
                    line_number=lineno,
                    recommendation=rule.recommendation,
                    cwe=rule.cwe,
                ))

    return _deduplicate(findings)


def _iter_files(root: Path, max_bytes: int):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name.endswith((".png", ".jpg", ".gif", ".ico", ".woff", ".ttf",
                               ".zip", ".tar", ".gz", ".exe", ".dll", ".pyc")):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        yield path


def _matches_globs(path: Path, globs: Tuple[str, ...]) -> bool:
    name = path.name
    for glob in globs:
        if glob.startswith("*"):
            if name.endswith(glob.lstrip("*")):
                return True
        elif name == glob:
            return True
    return False


def _deduplicate(findings: List[ArchitectureFinding]) -> List[ArchitectureFinding]:
    seen: set = set()
    unique: List[ArchitectureFinding] = []
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_number)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
