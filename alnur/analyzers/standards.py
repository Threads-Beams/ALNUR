"""Check project against software engineering and security standards."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from alnur.core.models import ProjectType, Severity, StandardsFinding


def scan(root: Path, project_types: List[ProjectType]) -> List[StandardsFinding]:
    findings: List[StandardsFinding] = []

    findings.append(_check_gitignore(root))
    findings.append(_check_env_not_committed(root))
    findings.append(_check_lockfile(root, project_types))
    findings.append(_check_sensitive_in_gitignore(root))
    findings.append(_check_no_node_modules_committed(root))
    findings.append(_check_no_pycache_committed(root))
    findings.append(_check_has_tests(root, project_types))
    findings.append(_check_ci_cd(root))
    findings.append(_check_docker_non_root(root))
    findings.append(_check_docker_no_latest(root))
    findings.append(_check_dep_pinning(root, project_types))
    findings.append(_check_no_debug_code(root))
    findings.append(_check_security_policy(root))
    findings.append(_check_https_in_api_calls(root))
    findings.append(_check_no_print_sensitive(root))

    return [f for f in findings if f is not None]


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_gitignore(root: Path) -> StandardsFinding:
    exists = (root / ".gitignore").exists()
    return StandardsFinding(
        check_id="STD001",
        check_name=".gitignore present",
        passed=exists,
        severity=Severity.HIGH,
        description=".gitignore found" if exists else "No .gitignore file detected",
        recommendation="Create a .gitignore appropriate for your project type to avoid committing secrets, binaries, or build artifacts",
    )


def _check_env_not_committed(root: Path) -> StandardsFinding:
    env_files = [p for p in root.glob(".env*") if p.is_file() and not p.name.endswith(".example")]
    git_index = root / ".git" / "index"

    if not env_files:
        return StandardsFinding(
            check_id="STD002",
            check_name=".env not committed",
            passed=True,
            severity=Severity.CRITICAL,
            description="No .env file found in project root",
        )

    gitignore_path = root / ".gitignore"
    protected = False
    if gitignore_path.exists():
        content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        protected = any(
            pattern in content
            for pattern in (".env", "*.env", ".env*", ".env.local")
        )

    passed = protected
    return StandardsFinding(
        check_id="STD002",
        check_name=".env not committed",
        passed=passed,
        severity=Severity.CRITICAL,
        description=".env file is gitignored" if passed else ".env file exists but is NOT in .gitignore — may expose secrets",
        recommendation="Add .env to .gitignore; use .env.example with dummy values for documentation",
    )


def _check_lockfile(root: Path, project_types: List[ProjectType]) -> StandardsFinding:
    lockfiles = [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "Pipfile.lock", "poetry.lock",
        "composer.lock",
        "Gemfile.lock",
        "Cargo.lock",
        "go.sum",
    ]
    has_lockfile = any((root / lf).exists() for lf in lockfiles)
    return StandardsFinding(
        check_id="STD003",
        check_name="Dependency lockfile present",
        passed=has_lockfile,
        severity=Severity.MEDIUM,
        description="Lockfile found — reproducible builds ensured" if has_lockfile else "No lockfile found — dependency versions may be unpredictable",
        recommendation="Commit your lockfile (package-lock.json, poetry.lock, etc.) to ensure deterministic installs",
    )


def _check_sensitive_in_gitignore(root: Path) -> StandardsFinding:
    gitignore_path = root / ".gitignore"
    if not gitignore_path.exists():
        return StandardsFinding(
            check_id="STD004",
            check_name="Gitignore covers sensitive patterns",
            passed=False,
            severity=Severity.HIGH,
            description=".gitignore missing — sensitive file patterns not excluded",
            recommendation="Create .gitignore with entries for .env, *.pem, *.key, *.p12, secrets/, etc.",
        )

    content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
    sensitive_patterns = {".env", "*.pem", "*.key", "*.p12", "*.pfx", "*.crt"}
    missing = sensitive_patterns - set(
        line.strip() for line in content.splitlines()
    )
    passed = len(missing) <= 2

    return StandardsFinding(
        check_id="STD004",
        check_name="Gitignore covers sensitive patterns",
        passed=passed,
        severity=Severity.MEDIUM,
        description=f"Gitignore covers sensitive patterns" if passed else f"Gitignore missing patterns: {', '.join(sorted(missing))}",
        recommendation="Add these patterns to .gitignore: " + ", ".join(sorted(missing)),
    )


def _check_no_node_modules_committed(root: Path) -> StandardsFinding:
    nm = root / "node_modules"
    if not nm.exists():
        return StandardsFinding(
            check_id="STD005",
            check_name="node_modules not in repo",
            passed=True,
            severity=Severity.MEDIUM,
            description="node_modules directory not present in project root",
        )
    # Check if it's gitignored
    gitignore_path = root / ".gitignore"
    protected = False
    if gitignore_path.exists():
        content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        protected = "node_modules" in content

    return StandardsFinding(
        check_id="STD005",
        check_name="node_modules not in repo",
        passed=protected,
        severity=Severity.MEDIUM,
        description="node_modules is gitignored" if protected else "node_modules exists and is NOT in .gitignore — bloats repository",
        recommendation="Add node_modules/ to .gitignore",
    )


def _check_no_pycache_committed(root: Path) -> StandardsFinding:
    gitignore_path = root / ".gitignore"
    if not gitignore_path.exists():
        return StandardsFinding(
            check_id="STD006",
            check_name="__pycache__ not in repo",
            passed=False,
            severity=Severity.LOW,
            description="No .gitignore — __pycache__ may be committed",
            recommendation="Add __pycache__/, *.py[cod], *.pyo to .gitignore",
        )

    content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
    protected = "__pycache__" in content or "*.pyc" in content
    return StandardsFinding(
        check_id="STD006",
        check_name="__pycache__ not in repo",
        passed=protected,
        severity=Severity.LOW,
        description="Python bytecode excluded from repo" if protected else "__pycache__ not in .gitignore",
        recommendation="Add __pycache__/ and *.pyc to .gitignore",
    )


def _check_has_tests(root: Path, project_types: List[ProjectType]) -> StandardsFinding:
    test_indicators = [
        root / "tests",
        root / "test",
        root / "spec",
        root / "__tests__",
        root / "test_*.py",
        root / "*.test.js",
        root / "*.spec.js",
        root / "*.test.ts",
        root / "*.spec.ts",
    ]
    has_tests = (
        any(p.exists() for p in test_indicators[:6])
        or bool(list(root.glob("test_*.py"))[:1])
        or bool(list(root.glob("**/*.test.js"))[:1])
        or bool(list(root.glob("**/*.test.ts"))[:1])
        or bool(list(root.glob("**/*.spec.js"))[:1])
    )
    return StandardsFinding(
        check_id="STD007",
        check_name="Test suite present",
        passed=has_tests,
        severity=Severity.MEDIUM,
        description="Test suite found" if has_tests else "No test suite detected — untested code is higher risk",
        recommendation="Add a tests/ directory with unit and integration tests; aim for >70% coverage",
    )


def _check_ci_cd(root: Path) -> StandardsFinding:
    ci_files = [
        ".github/workflows",
        ".gitlab-ci.yml",
        ".travis.yml",
        "Jenkinsfile",
        ".circleci/config.yml",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
        ".buildkite",
        "cloudbuild.yaml",
    ]
    has_ci = any((root / f).exists() for f in ci_files)
    return StandardsFinding(
        check_id="STD008",
        check_name="CI/CD pipeline configured",
        passed=has_ci,
        severity=Severity.LOW,
        description="CI/CD pipeline found" if has_ci else "No CI/CD configuration detected",
        recommendation="Set up a CI/CD pipeline (GitHub Actions, GitLab CI, etc.) to run tests and security scans automatically",
    )


def _check_docker_non_root(root: Path) -> StandardsFinding:
    dockerfiles = list(root.glob("**/Dockerfile")) + list(root.glob("**/*.dockerfile"))
    if not dockerfiles:
        return StandardsFinding(
            check_id="STD009",
            check_name="Docker non-root user",
            passed=True,
            severity=Severity.HIGH,
            description="No Dockerfile found — check not applicable",
        )

    all_ok = True
    for df in dockerfiles:
        if any(part in {".git", "node_modules"} for part in df.parts):
            continue
        try:
            content = df.read_text(encoding="utf-8", errors="ignore")
            has_user = bool(re.search(r"^USER\s+(?!root\b)", content, re.MULTILINE))
            has_root_user = bool(re.search(r"^USER\s+root\b", content, re.MULTILINE))
            if has_root_user or (not has_user and "FROM" in content):
                all_ok = False
                break
        except Exception:
            pass

    return StandardsFinding(
        check_id="STD009",
        check_name="Docker non-root user",
        passed=all_ok,
        severity=Severity.HIGH,
        description="Dockerfile(s) use non-root user" if all_ok else "Dockerfile(s) may run as root — privilege escalation risk",
        recommendation="Add 'USER appuser' instruction in Dockerfile before CMD/ENTRYPOINT",
    )


def _check_docker_no_latest(root: Path) -> StandardsFinding:
    dockerfiles = list(root.glob("**/Dockerfile")) + list(root.glob("**/*.dockerfile"))
    if not dockerfiles:
        return StandardsFinding(
            check_id="STD010",
            check_name="Docker images pinned",
            passed=True,
            severity=Severity.MEDIUM,
            description="No Dockerfile found — check not applicable",
        )

    uses_latest = False
    for df in dockerfiles:
        if any(part in {".git", "node_modules"} for part in df.parts):
            continue
        try:
            content = df.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"^FROM\s+\S+:latest", content, re.MULTILINE):
                uses_latest = True
                break
        except Exception:
            pass

    return StandardsFinding(
        check_id="STD010",
        check_name="Docker images pinned",
        passed=not uses_latest,
        severity=Severity.MEDIUM,
        description="Docker images are version-pinned" if not uses_latest else "Dockerfile uses :latest tag — non-deterministic builds",
        recommendation="Pin Docker base images to specific versions or SHA digests",
    )


def _check_dep_pinning(root: Path, project_types: List[ProjectType]) -> StandardsFinding:
    req_path = root / "requirements.txt"
    if not req_path.exists():
        return StandardsFinding(
            check_id="STD011",
            check_name="Dependencies pinned",
            passed=True,
            severity=Severity.MEDIUM,
            description="No requirements.txt found — check not applicable",
        )

    try:
        lines = req_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        unpinned = [
            line.strip()
            for line in lines
            if line.strip()
            and not line.startswith(("#", "-"))
            and "==" not in line
            and re.match(r"^[A-Za-z0-9]", line)
        ]
    except Exception:
        unpinned = []

    passed = len(unpinned) == 0
    return StandardsFinding(
        check_id="STD011",
        check_name="Python dependencies pinned",
        passed=passed,
        severity=Severity.MEDIUM,
        description="All Python dependencies pinned with ==" if passed else f"{len(unpinned)} unpinned dependencies found",
        recommendation="Pin all dependencies with exact versions (==) or use a lockfile to ensure reproducibility",
    )


def _check_no_debug_code(root: Path) -> StandardsFinding:
    debug_patterns = [
        (r"\bpdb\.set_trace\(\)", "*.py"),
        (r"\bdebugger\b\s*;", "*.js"),
        (r"\bconsole\.log\b", "*.js"),
        (r"\bvar_dump\s*\(", "*.php"),
        (r"\bprint_r\s*\(", "*.php"),
    ]
    found_debug = False
    for pattern, glob in debug_patterns:
        for file_path in list(root.glob(f"**/{glob}"))[:50]:
            if any(part in {".git", "node_modules", "test", "tests", "__pycache__"} for part in file_path.parts):
                continue
            try:
                if re.search(pattern, file_path.read_text(encoding="utf-8", errors="ignore")):
                    found_debug = True
                    break
            except Exception:
                pass
        if found_debug:
            break

    return StandardsFinding(
        check_id="STD012",
        check_name="No debug statements in production code",
        passed=not found_debug,
        severity=Severity.LOW,
        description="No debug statements detected" if not found_debug else "Debug statements found (pdb.set_trace, debugger, console.log, var_dump)",
        recommendation="Remove all debug statements before deploying to production",
    )


def _check_security_policy(root: Path) -> StandardsFinding:
    security_files = [
        root / "SECURITY.md",
        root / "security.md",
        root / ".github" / "SECURITY.md",
        root / "docs" / "SECURITY.md",
    ]
    has_policy = any(f.exists() for f in security_files)
    return StandardsFinding(
        check_id="STD013",
        check_name="Security policy defined",
        passed=has_policy,
        severity=Severity.INFO,
        description="SECURITY.md found" if has_policy else "No SECURITY.md — no responsible disclosure policy",
        recommendation="Add a SECURITY.md file describing how to report vulnerabilities",
    )


def _check_https_in_api_calls(root: Path) -> StandardsFinding:
    http_in_code = False
    for py_file in list(root.glob("**/*.py"))[:100]:
        if any(part in {".git", "venv", ".venv", "__pycache__"} for part in py_file.parts):
            continue
        try:
            text = py_file.read_text(encoding="utf-8", errors="ignore")
            if re.search(
                r"requests\.\w+\s*\(\s*['\"]http://(?!localhost|127\.0\.0\.1)",
                text,
            ):
                http_in_code = True
                break
        except Exception:
            pass

    return StandardsFinding(
        check_id="STD014",
        check_name="HTTPS used for external API calls",
        passed=not http_in_code,
        severity=Severity.MEDIUM,
        description="External API calls use HTTPS" if not http_in_code else "Plain HTTP found in external API requests — data transmitted unencrypted",
        recommendation="Use HTTPS for all external HTTP requests",
    )


def _check_no_print_sensitive(root: Path) -> StandardsFinding:
    found = False
    pattern = re.compile(
        r"(?i)(?:print|logger?\.\w+|console\.log)\s*\(.*(?:password|secret|token|key|credential)",
    )
    for src_file in list(root.glob("**/*.py"))[:100] + list(root.glob("**/*.js"))[:100]:
        if any(part in {".git", "node_modules", "venv", "__pycache__"} for part in src_file.parts):
            continue
        try:
            if pattern.search(src_file.read_text(encoding="utf-8", errors="ignore")):
                found = True
                break
        except Exception:
            pass

    return StandardsFinding(
        check_id="STD015",
        check_name="Secrets not logged",
        passed=not found,
        severity=Severity.HIGH,
        description="No secret logging detected" if not found else "Potential logging of secrets or credentials detected",
        recommendation="Never log passwords, tokens, or API keys; scrub sensitive data before logging",
    )
