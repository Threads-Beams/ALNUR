from __future__ import annotations

import json
from pathlib import Path
from typing import List

from alnur.core.models import ProjectType


def detect(root: Path) -> List[ProjectType]:
    found: List[ProjectType] = []

    def has(*files: str) -> bool:
        return any((root / f).exists() for f in files)

    def read_json(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return {}

    def file_contains(path: Path, *patterns: str) -> bool:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            return any(p.lower() in text for p in patterns)
        except Exception:
            return False

    # ── Python family ────────────────────────────────────────────────────────
    is_python = has(
        "requirements.txt", "Pipfile", "pyproject.toml",
        "setup.py", "setup.cfg", "poetry.lock",
    )
    if is_python:
        # Check for framework-specific markers
        if has("manage.py") or _has_django_settings(root):
            found.append(ProjectType.DJANGO)
        elif _has_flask(root):
            found.append(ProjectType.FLASK)
        elif _has_fastapi(root):
            found.append(ProjectType.FASTAPI)
        else:
            found.append(ProjectType.PYTHON)

    # ── Node.js family ───────────────────────────────────────────────────────
    pkg_json_path = root / "package.json"
    if pkg_json_path.exists():
        pkg = read_json(pkg_json_path)
        deps = {
            **pkg.get("dependencies", {}),
            **pkg.get("devDependencies", {}),
        }
        dep_names = set(deps.keys())

        if "next" in dep_names:
            found.append(ProjectType.NEXTJS)
        elif "nuxt" in dep_names or "@nuxt/core" in dep_names:
            found.append(ProjectType.NUXT)
        elif "react" in dep_names or "react-dom" in dep_names:
            found.append(ProjectType.REACT)
        elif "vue" in dep_names or "@vue/core" in dep_names:
            found.append(ProjectType.VUE)
        elif "express" in dep_names:
            found.append(ProjectType.EXPRESS)
        else:
            found.append(ProjectType.NODEJS)

    # ── PHP family ───────────────────────────────────────────────────────────
    composer_path = root / "composer.json"
    if composer_path.exists():
        comp = read_json(composer_path)
        all_require = {
            **comp.get("require", {}),
            **comp.get("require-dev", {}),
        }
        if "laravel/framework" in all_require or (root / "artisan").exists():
            found.append(ProjectType.LARAVEL)
        elif "symfony/framework-bundle" in all_require:
            found.append(ProjectType.SYMFONY)
        else:
            found.append(ProjectType.PHP)

    # ── .NET ────────────────────────────────────────────────────────────────
    csproj_files = list(root.glob("**/*.csproj")) + list(root.glob("**/*.fsproj"))
    if csproj_files or has("*.sln"):
        found.append(ProjectType.DOTNET)

    # ── Ruby family ──────────────────────────────────────────────────────────
    if has("Gemfile"):
        gemfile = root / "Gemfile"
        if file_contains(gemfile, "rails"):
            found.append(ProjectType.RAILS)
        else:
            found.append(ProjectType.RUBY)

    # ── Go ───────────────────────────────────────────────────────────────────
    if has("go.mod"):
        found.append(ProjectType.GO)

    # ── Rust ─────────────────────────────────────────────────────────────────
    if has("Cargo.toml"):
        found.append(ProjectType.RUST)

    # ── Java ─────────────────────────────────────────────────────────────────
    if has("pom.xml"):
        pom = (root / "pom.xml").read_text(encoding="utf-8", errors="ignore")
        if "spring-boot" in pom:
            found.append(ProjectType.SPRING)
        else:
            found.append(ProjectType.JAVA_MAVEN)

    if has("build.gradle", "build.gradle.kts"):
        build = ""
        for name in ("build.gradle", "build.gradle.kts"):
            p = root / name
            if p.exists():
                build += p.read_text(encoding="utf-8", errors="ignore")
        if "spring-boot" in build:
            found.append(ProjectType.SPRING)
        elif ProjectType.JAVA_MAVEN not in found and ProjectType.SPRING not in found:
            found.append(ProjectType.JAVA_GRADLE)

    if not found:
        found.append(ProjectType.UNKNOWN)

    return found


def _has_django_settings(root: Path) -> bool:
    for candidate in root.rglob("settings.py"):
        text = candidate.read_text(encoding="utf-8", errors="ignore")
        if "INSTALLED_APPS" in text or "DATABASES" in text:
            return True
    return False


def _has_flask(root: Path) -> bool:
    for candidate in [
        root / "requirements.txt",
        root / "Pipfile",
        root / "pyproject.toml",
        root / "setup.cfg",
    ]:
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8", errors="ignore").lower()
            if "flask" in text:
                return True
    for py_file in list(root.glob("*.py"))[:20]:
        try:
            if "from flask" in py_file.read_text(encoding="utf-8", errors="ignore"):
                return True
        except Exception:
            pass
    return False


def _has_fastapi(root: Path) -> bool:
    for candidate in [
        root / "requirements.txt",
        root / "Pipfile",
        root / "pyproject.toml",
    ]:
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8", errors="ignore").lower()
            if "fastapi" in text:
                return True
    for py_file in list(root.glob("*.py"))[:20]:
        try:
            if "from fastapi" in py_file.read_text(encoding="utf-8", errors="ignore"):
                return True
        except Exception:
            pass
    return False
