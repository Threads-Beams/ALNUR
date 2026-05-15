"""Extract packages and their versions from every common lockfile and manifest."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Tuple

from alnur.core.models import Package

# Directories to never descend into
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".mypy_cache",
    "venv", ".venv", "env", ".env", "virtualenv",
    "dist", "build", ".tox", ".pytest_cache",
    "vendor", "target", "bin", "obj", ".idea", ".vscode",
    "coverage", ".coverage", "htmlcov",
})


def extract(root: Path, include_dev: bool = True) -> List[Package]:
    packages: List[Package] = []

    packages.extend(_parse_package_lock(root))
    packages.extend(_parse_yarn_lock(root))
    packages.extend(_parse_pnpm_lock(root))
    if not packages:
        packages.extend(_parse_package_json(root, include_dev))

    packages.extend(_parse_pipfile_lock(root, include_dev))
    if not any(p.ecosystem == "PyPI" for p in packages):
        packages.extend(_parse_poetry_lock(root))
    if not any(p.ecosystem == "PyPI" for p in packages):
        packages.extend(_parse_requirements(root, include_dev))
    if not any(p.ecosystem == "PyPI" for p in packages):
        packages.extend(_parse_pyproject_toml(root, include_dev))

    packages.extend(_parse_composer_lock(root, include_dev))
    if not any(p.ecosystem == "Packagist" for p in packages):
        packages.extend(_parse_composer_json(root, include_dev))

    packages.extend(_parse_gemfile_lock(root))

    packages.extend(_parse_go_mod(root))

    packages.extend(_parse_cargo_lock(root))
    if not any(p.ecosystem == "crates.io" for p in packages):
        packages.extend(_parse_cargo_toml(root, include_dev))

    packages.extend(_parse_pom_xml(root))
    packages.extend(_parse_build_gradle(root))

    packages.extend(_parse_csproj(root))
    packages.extend(_parse_packages_config(root))

    return _deduplicate(packages)


# ── npm / Node.js ─────────────────────────────────────────────────────────────

def _parse_package_json(root: Path, include_dev: bool) -> List[Package]:
    path = root / "package.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    for name, spec in data.get("dependencies", {}).items():
        ver = _npm_version(spec)
        if ver:
            pkgs.append(Package(name, ver, "npm", False, str(path)))
    if include_dev:
        for name, spec in data.get("devDependencies", {}).items():
            ver = _npm_version(spec)
            if ver:
                pkgs.append(Package(name, ver, "npm", True, str(path)))
    return pkgs


def _parse_package_lock(root: Path) -> List[Package]:
    path = root / "package-lock.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    lock_version = data.get("lockfileVersion", 1)
    if lock_version >= 2 and "packages" in data:
        for pkg_path, meta in data["packages"].items():
            if not pkg_path or pkg_path == "":
                continue
            name = meta.get("name") or pkg_path.split("node_modules/")[-1]
            version = meta.get("version", "")
            if name and version:
                is_dev = meta.get("dev", False)
                pkgs.append(Package(name, version, "npm", is_dev, str(path)))
    else:
        for name, meta in data.get("dependencies", {}).items():
            version = meta.get("version", "")
            if version:
                is_dev = meta.get("dev", False)
                pkgs.append(Package(name, version, "npm", is_dev, str(path)))
    return pkgs


def _parse_yarn_lock(root: Path) -> List[Package]:
    path = root / "yarn.lock"
    if not path.exists():
        return []
    pkgs = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        # Match blocks: "name@spec":\n  version "x.y.z"
        blocks = re.split(r"\n\n+", text)
        for block in blocks:
            header_match = re.match(r'^"?(@?[^@\s"]+)@', block)
            version_match = re.search(r'^\s+version\s+"([^"]+)"', block, re.MULTILINE)
            if header_match and version_match:
                pkgs.append(Package(
                    header_match.group(1),
                    version_match.group(1),
                    "npm",
                    False,
                    str(path),
                ))
    except Exception:
        pass
    return pkgs


def _parse_pnpm_lock(root: Path) -> List[Package]:
    path = root / "pnpm-lock.yaml"
    if not path.exists():
        return []
    pkgs = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        # Match "  /name/version:" or "  name@version:" patterns
        for match in re.finditer(
            r"^\s{2}(?:/)?(@?[a-zA-Z0-9._\-]+)[@/]([0-9][^\s:]*)",
            text,
            re.MULTILINE,
        ):
            pkgs.append(Package(match.group(1), match.group(2), "npm", False, str(path)))
    except Exception:
        pass
    return pkgs


def _npm_version(spec: str) -> Optional[str]:
    spec = spec.strip()
    if not spec or spec.startswith(("http", "git", "file:")):
        return None
    clean = spec.lstrip("^~>=<")
    if re.match(r"^\d+\.\d+", clean):
        return clean.split(" ")[0].split(",")[0]
    return None


# ── Python ────────────────────────────────────────────────────────────────────

def _parse_requirements(root: Path, include_dev: bool) -> List[Package]:
    pkgs: List[Package] = []
    req_files = list(root.glob("requirements*.txt")) + list(root.glob("requirements/*.txt"))
    for req_path in req_files:
        is_dev = "dev" in req_path.name.lower() or "test" in req_path.name.lower()
        if is_dev and not include_dev:
            continue
        try:
            for line in req_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                pkg = _parse_req_line(line)
                if pkg:
                    pkgs.append(Package(pkg[0], pkg[1], "PyPI", is_dev, str(req_path)))
        except Exception:
            pass
    return pkgs


def _parse_req_line(line: str) -> Optional[Tuple[str, str]]:
    line = line.strip()
    if not line or line.startswith(("#", "-", "http", "git+")):
        return None
    match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
    if match:
        return match.group(1).lower(), match.group(2)
    match = re.match(r"^([A-Za-z0-9_.\-]+)\s*>=?\s*([0-9][^\s,;#]*)", line)
    if match:
        return match.group(1).lower(), match.group(2)
    match = re.match(r"^([A-Za-z0-9_.\-]+)\s*[^=<>!~]", line)
    if match:
        name = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if name:
            return name.group(1).lower(), "latest"
    return None


def _parse_pipfile_lock(root: Path, include_dev: bool) -> List[Package]:
    path = root / "Pipfile.lock"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    for name, meta in data.get("default", {}).items():
        ver = meta.get("version", "").lstrip("=")
        if ver:
            pkgs.append(Package(name.lower(), ver, "PyPI", False, str(path)))
    if include_dev:
        for name, meta in data.get("develop", {}).items():
            ver = meta.get("version", "").lstrip("=")
            if ver:
                pkgs.append(Package(name.lower(), ver, "PyPI", True, str(path)))
    return pkgs


def _parse_poetry_lock(root: Path) -> List[Package]:
    path = root / "poetry.lock"
    if not path.exists():
        return []
    pkgs = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        blocks = re.split(r"\[\[package\]\]", text)[1:]
        for block in blocks:
            name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_m and ver_m:
                pkgs.append(Package(
                    name_m.group(1).lower(),
                    ver_m.group(1),
                    "PyPI",
                    False,
                    str(path),
                ))
    except Exception:
        pass
    return pkgs


def _parse_pyproject_toml(root: Path, include_dev: bool) -> List[Package]:
    path = root / "pyproject.toml"
    if not path.exists():
        return []
    try:
        import sys
        if sys.version_info >= (3, 11):
            import tomllib
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            import tomli
            data = tomli.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    pkgs = []
    # PEP 621
    for dep in data.get("project", {}).get("dependencies", []):
        if isinstance(dep, str):
            parsed = _parse_req_line(dep)
            if parsed:
                pkgs.append(Package(parsed[0], parsed[1], "PyPI", False, str(path)))
    # Poetry
    for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
        if name == "python":
            continue
        ver = spec if isinstance(spec, str) else (spec.get("version", "") if isinstance(spec, dict) else "")
        ver = ver.lstrip("^~>=<")
        if ver:
            pkgs.append(Package(name.lower(), ver, "PyPI", False, str(path)))
    if include_dev:
        dev_section = (
            data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {})
            or data.get("tool", {}).get("poetry", {}).get("group", {}).get("dev", {}).get("dependencies", {})
        )
        for name, spec in dev_section.items():
            ver = spec if isinstance(spec, str) else (spec.get("version", "") if isinstance(spec, dict) else "")
            ver = ver.lstrip("^~>=<")
            if ver:
                pkgs.append(Package(name.lower(), ver, "PyPI", True, str(path)))
    return pkgs


# ── PHP / Composer ────────────────────────────────────────────────────────────

def _parse_composer_lock(root: Path, include_dev: bool) -> List[Package]:
    path = root / "composer.lock"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    for pkg in data.get("packages", []):
        ver = pkg.get("version", "").lstrip("v")
        if pkg.get("name") and ver:
            pkgs.append(Package(pkg["name"], ver, "Packagist", False, str(path)))
    if include_dev:
        for pkg in data.get("packages-dev", []):
            ver = pkg.get("version", "").lstrip("v")
            if pkg.get("name") and ver:
                pkgs.append(Package(pkg["name"], ver, "Packagist", True, str(path)))
    return pkgs


def _parse_composer_json(root: Path, include_dev: bool) -> List[Package]:
    path = root / "composer.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    for name, spec in data.get("require", {}).items():
        if name == "php":
            continue
        ver = re.sub(r"[^0-9.]", "", spec.split("|")[0].strip())
        if ver:
            pkgs.append(Package(name, ver, "Packagist", False, str(path)))
    if include_dev:
        for name, spec in data.get("require-dev", {}).items():
            ver = re.sub(r"[^0-9.]", "", spec.split("|")[0].strip())
            if ver:
                pkgs.append(Package(name, ver, "Packagist", True, str(path)))
    return pkgs


# ── Ruby / Bundler ────────────────────────────────────────────────────────────

def _parse_gemfile_lock(root: Path) -> List[Package]:
    path = root / "Gemfile.lock"
    if not path.exists():
        return []
    pkgs = []
    try:
        in_gems = False
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip() == "GEM":
                in_gems = True
                continue
            if in_gems and line.strip() and not line.startswith(" "):
                in_gems = False
            if in_gems:
                match = re.match(r"^\s{4}([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)", line)
                if match:
                    pkgs.append(Package(
                        match.group(1),
                        match.group(2).split(",")[0].strip(),
                        "RubyGems",
                        False,
                        str(path),
                    ))
    except Exception:
        pass
    return pkgs


# ── Go ────────────────────────────────────────────────────────────────────────

def _parse_go_mod(root: Path) -> List[Package]:
    path = root / "go.mod"
    if not path.exists():
        return []
    pkgs = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        in_require = False
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                line = line.removeprefix("require ").strip()
                match = re.match(r"^([^\s]+)\s+v([^\s]+)", line)
                if match:
                    pkgs.append(Package(
                        match.group(1),
                        match.group(2),
                        "Go",
                        False,
                        str(path),
                    ))
    except Exception:
        pass
    return pkgs


# ── Rust / Cargo ──────────────────────────────────────────────────────────────

def _parse_cargo_lock(root: Path) -> List[Package]:
    path = root / "Cargo.lock"
    if not path.exists():
        return []
    pkgs = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        blocks = re.split(r"\[\[package\]\]", text)[1:]
        for block in blocks:
            name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_m and ver_m:
                pkgs.append(Package(
                    name_m.group(1),
                    ver_m.group(1),
                    "crates.io",
                    False,
                    str(path),
                ))
    except Exception:
        pass
    return pkgs


def _parse_cargo_toml(root: Path, include_dev: bool) -> List[Package]:
    path = root / "Cargo.toml"
    if not path.exists():
        return []
    try:
        import sys
        if sys.version_info >= (3, 11):
            import tomllib
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            import tomli
            data = tomli.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    pkgs = []
    for name, spec in data.get("dependencies", {}).items():
        ver = spec if isinstance(spec, str) else spec.get("version", "")
        ver = ver.lstrip("^~>=< ")
        if ver:
            pkgs.append(Package(name, ver, "crates.io", False, str(path)))
    if include_dev:
        for name, spec in data.get("dev-dependencies", {}).items():
            ver = spec if isinstance(spec, str) else spec.get("version", "")
            ver = ver.lstrip("^~>=< ")
            if ver:
                pkgs.append(Package(name, ver, "crates.io", True, str(path)))
    return pkgs


# ── Java / Maven ──────────────────────────────────────────────────────────────

def _parse_pom_xml(root: Path) -> List[Package]:
    pkgs = []
    for pom_path in root.rglob("pom.xml"):
        if any(part in _SKIP_DIRS for part in pom_path.parts):
            continue
        try:
            tree = ET.parse(str(pom_path))
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            root_el = tree.getroot()
            ns_prefix = root_el.tag.split("}")[0].lstrip("{") if "}" in root_el.tag else ""
            ns_map = {("m" if ns_prefix else ""): ns_prefix} if ns_prefix else {}

            def find_text(el, tag: str) -> str:
                child = el.find(f"{{{ns_prefix}}}{tag}" if ns_prefix else tag)
                return (child.text or "").strip() if child is not None else ""

            for dep in root_el.iter(f"{{{ns_prefix}}}dependency" if ns_prefix else "dependency"):
                group = find_text(dep, "groupId")
                artifact = find_text(dep, "artifactId")
                version = find_text(dep, "version")
                if artifact and version and not version.startswith("$"):
                    name = f"{group}:{artifact}" if group else artifact
                    pkgs.append(Package(name, version, "Maven", False, str(pom_path)))
        except Exception:
            pass
    return pkgs


# ── Java / Gradle ─────────────────────────────────────────────────────────────

def _parse_build_gradle(root: Path) -> List[Package]:
    pkgs = []
    for grad_path in list(root.rglob("build.gradle")) + list(root.rglob("build.gradle.kts")):
        if any(part in _SKIP_DIRS for part in grad_path.parts):
            continue
        try:
            text = grad_path.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(
                r"""(?:implementation|api|compile|testImplementation|runtimeOnly)\s*[("']([^:"'\s]+):([^:"'\s]+):([^"'\s)]+)""",
                text,
            ):
                group, artifact, version = match.group(1), match.group(2), match.group(3)
                if not version.startswith("$"):
                    name = f"{group}:{artifact}"
                    pkgs.append(Package(name, version, "Maven", False, str(grad_path)))
        except Exception:
            pass
    return pkgs


# ── .NET / NuGet ──────────────────────────────────────────────────────────────

def _parse_csproj(root: Path) -> List[Package]:
    pkgs = []
    for csproj in list(root.rglob("*.csproj")) + list(root.rglob("*.fsproj")):
        if any(part in _SKIP_DIRS for part in csproj.parts):
            continue
        try:
            tree = ET.parse(str(csproj))
            for ref in tree.getroot().iter("PackageReference"):
                name = ref.get("Include", "")
                version = ref.get("Version", "")
                if not version:
                    ver_el = ref.find("Version")
                    version = ver_el.text.strip() if ver_el is not None and ver_el.text else ""
                if name and version:
                    pkgs.append(Package(name, version, "NuGet", False, str(csproj)))
        except Exception:
            pass
    return pkgs


def _parse_packages_config(root: Path) -> List[Package]:
    pkgs = []
    for pc in root.rglob("packages.config"):
        if any(part in _SKIP_DIRS for part in pc.parts):
            continue
        try:
            tree = ET.parse(str(pc))
            for pkg in tree.getroot().iter("package"):
                name = pkg.get("id", "")
                version = pkg.get("version", "")
                if name and version:
                    pkgs.append(Package(name, version, "NuGet", False, str(pc)))
        except Exception:
            pass
    return pkgs


# ── Helpers ───────────────────────────────────────────────────────────────────

def _deduplicate(packages: List[Package]) -> List[Package]:
    seen: dict = {}
    for pkg in packages:
        key = (pkg.name.lower(), pkg.ecosystem)
        if key not in seen:
            seen[key] = pkg
    return list(seen.values())
