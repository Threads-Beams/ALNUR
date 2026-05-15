from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW

    def __lt__(self, other: "Severity") -> bool:
        return self.weight < other.weight

    def __le__(self, other: "Severity") -> bool:
        return self.weight <= other.weight


class ProjectType(str, Enum):
    NODEJS = "Node.js"
    REACT = "React"
    VUE = "Vue.js"
    NEXTJS = "Next.js"
    NUXT = "Nuxt.js"
    EXPRESS = "Express.js"
    PYTHON = "Python"
    DJANGO = "Django"
    FLASK = "Flask"
    FASTAPI = "FastAPI"
    DOTNET = ".NET"
    LARAVEL = "Laravel"
    PHP = "PHP"
    SYMFONY = "Symfony"
    RUBY = "Ruby"
    RAILS = "Ruby on Rails"
    GO = "Go"
    RUST = "Rust"
    JAVA_MAVEN = "Java (Maven)"
    JAVA_GRADLE = "Java (Gradle)"
    SPRING = "Spring Boot"
    UNKNOWN = "Unknown"


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str
    is_dev: bool = False
    source_file: str = ""


@dataclass
class Vulnerability:
    id: str
    package: str
    version: str
    ecosystem: str
    severity: Severity
    summary: str
    details: str
    fixed_versions: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    aliases: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published: str = ""
    is_dev: bool = False


@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    secret_type: str
    severity: Severity
    description: str
    match_preview: str = ""


@dataclass
class ArchitectureFinding:
    rule_id: str
    category: str
    severity: Severity
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    recommendation: str = ""
    cwe: Optional[str] = None


@dataclass
class StandardsFinding:
    check_id: str
    check_name: str
    passed: bool
    severity: Severity
    description: str
    recommendation: str = ""


@dataclass
class PortFinding:
    source_file: str
    port: int
    service: str
    protocol: str
    risk: Severity
    description: str
    recommendation: str = ""
    binding: str = ""


@dataclass
class ScanConfig:
    min_severity: Severity = Severity.LOW
    skip_cve: bool = False
    skip_secrets: bool = False
    skip_architecture: bool = False
    skip_standards: bool = False
    skip_ports: bool = False
    include_dev_deps: bool = True
    max_file_size_bytes: int = 1_048_576


@dataclass
class ScanResult:
    target_path: str
    project_types: List[ProjectType] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    secrets: List[SecretFinding] = field(default_factory=list)
    architecture_findings: List[ArchitectureFinding] = field(default_factory=list)
    standards_findings: List[StandardsFinding] = field(default_factory=list)
    port_findings: List[PortFinding] = field(default_factory=list)
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @property
    def total_issues(self) -> int:
        return (
            len(self.vulnerabilities)
            + len(self.secrets)
            + len(self.architecture_findings)
            + sum(1 for f in self.standards_findings if not f.passed)
            + len(self.port_findings)
        )

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 40,
            Severity.MEDIUM: 10,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        score = 0
        for v in self.vulnerabilities:
            score += weights.get(v.severity, 0)
        for s in self.secrets:
            score += weights.get(s.severity, 0)
        for a in self.architecture_findings:
            score += weights.get(a.severity, 0)
        for p in self.port_findings:
            score += weights.get(p.risk, 0)
        return min(score, 1000)

    @property
    def risk_grade(self) -> str:
        score = self.risk_score
        if score >= 200:
            return "F"
        if score >= 100:
            return "D"
        if score >= 50:
            return "C"
        if score >= 20:
            return "B"
        return "A"

    @property
    def standards_pass_rate(self) -> float:
        if not self.standards_findings:
            return 100.0
        passed = sum(1 for f in self.standards_findings if f.passed)
        return round((passed / len(self.standards_findings)) * 100, 1)
