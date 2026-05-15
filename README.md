# ALNUR

**Open-Source End-to-End Vulnerability Scanner**

ALNUR is an open-source, end-to-end security vulnerability scanner for application projects. Point it at any project directory and it acts as your security analyst — detecting CVEs in dependencies, leaked secrets, architecture flaws, standards violations, and risky port configurations.

---

## Features

| Module | What It Checks |
|---|---|
| **CVE Scanner** | Queries OSV.dev for known CVEs across all detected packages |
| **Secret Detection** | Finds hardcoded API keys, tokens, passwords, and private keys using patterns + entropy analysis |
| **Architecture Analysis** | 30+ SAST rules covering injection, weak crypto, insecure deserialization, misconfigurations |
| **Standards Compliance** | Gitignore hygiene, lockfile presence, CI/CD, test suite, Docker best practices |
| **Port Risk Analysis** | Flags dangerous ports in Dockerfiles, docker-compose, config files, and `.env` |

## Supported Project Types

Node.js · React · Vue.js · Next.js · Express.js · Python · Django · Flask · FastAPI · PHP · Laravel · Symfony · Ruby · Ruby on Rails · Go · Rust · Java (Maven/Gradle) · Spring Boot · .NET

## Installation

```bash
pip install alnur
```

Or install from source:

```bash
git clone https://github.com/threads-beams/alnur
cd alnur
pip install -e .
```

## Quick Start

```bash
# Scan current directory
alnur scan .

# Scan a specific path
alnur scan /path/to/my-project

# Generate HTML report
alnur scan . --output html --output-file report.html

# Generate all formats
alnur scan . --output all --output-file report

# Show only high+ severity issues
alnur scan . --severity high

# Detect project type only (fast)
alnur detect .
```

## CLI Reference

```
alnur scan [PATH] [OPTIONS]

Options:
  -o, --output [console|json|html|all]   Output format (default: console)
  -f, --output-file PATH                 Write report to file
  -s, --severity [critical|high|medium|low|info]  Minimum severity (default: low)
  --skip-cve                             Skip CVE check
  --skip-secrets                         Skip secret detection
  --skip-arch                            Skip architecture analysis
  --skip-standards                       Skip standards compliance
  --skip-ports                           Skip port risk analysis
  --no-dev                               Exclude dev dependencies
  -v, --verbose                          Show recommendations inline
  -q, --quiet                            Suppress progress output
```

## Risk Grading

| Grade | Score | Meaning |
|---|---|---|
| A | 0–19 | Low risk — keep it up |
| B | 20–49 | Minor issues — review low-priority findings |
| C | 50–99 | Moderate risk — address before production |
| D | 100–199 | High risk — urgent remediation needed |
| F | 200+ | Critical — do not deploy |

## Output Formats

- **Console** — Rich colored terminal output with tables and severity badges
- **JSON** — Machine-readable structured report (CI/CD integration)
- **HTML** — Self-contained dark-theme security dashboard, no external dependencies

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed — no critical/high issues |
| `1` | Critical or high severity issues found |

## CVE Data Source

ALNUR uses the [OSV.dev](https://osv.dev) API — a free, open vulnerability database covering npm, PyPI, Maven, NuGet, RubyGems, crates.io, Packagist, Go modules, and more. No API key required.

## Architecture Rules (Sample)

| Rule | Category | Severity |
|---|---|---|
| `INJ001–009` | SQL / Command Injection | HIGH/CRITICAL |
| `DESER001–003` | Insecure Deserialization | HIGH |
| `CRYPTO001–004` | Weak Cryptography | MEDIUM/HIGH |
| `TLS001–004` | SSL/TLS Misconfiguration | MEDIUM/HIGH |
| `DJANGO001–005` | Django Misconfiguration | MEDIUM/HIGH |
| `FLASK001–003` | Flask Misconfiguration | MEDIUM/HIGH |
| `NODE001–004` | Node.js Misconfiguration | MEDIUM/HIGH |
| `DOCKER001–003` | Container Security | MEDIUM/HIGH |
| `XSS001–002` | Cross-Site Scripting | HIGH |
| `PATH001–002` | Path Traversal | HIGH |

## Contributing

Contributions are welcome. To add a new architecture rule, add an entry to `_RULES` in `alnur/analyzers/architecture.py`. To add a new secret pattern, add to `_PATTERNS` in `alnur/analyzers/secrets.py`.

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE)

---

*ALNUR — illuminating what's hidden in your codebase.*
