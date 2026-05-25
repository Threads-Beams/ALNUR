# ALNUR

**Open-Source End-to-End Vulnerability Scanner**

ALNUR is an open-source, end-to-end security vulnerability scanner for application projects. Point it at any project directory and it acts as your security analyst — detecting CVEs in dependencies, leaked secrets, architecture flaws, standards violations, risky port configurations, and — uniquely — security risks in agentic AI applications.

---

## Features

| Module | What It Checks |
|---|---|
| **CVE Scanner** | Queries OSV.dev for known CVEs across all detected packages |
| **Secret Detection** | Finds hardcoded API keys, tokens, passwords, and private keys using patterns + entropy analysis |
| **Architecture Analysis** | 30+ SAST rules covering injection, weak crypto, insecure deserialization, misconfigurations |
| **Agentic AI Analysis** | 30 rules targeting LLM/agent-specific risks: prompt injection, excessive tool permissions, unauthenticated endpoints, exfiltration combos, MCP misconfigurations |
| **Standards Compliance** | Gitignore hygiene, lockfile presence, CI/CD, test suite, Docker best practices |
| **Port Risk Analysis** | Flags dangerous ports in Dockerfiles, docker-compose, config files, and `.env` |
| **LLM-Enhanced Analysis** | Optional AI-powered executive summary and remediation guidance (OpenAI / Anthropic / Groq / Mistral / Ollama) |

## Supported Project Types

Node.js · React · Vue.js · Next.js · Express.js · Python · Django · Flask · FastAPI · PHP · Laravel · Symfony · Ruby · Ruby on Rails · Go · Rust · Java (Maven/Gradle) · Spring Boot · .NET

## Installation

```bash
pip install alnur
```

Or install from source:

```bash
git clone https://github.com/Threads-Beams/ALNUR
cd ALNUR
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
  -o, --output [console|json|html|all]            Output format (default: console)
  -f, --output-file PATH                          Write report to file
  -s, --severity [critical|high|medium|low|info]  Minimum severity (default: low)
  --skip-cve                                      Skip CVE check
  --skip-secrets                                  Skip secret detection
  --skip-arch                                     Skip architecture analysis
  --skip-agentic                                  Skip agentic AI security analysis
  --skip-standards                                Skip standards compliance
  --skip-ports                                    Skip port risk analysis
  --no-llm                                        Disable LLM-enhanced analysis
  --no-dev                                        Exclude dev dependencies
  -v, --verbose                                   Show recommendations inline
  -q, --quiet                                     Suppress progress output
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

## Agentic AI Security

ALNUR automatically detects files that import LangChain, CrewAI, AutoGen, LlamaIndex, OpenAI Agents, Anthropic SDK, and other agentic frameworks, then applies 30 dedicated rules:

| Rule Range | Category | Severity |
|---|---|---|
| `AGENT001–004` | Secrets in agent context / hardcoded LLM keys | HIGH/CRITICAL |
| `AGENT005–007` | Prompt injection surfaces | CRITICAL |
| `AGENT008–014` | Excessive tool permissions (shell, filesystem, SQL, email) | HIGH/CRITICAL |
| `AGENT015–016` | Unauthenticated agent endpoints | CRITICAL |
| `AGENT017–018` | Data exfiltration combos (DB + outbound HTTP) | HIGH |
| `AGENT019–022` | MCP server misconfigurations | HIGH/CRITICAL |
| `AGENT023–030` | Missing human-in-the-loop, unsafe delegation, code execution | HIGH/CRITICAL |

## Optional LLM-Enhanced Analysis

Set any supported API key and ALNUR will automatically include an AI-generated security review at the end of each scan — no extra flags needed.

| Environment Variable | Provider | Default Model |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI | `gpt-4o-mini` |
| `ANTHROPIC_API_KEY` | Anthropic | `claude-haiku-4-5` |
| `GROQ_API_KEY` | Groq | `llama-3.1-8b-instant` |
| `MISTRAL_API_KEY` | Mistral | `mistral-small-latest` |
| `OLLAMA_HOST` | Ollama (local) | `llama3.2` |

Override any setting with environment variables:

```bash
export ALNUR_LLM_PROVIDER=anthropic    # force a specific provider
export ALNUR_LLM_MODEL=claude-sonnet-4-6  # override the model
export ALNUR_LLM_BASE_URL=http://...   # custom endpoint / proxy
```

Use `--no-llm` to disable the feature even when a key is present.

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

## Suppressing False Positives

Add `# alnur: ignore` to any line to exclude it from all scan results:

```python
API_KEY = os.environ.get("API_KEY", "default-value")  # alnur: ignore
```

## Contributing

Contributions are welcome. To add a new architecture rule, add an entry to `_RULES` in `alnur/analyzers/architecture.py`. To add a new agentic AI rule, add to `_RULES` in `alnur/analyzers/agentic.py`. To add a new secret pattern, add to `_PATTERNS` in `alnur/analyzers/secrets.py`.

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE)

---

*ALNUR — illuminating what's hidden in your codebase.*
