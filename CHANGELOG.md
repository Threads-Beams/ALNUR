# Changelog

All notable changes to ALNUR are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.2] — 2026-05-25

### Added
- **Agentic AI analyzer** (`alnur/analyzers/agentic.py`) — 30 rules targeting LLM/agent-specific
  security risks: secrets leaked into system prompts, prompt injection via user-controlled inputs,
  excessive tool permissions (ShellTool, WriteFileTool, PythonREPLTool, SQLDatabaseToolkit),
  unauthenticated agent endpoints, DB + outbound HTTP exfiltration combos, MCP server
  misconfigurations (root filesystem access, admin credentials, shell commands), and missing
  human-in-the-loop guards. Supports LangChain, CrewAI, AutoGen, LlamaIndex, OpenAI Agents,
  Anthropic SDK, and more.
- **Optional LLM-enhanced analysis** (`alnur/analyzers/llm_enhancer.py`) — provider-agnostic
  post-scan AI review. Activates automatically when any supported API key is present in the
  environment; silent no-op otherwise. Providers: OpenAI (`OPENAI_API_KEY`),
  Anthropic (`ANTHROPIC_API_KEY`), Groq (`GROQ_API_KEY`), Mistral (`MISTRAL_API_KEY`),
  Ollama (`OLLAMA_HOST`). Override via `ALNUR_LLM_PROVIDER`, `ALNUR_LLM_MODEL`,
  `ALNUR_LLM_API_KEY`, `ALNUR_LLM_BASE_URL`. Produces an executive summary, top 3 priority
  actions, and false-positive notes in both console and JSON output.
- `--skip-agentic` CLI flag to opt out of agentic AI analysis.
- `--no-llm` CLI flag to suppress LLM analysis even when an API key is configured.
- `LLMInsight` dataclass in `core/models.py`; `llm_insight` field on `ScanResult`.

### Fixed
- **Severity comparison bug** — `Severity` inherits from `str`, so Python was silently using
  lexicographic `>=` (e.g. `"CRITICAL" >= "LOW"` → `False`). Added `__gt__` and `__ge__`
  with weight-based logic; this was causing HIGH/CRITICAL findings from architecture and
  agentic scans to be filtered out entirely.
- **False positives in rule-definition files** — added `# alnur: ignore` suppression on
  description/recommendation strings inside `architecture.py`, `agentic.py`, and
  `llm_enhancer.py` that contained their own detection patterns (e.g. the INJ001 rule's
  recommendation string containing `cursor.execute('SELECT …')`).

---

## [1.0.1] — 2026-05-22

### Fixed
- ASCII art logo: the `R` in ALNUR was rendering as `D` due to a block-art ambiguity; replaced
  with unambiguous box-drawing characters in both the console reporter and the landing page.
- Package metadata: corrected author name to `Habib Hussain` and homepage URL to
  `https://github.com/Threads-Beams/ALNUR` (were wrong in the initial PyPI upload).
- Bumped `requests` from `2.31.0` → `2.33.0` to resolve two real CVEs:
  GHSA-9hjg-f4h5-9r9r and GHSA-gc5v-65fq-vhfx (reported by ALNUR scanning its own
  dependencies).

---

## [1.0.0] — 2026-05-15

### Added
- Multi-language project type detection (18 types)
- Dependency extraction from 15+ lockfile and manifest formats
- CVE scanning via OSV.dev batch API (npm, PyPI, Maven, NuGet, RubyGems, crates.io, Packagist, Go)
- Secret detection with 18 named patterns + Shannon entropy analysis
- 30+ architecture SAST rules across injection, crypto, TLS, and framework misconfigurations
- 15 software engineering standards compliance checks
- Port risk analysis for Dockerfiles, docker-compose, config files, and `.env`
- Console (Rich), JSON, and HTML report output
- `alnur scan` and `alnur detect` CLI commands
- CI/CD exit code support (exits 1 on critical/high findings)
