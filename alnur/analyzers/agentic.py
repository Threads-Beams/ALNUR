"""
Detect security risks specific to agentic AI applications.

Threat models covered:
  1. Secrets/credentials leaked into agent context (system prompts, tool configs, memory)
  2. Overly permissive tools (shell, REPL, filesystem write, unrestricted SQL)
  3. Unauthenticated agent endpoints — AI becomes an auth bypass
  4. Exfiltration combos — agent has both DB/internal access AND outbound tools
  5. Prompt injection surfaces — user input injected into system prompts
  6. MCP server misconfigurations — filesystem root access, admin DB credentials
  7. Missing human-in-the-loop for destructive operations
  8. Insecure agent memory — conversations stored with embedded secrets
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

from alnur.core.models import ArchitectureFinding, Severity

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".mypy_cache",
    "venv", ".venv", "env", "virtualenv",
    "dist", "build", ".tox", ".pytest_cache",
    "vendor", "target", ".idea", ".vscode",
})

_MAX_FILE_BYTES = 1_048_576

# ── Known agentic AI framework import patterns ────────────────────────────────
_FRAMEWORK_IMPORTS = re.compile(
    r"(?:from|import)\s+(?:langchain|crewai|autogen|pyautogen|llama_index|"
    r"llama-index|haystack|semantic_kernel|openai|anthropic|google\.adk|"
    r"agentops|phidata|pydantic_ai|smolagents|langraph|langgraph|"
    r"langchain_community|langchain_openai|langchain_anthropic|"
    r"langchain_google|openai_agents)"
)

# ── Rule definition ───────────────────────────────────────────────────────────
@dataclass
class AgentRule:
    id: str
    category: str
    severity: Severity
    pattern: re.Pattern
    description: str
    recommendation: str
    file_globs: Tuple[str, ...]
    attack_vector: str
    cwe: Optional[str] = None
    negative: Optional[re.Pattern] = None


def _rule(
    rule_id: str,
    category: str,
    severity: str,
    pattern: str,
    description: str,
    recommendation: str,
    globs: Tuple[str, ...],
    attack_vector: str,
    cwe: Optional[str] = None,
    negative: Optional[str] = None,
) -> AgentRule:
    return AgentRule(
        id=rule_id,
        category=category,
        severity=Severity(severity),
        pattern=re.compile(pattern, re.MULTILINE | re.IGNORECASE),
        description=description,
        recommendation=recommendation,
        file_globs=globs,
        attack_vector=attack_vector,
        cwe=cwe,
        negative=re.compile(negative, re.IGNORECASE) if negative else None,
    )


_ALL_SRC = ("*.py", "*.js", "*.ts", "*.mjs")
_PY = ("*.py",)
_JS = ("*.js", "*.ts", "*.mjs")
_JSON = ("*.json",)
_YAML = ("*.yml", "*.yaml")
_ALL = ("*.py", "*.js", "*.ts", "*.json", "*.yml", "*.yaml", "*.mjs")

_RULES: List[AgentRule] = [

    # ── Secrets in agent context ──────────────────────────────────────────────

    _rule(
        "AGENT001", "Secret Exposure", "CRITICAL",
        r"(?:system_prompt|system_message|instructions)\s*[=:]\s*[f\"'].*"
        r"(?:password|api_key|secret|token|credential|private_key)",
        "Credentials or secrets embedded in agent system prompt — the LLM sees and may leak them",
        "Never put secrets in system prompts. Pass them via secure tool configurations outside the context window",
        _PY, "LLM leaks secrets through conversation or tool calls", "CWE-312",
    ),
    _rule(
        "AGENT002", "Secret Exposure", "HIGH",
        r"(?:ChatOpenAI|OpenAI|AzureChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|"
        r"Anthropic|Bedrock)\s*\([^)]*(?:api_key|openai_api_key|anthropic_api_key)"
        r"\s*=\s*['\"][^'\"]{10,}['\"]",
        "Hardcoded API key passed directly to LLM constructor",
        "Use environment variables: ChatOpenAI(api_key=os.environ['OPENAI_API_KEY'])",  # alnur: ignore
        _PY, "Exposed AI provider credentials", "CWE-798",
    ),
    _rule(
        "AGENT003", "Secret Exposure", "HIGH",
        r"(?:ConversationBufferMemory|ConversationSummaryMemory|"
        r"ConversationBufferWindowMemory|ChatMessageHistory)\s*\(",
        "Unbounded conversation memory — if secrets appear in conversation they are stored in plaintext",
        "Audit what enters agent memory; use ConversationSummaryMemory with sensitive data scrubbing",
        _PY, "Secrets persisted in agent memory store", "CWE-312",
    ),
    _rule(
        "AGENT004", "Secret Exposure", "HIGH",
        r"(?:agent|chain|llm)\.(?:run|invoke|call|chat)\s*\([^)]*"
        r"(?:password|secret|token|api_key|credential)",
        "Sensitive keyword passed as input to agent invocation — enters the LLM context",
        "Strip or mask sensitive values before passing data to any LLM invocation",
        _PY, "Credentials ingested into LLM context window", "CWE-312",
    ),

    # ── Prompt injection ──────────────────────────────────────────────────────

    _rule(
        "AGENT005", "Prompt Injection", "CRITICAL",
        r"(?:system_prompt|system_message|instructions|prompt)\s*[=:+]\s*"
        r"(?:[^#\n]*\+\s*(?:request\.|req\.|user_input|body\.|params\.|query\.)|"
        r"f['\"].*\{(?:request|req|user_input|body|params|query|message|text))",
        "User-controlled input concatenated into agent system prompt — prompt injection attack surface",
        "Never inject user input into system prompts. Validate and sanitize all user data before "
        "passing it as human message only, never as system context",
        _PY, "Attacker rewrites agent instructions via crafted input", "CWE-94",
    ),
    _rule(
        "AGENT006", "Prompt Injection", "HIGH",
        r"(?:HumanMessage|SystemMessage|AIMessage)\s*\(\s*content\s*=\s*"
        r"(?:f['\"].*\{(?:request|req|user|body|input|message|text)|[^)]*\+\s*(?:request|req|user))",
        "User input directly injected into LangChain message object without sanitization",
        "Treat user input as untrusted data; apply input validation before constructing messages",
        _PY, "Prompt injection via message construction", "CWE-94",
    ),
    _rule(
        "AGENT007", "Prompt Injection", "MEDIUM",
        r"tool_call\s*=\s*(?:eval|exec)\s*\(.*(?:output|result|response|content)",
        "Agent output passed to eval/exec — prompt injection can achieve remote code execution",
        "Never execute LLM output. Validate tool call names against a strict whitelist",
        _PY, "Prompt injection escalates to RCE via eval", "CWE-94",
    ),

    # ── Excessive tool permissions ────────────────────────────────────────────

    _rule(
        "AGENT008", "Excessive Permissions", "CRITICAL",
        r"(?:ShellTool|BashProcess|BashTool|Terminal)\s*\(",
        "Agent has unrestricted shell/bash execution tool — any command can be run on the host",
        "Remove shell tools from production agents. Use purpose-built tools with strict input validation",
        _PY, "Attacker achieves host RCE via prompt injection into shell tool", "CWE-78",
    ),
    _rule(
        "AGENT009", "Excessive Permissions", "CRITICAL",
        r"(?:PythonREPLTool|PythonAstREPLTool|CodeInterpreter|E2BCodeInterpreter)\s*\(",
        "Agent has Python REPL/code execution tool — arbitrary code execution on host",
        "Run code execution tools in isolated sandboxes (containers, E2B) with no network or filesystem access",
        _PY, "Attacker executes arbitrary Python on host via crafted prompt", "CWE-94",
    ),
    _rule(
        "AGENT010", "Excessive Permissions", "HIGH",
        r"(?:WriteFileTool|FileWriteTool|write_file)\s*\(",
        "Agent has filesystem write tool — can overwrite any file the process has access to",
        "Restrict write access to specific sandboxed directories; never allow write to system paths",
        _PY, "Agent overwrites configuration or code files", "CWE-732",
    ),
    _rule(
        "AGENT011", "Excessive Permissions", "HIGH",
        r"(?:SQLDatabaseToolkit|SQLDatabase\.from_uri|create_sql_agent)\s*\([^)]*"
        r"(?:postgresql|mysql|sqlite|mssql|oracle|mongodb)",
        "Agent has direct database access via SQL toolkit — can read or modify entire database",
        "Use read-only database credentials for AI agents; restrict to specific tables; "
        "never give agents write/delete/drop permissions",
        _PY, "Agent reads or destroys entire database contents without authentication", "CWE-89",
    ),
    _rule(
        "AGENT012", "Excessive Permissions", "HIGH",
        r"(?:GmailToolkit|GmailSendMessage|SendGridAPIWrapper|TwilioAPIWrapper|"
        r"SlackToolkit|DiscordTool|TelegramBotTool)\s*\(",
        "Agent has messaging/email sending capability — can send arbitrary messages to anyone",
        "Require human approval for all outbound communications; restrict recipient whitelist",
        _PY, "Agent used for spam, phishing, or social engineering at scale", "CWE-20",
    ),
    _rule(
        "AGENT013", "Excessive Permissions", "MEDIUM",
        r"allow_dangerous_requests\s*=\s*True",
        "Agent tool configured with allow_dangerous_requests=True — bypasses safety checks",
        "Remove this flag; implement proper input validation instead of disabling safety checks",
        _PY, "Safety guardrails disabled — agent makes unvalidated external requests",
    ),
    _rule(
        "AGENT014", "Excessive Permissions", "MEDIUM",
        r"(?:ReadFileTool|FileReadTool)\s*\(\s*\)",
        "Agent has unrestricted filesystem read tool — can read any file including secrets and keys",
        "Restrict readable paths to a specific allowed directory; exclude .env, *.pem, *.key",
        _PY, "Agent reads /etc/passwd, .env, private keys, or other sensitive files",
    ),

    # ── Unauthenticated agent endpoints ──────────────────────────────────────

    _rule(
        "AGENT015", "Missing Authentication", "CRITICAL",
        r"@(?:app|router)\.(?:post|get|route)\s*\(['\"](?:/agent|/chat|/ask|/run|/invoke|/query)['\"]",
        "AI agent endpoint exposed without visible authentication middleware",
        "Add authentication to all agent endpoints; rate limit to prevent abuse and cost attacks",
        _PY, "Anyone can query the agent — data exfiltration or unauthorized actions", "CWE-306",
    ),
    _rule(
        "AGENT016", "Missing Authentication", "HIGH",
        r"(?:AgentExecutor|ConversationalAgent|OpenAIFunctionsAgent|"
        r"ReActAgent|ZeroShotAgent)\.from_agent_and_tools\s*\(",
        "Agent executor created — verify it is only accessible through authenticated routes",
        "Wrap all agent executor calls behind authentication and authorization checks",
        _PY, "Unauthenticated users invoke agent with full tool access",
    ),

    # ── Data exfiltration risk ────────────────────────────────────────────────

    _rule(
        "AGENT017", "Data Exfiltration Risk", "CRITICAL",
        r"(?:SQLDatabaseToolkit|create_sql_agent|MongoDBAtlasVectorSearch|"
        r"PineconeVectorStore|WeaviateVectorStore|ChromaVectorStore)[^#\n]*\n"
        r"(?:.*\n){0,20}(?:RequestsTool|BrowsingTool|WebBrowser|HttpxClient|"
        r"requests\.(?:get|post)|httpx\.(?:get|post)|aiohttp)",
        "Agent has both internal database access AND outbound HTTP capability in the same scope — "
        "data exfiltration path exists",
        "Separate agents by responsibility: one agent reads data, a separate human-approved step "
        "sends it externally. Never combine internal DB access with unrestricted HTTP in one agent",
        _PY, "Agent autonomously reads database and sends contents to external attacker-controlled URL",
        "CWE-200",
    ),
    _rule(
        "AGENT018", "Data Exfiltration Risk", "HIGH",
        r"(?:WebBrowser|BrowsingTool|RequestsTool|DuckDuckGoSearchRun|"
        r"SerpAPIWrapper|TavilySearchResults)\s*\(",
        "Agent has internet browsing or search tool — can be used to exfiltrate data to external URLs",
        "Monitor all outbound agent requests; log destinations; block requests to non-whitelisted domains",
        _PY, "Agent sends internal data to attacker-controlled search queries or URLs",
    ),

    # ── MCP server misconfigurations ──────────────────────────────────────────

    _rule(
        "AGENT019", "MCP Misconfiguration", "CRITICAL",
        r'"(?:rootPath|allowed_paths|root)"\s*:\s*["\']/',
        "MCP filesystem server configured with root '/' — agent can read/write entire filesystem",
        "Restrict MCP filesystem server to a specific project directory, never '/'",
        ("*.json", "*.jsonc"), "Agent reads private keys, credentials, and system files via MCP",
    ),
    _rule(
        "AGENT020", "MCP Misconfiguration", "CRITICAL",
        r'"(?:connectionString|connection_string|database_url|db_url)"\s*:\s*'
        r'"(?:postgresql|mysql|mongodb|redis|sqlite)://[^"]*(?:admin|root|postgres|sa):[^"]*@',
        "MCP database server configured with admin/root credentials — agent has full database access",
        "Create a read-only, restricted-scope database user for MCP agent access",
        ("*.json", "*.jsonc", "*.yaml", "*.yml"),
        "Agent reads or destroys entire database using admin credentials via MCP", "CWE-250",
    ),
    _rule(
        "AGENT021", "MCP Misconfiguration", "HIGH",
        r'"(?:command|exec|shell)"\s*:\s*"(?:bash|sh|zsh|cmd|powershell|/bin/)',
        "MCP server configured to run shell commands — arbitrary code execution via agent",
        "Remove shell execution from MCP server configuration; use purpose-built tools",
        ("*.json", "*.jsonc"), "Agent runs arbitrary shell commands via MCP tool", "CWE-78",
    ),
    _rule(
        "AGENT022", "MCP Misconfiguration", "MEDIUM",
        r'"mcpServers"\s*:.*"env"\s*:\s*\{[^}]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)',  # alnur: ignore
        "MCP server configuration contains secret environment variables in plaintext config file",
        "Use environment variable references instead of hardcoded secrets in MCP config files",
        ("*.json", "*.jsonc"), "Secrets committed to source control via MCP config", "CWE-312",
    ),

    # ── CrewAI specific ───────────────────────────────────────────────────────

    _rule(
        "AGENT023", "Excessive Permissions", "HIGH",
        r"Agent\s*\([^)]*allow_delegation\s*=\s*True",
        "CrewAI agent has allow_delegation=True — can spawn sub-agents with its full permissions",
        "Disable delegation unless explicitly required; audit what tools delegated agents inherit",
        _PY, "Agent delegates tasks to sub-agents that bypass permission boundaries",
    ),
    _rule(
        "AGENT024", "Excessive Permissions", "HIGH",
        r"Agent\s*\([^)]*allow_code_execution\s*=\s*True",
        "CrewAI agent has allow_code_execution=True — arbitrary code execution enabled",
        "Disable code execution or run in an isolated sandbox with no network/filesystem access",
        _PY, "Agent executes arbitrary code on host system", "CWE-94",
    ),

    # ── AutoGen / multi-agent ─────────────────────────────────────────────────

    _rule(
        "AGENT025", "Excessive Permissions", "CRITICAL",
        r"(?:UserProxyAgent|AssistantAgent)\s*\([^)]*code_execution_config\s*=\s*"
        r"\{[^}]*(?:\"use_docker\"\s*:\s*false|'use_docker'\s*:\s*False)",
        "AutoGen agent executes code directly on host (use_docker=False) — arbitrary code execution",
        "Always set use_docker=True for code-executing AutoGen agents; never execute on host",
        _PY, "Agent runs untrusted LLM-generated code directly on host", "CWE-94",
    ),
    _rule(
        "AGENT026", "Excessive Permissions", "HIGH",
        r"(?:GroupChat|GroupChatManager)\s*\([^)]*max_round\s*=\s*(?:[5-9]\d{2,}|\d{4,})",
        "AutoGen GroupChat configured with very high max_round — runaway agent loops risk",
        "Set a reasonable max_round (≤50) and implement termination conditions",
        _PY, "Unbounded agent loop burns API budget or causes runaway actions",
    ),

    # ── LlamaIndex specific ───────────────────────────────────────────────────

    _rule(
        "AGENT027", "Excessive Permissions", "HIGH",
        r"(?:OpenAIAgent|ReActAgent)\.from_tools\s*\([^)]*(?:code_exec|shell|bash|terminal)",
        "LlamaIndex agent loaded with code execution or shell tools",
        "Remove execution tools from production agents; restrict to read-only data tools",
        _PY, "Agent achieves code execution on host", "CWE-78",
    ),

    # ── OpenAI Agents SDK ─────────────────────────────────────────────────────

    _rule(
        "AGENT028", "Secret Exposure", "HIGH",
        r"Runner\.run\s*\([^)]*(?:context|kwargs)\s*[=:]\s*\{[^}]*"
        r"(?:api_key|secret|password|token|credential)",
        "Secrets passed in agent runner context — visible to all tools and the LLM",
        "Pass credentials through secure tool configuration, not through the agent runner context",
        _PY, "Secrets leak through agent context to LLM and all tools", "CWE-312",
    ),

    # ── General agentic patterns ──────────────────────────────────────────────

    _rule(
        "AGENT029", "Missing Human-in-the-Loop", "HIGH",
        r"(?:os\.remove|os\.unlink|shutil\.rmtree|DROP\s+TABLE|DELETE\s+FROM|"
        r"db\.drop_collection|collection\.delete_many)\s*\([^)]*"
        r"(?:agent|tool|result|output|response|llm)",
        "Destructive operation (delete/drop) executed with agent/LLM output — no human approval",
        "Add a human-in-the-loop confirmation step before any destructive operation triggered by AI",
        _PY, "Agent autonomously deletes data or files without human confirmation", "CWE-284",
    ),
    _rule(
        "AGENT030", "Missing Human-in-the-Loop", "MEDIUM",
        r"(?:human_input_mode|human_approval)\s*=\s*['\"]?(?:NEVER|never|false|False|0)['\"]?",
        "Human input/approval mode disabled — agent operates fully autonomously without oversight",
        "Enable human approval for high-risk operations; use TERMINATE or ALWAYS mode for sensitive tasks",
        _PY, "Agent takes irreversible actions without any human oversight",
    ),
]


def scan(root: Path, max_file_bytes: int = _MAX_FILE_BYTES) -> List[ArchitectureFinding]:
    findings: List[ArchitectureFinding] = []

    # First pass: identify which files use agentic frameworks
    agentic_files: Set[Path] = set()
    for path in _iter_files(root, max_file_bytes):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if _FRAMEWORK_IMPORTS.search(text):
                agentic_files.add(path)
        except Exception:
            pass

    # Second pass: scan all files for rules (some rules apply to config files too)
    for path in _iter_files(root, max_file_bytes):
        # For .py files, only deep-scan if agentic framework is used or rules are config-level
        is_config = any(path.name.endswith(ext) for ext in (".json", ".jsonc", ".yaml", ".yml"))
        if not is_config and path not in agentic_files:
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        lines = text.splitlines()
        applicable = [r for r in _RULES if _matches_globs(path, r.file_globs)]

        for rule in applicable:
            for match in rule.pattern.finditer(text):
                if rule.negative and rule.negative.search(match.group(0)):
                    continue
                lineno = text[: match.start()].count("\n") + 1
                if lineno <= len(lines) and "# alnur: ignore" in lines[lineno - 1]:
                    continue
                findings.append(ArchitectureFinding(
                    rule_id=rule.id,
                    category=f"Agentic AI · {rule.category}",
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
        if path.name.endswith((".png", ".jpg", ".gif", ".ico", ".woff",
                               ".ttf", ".zip", ".tar", ".gz", ".exe",
                               ".dll", ".pyc", ".lock")):
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
