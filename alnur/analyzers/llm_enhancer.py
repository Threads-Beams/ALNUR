"""
Optional LLM-enhanced security analysis.

Activated automatically when any supported provider key is found in the environment.
Returns None silently when no provider is configured — the scanner is fully
functional without it.

Supported providers (checked in priority order):
  OPENAI_API_KEY        → OpenAI          (default model: gpt-4o-mini)
  ANTHROPIC_API_KEY     → Anthropic        (default model: claude-haiku-4-5-20251001)
  GROQ_API_KEY          → Groq             (default model: llama-3.1-8b-instant)
  MISTRAL_API_KEY       → Mistral          (default model: mistral-small-latest)
  OLLAMA_HOST           → Ollama/local     (default model: llama3.2, no key needed)

Override / force a specific provider:
  ALNUR_LLM_PROVIDER    openai | anthropic | groq | mistral | ollama
  ALNUR_LLM_API_KEY     override the resolved API key
  ALNUR_LLM_MODEL       override the model name
  ALNUR_LLM_BASE_URL    override the API endpoint (useful for proxies / LiteLLM)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

import requests as _requests

from alnur.core.models import LLMInsight, ScanResult

_TIMEOUT = 30  # seconds per LLM request

# ── Provider catalogue ────────────────────────────────────────────────────────
_PROVIDERS = [
    # (name, env_key_var, default_model, base_url)
    ("openai",    "OPENAI_API_KEY",    "gpt-4o-mini",                  "https://api.openai.com/v1"),
    ("anthropic", "ANTHROPIC_API_KEY", "claude-haiku-4-5-20251001",    "https://api.anthropic.com"),  # alnur: ignore
    ("groq",      "GROQ_API_KEY",      "llama-3.1-8b-instant",         "https://api.groq.com/openai/v1"),  # alnur: ignore
    ("mistral",   "MISTRAL_API_KEY",   "mistral-small-latest",          "https://api.mistral.ai/v1"),
    ("ollama",    "",                  "llama3.2",                      ""),   # base_url resolved at runtime
]


@dataclass
class _LLMConfig:
    provider: str
    api_key: str
    model: str
    base_url: str


# ── Provider detection ────────────────────────────────────────────────────────

def detect_provider() -> Optional[_LLMConfig]:
    """
    Return the first configured LLM provider, or None if none is available.
    Environment variables ALNUR_LLM_* act as overrides.
    """
    force    = os.environ.get("ALNUR_LLM_PROVIDER", "").lower().strip()
    ovr_key  = os.environ.get("ALNUR_LLM_API_KEY",  "").strip()
    ovr_mdl  = os.environ.get("ALNUR_LLM_MODEL",    "").strip()
    ovr_url  = os.environ.get("ALNUR_LLM_BASE_URL",  "").strip()

    for name, env_var, default_model, default_url in _PROVIDERS:
        if force and force != name:
            continue

        if name == "ollama":
            # Ollama: no key needed — activate if explicitly forced or OLLAMA_HOST is set
            if force == "ollama" or os.environ.get("OLLAMA_HOST"):
                host = ovr_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
                return _LLMConfig(
                    provider="ollama",
                    api_key="ollama",  # placeholder — Ollama doesn't use Bearer auth
                    model=ovr_mdl or default_model,
                    base_url=f"{host.rstrip('/')}/v1",
                )
            continue

        api_key = ovr_key or os.environ.get(env_var, "").strip()
        if api_key:
            return _LLMConfig(
                provider=name,
                api_key=api_key,
                model=ovr_mdl or default_model,
                base_url=ovr_url or default_url,
            )

    return None


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(result: ScanResult) -> str:
    project = ", ".join(pt.value for pt in result.project_types) or "software"
    lines = [
        f"You are a senior application security engineer reviewing an automated scan of a {project} project.",
        "",
        "SCAN RESULTS:",
        f"  Risk Score : {result.risk_score}/1000  (Grade {result.risk_grade})",
        f"  CVE vulns  : {len(result.vulnerabilities)}  "
        f"({result.critical_count} critical, {result.high_count} high, "
        f"{result.medium_count} medium, {result.low_count} low)",
        f"  Secrets    : {len(result.secrets)}",
        f"  Arch issues: {len(result.architecture_findings)}",
        f"  Port risks : {len(result.port_findings)}",
        f"  Standards  : {result.standards_pass_rate:.0f}% pass rate",
        "",
    ]

    # Top CVE findings
    top_vulns = sorted(result.vulnerabilities, key=lambda v: v.severity.weight, reverse=True)[:5]
    if top_vulns:
        lines.append("TOP CVE FINDINGS:")
        for v in top_vulns:
            fix = f" → fix: {v.fixed_versions[0]}" if v.fixed_versions else ""
            lines.append(f"  [{v.severity.value}] {v.id}  {v.package}@{v.version}{fix}  — {v.summary[:90]}")
        lines.append("")

    # Top architecture / agentic issues
    top_arch = sorted(result.architecture_findings, key=lambda a: a.severity.weight, reverse=True)[:5]
    if top_arch:
        lines.append("TOP ARCHITECTURE / AGENTIC ISSUES:")
        for a in top_arch:
            loc = f"  ({a.file_path}:{a.line_number})" if a.file_path else ""
            lines.append(f"  [{a.severity.value}] {a.rule_id}  {a.description[:90]}{loc}")
        lines.append("")

    # Secrets (redacted)
    if result.secrets:
        lines.append(f"SECRET LEAKS ({len(result.secrets)} total):")
        for s in result.secrets[:3]:
            lines.append(f"  [{s.severity.value}] {s.secret_type}  in {s.file_path}:{s.line_number}")
        lines.append("")

    lines += [
        "Provide a concise security review. Respond ONLY with valid JSON — no markdown, no extra text:",
        '{',
        '  "executive_summary": "<2-3 sentences describing the overall security posture and most urgent concern>",',
        '  "priority_actions": [',
        '    "<most critical action>",',
        '    "<second action>",',
        '    "<third action>"',
        '  ],',
        '  "false_positive_notes": "<brief note on likely false positives, or empty string if none>"',
        '}',
    ]
    return "\n".join(lines)


# ── API callers ───────────────────────────────────────────────────────────────

def _call_openai_compat(cfg: _LLMConfig, prompt: str) -> str:
    """OpenAI-compatible chat completion (OpenAI, Groq, Mistral, Ollama)."""
    resp = _requests.post(
        f"{cfg.base_url}/chat/completions",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg.api_key}",
        },
        json={
            "model": cfg.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 600,
        },
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return str(resp.json()["choices"][0]["message"]["content"])


def _call_anthropic(cfg: _LLMConfig, prompt: str) -> str:
    """Anthropic Messages API."""
    resp = _requests.post(
        f"{cfg.base_url}/v1/messages",
        headers={
            "Content-Type": "application/json",
            "x-api-key": cfg.api_key,
            "anthropic-version": "2023-06-01",
        },
        json={
            "model": cfg.model,
            "max_tokens": 600,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return str(resp.json()["content"][0]["text"])


def _parse_response(raw: str) -> dict:
    """Extract JSON from the LLM response, tolerating markdown code fences."""
    text = raw.strip()
    # Strip ```json ... ``` or ``` ... ``` wrappers
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                text = part
                break
    return dict(json.loads(text))


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(result: ScanResult) -> Optional[LLMInsight]:
    """
    Run LLM-enhanced analysis on a completed ScanResult.

    Returns an LLMInsight if a provider is configured and the call succeeds.
    Returns None silently in all other cases — never raises.
    """
    cfg = detect_provider()
    if cfg is None:
        return None

    # Nothing to enhance when the project is clean
    if result.total_issues == 0:
        return None

    try:
        prompt = _build_prompt(result)

        if cfg.provider == "anthropic":
            raw = _call_anthropic(cfg, prompt)
        else:
            raw = _call_openai_compat(cfg, prompt)

        data = _parse_response(raw)
        return LLMInsight(
            provider=cfg.provider,
            model=cfg.model,
            executive_summary=str(data.get("executive_summary", "")),
            priority_actions=[str(a) for a in data.get("priority_actions", [])],
            false_positive_notes=str(data.get("false_positive_notes", "")),
        )
    except Exception:
        # LLM failure must never crash the scan
        return None
