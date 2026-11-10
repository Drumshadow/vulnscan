"""Frontier reference arms via the subscription CLIs on the Spark: same single-shot prompt and context
budget as the local arms, no tools, no MCP, no settings, empty working directory.

claude: `claude -p` on the Max plan; ANTHROPIC_API_KEY is stripped so it can never fall back to billed API.
codex:  `codex exec` (gpt-6-astra) on the ChatGPT plan, read-only sandbox, ephemeral session.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile

from ..prompt import SYSTEM, build_user, parse_findings

BUDGET_CHARS = 90000
CLAUDE_MODEL = "claude-opus-5-5"
CODEX_MODEL = "gpt-6-astra"


def _env() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")}
    env["DISABLE_AUTOUPDATER"] = "1"
    return env


def review_claude(item: dict):
    user = build_user(item, BUDGET_CHARS)
    with tempfile.TemporaryDirectory(prefix="vs-claude-") as td:
        r = subprocess.run(
            ["claude", "-p", "--model", CLAUDE_MODEL, "--system-prompt", SYSTEM, "--tools", "",
             "--strict-mcp-config", "--setting-sources", "", "--output-format", "json"],
            input=user, capture_output=True, text=True, timeout=1800, cwd=td, env=_env())
    if r.returncode != 0:
        raise RuntimeError(f"claude rc={r.returncode}: {(r.stderr or r.stdout)[-400:]}")
    out = json.loads(r.stdout)
    if out.get("is_error"):
        raise RuntimeError(f"claude error: {str(out.get('result'))[:400]}")
    usage = out.get("usage") or {}
    text = out.get("result") or ""
    return parse_findings(text), {"tokens_in": usage.get("input_tokens"), "tokens_out": usage.get("output_tokens"),
                                  "raw": text[:20000]}


def review_codex(item: dict):
    prompt = SYSTEM + "\n\n" + build_user(item, BUDGET_CHARS)
    with tempfile.TemporaryDirectory(prefix="vs-codex-") as td:
        r = subprocess.run(
            ["codex", "exec", "--json", "-m", CODEX_MODEL, "--sandbox", "read-only", "--skip-git-repo-check",
             "--ephemeral", "-"],
            input=prompt, capture_output=True, text=True, timeout=1800, cwd=td, env=_env())
    text, usage = "", {}
    for line in r.stdout.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        item_ = ev.get("item") or {}
        if ev.get("type") == "item.completed" and item_.get("type") == "agent_message":
            text = item_.get("text") or text
        if ev.get("type") == "turn.completed":
            usage = ev.get("usage") or usage
        if ev.get("type") in ("error", "turn.failed"):
            raise RuntimeError(f"codex {ev.get('type')}: {json.dumps(ev)[:400]}")
    if not text:
        raise RuntimeError(f"codex rc={r.returncode}, no agent message: {(r.stderr or r.stdout)[-400:]}")
    return parse_findings(text), {"tokens_in": usage.get("input_tokens"), "tokens_out": usage.get("output_tokens"),
                                  "raw": text[:20000]}


CONFIGS = {
    "claude": {"tool": "claude-cli-single-shot", "model": CLAUDE_MODEL, "budget_chars": BUDGET_CHARS,
               "flags": "--tools '' --strict-mcp-config --setting-sources ''", "prompt": "vs/prompt.py@v1+nc-v2-redact"},
    "codex": {"tool": "codex-cli-single-shot", "model": CODEX_MODEL, "budget_chars": BUDGET_CHARS,
              "flags": "--sandbox read-only --ephemeral", "prompt": "vs/prompt.py@v1+nc-v2-redact"},
}
REVIEW = {"claude": review_claude, "codex": review_codex}
