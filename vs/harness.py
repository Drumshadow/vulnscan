"""U2 harness: context gathering + static hints + 35B investigation + per-candidate refutation.

Truth is never read here. For new-code items the "changed region" is everything shown (views); for
regression items it is the diff's hunks. Every candidate and every refuter verdict is kept in the raw
record so the confidence threshold can be swept offline (scripts/sweep_harness.py) without re-running.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.request

from .bench import file_at, repo_dir
from .diffutil import hunk_ranges
from .prompt import build_user, parse_findings, redact

VLLM = "http://127.0.0.1:8000/v1"
DEF_RE = {
    "py": re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)|^\s*class\s+([A-Za-z_]\w*)"),
    "js": re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)"
                     r"|^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
                     r"|^\s*(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][\w$]*)"
                     r"|^\s*(?:public|private|protected|static|async|\s)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
}
NOT_NAMES = {"if", "for", "while", "switch", "catch", "function", "return", "constructor", "super", "require"}
CODE_GLOBS = ["*.py", "*.js", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.jsx", "*.mts", "*.cts"]

INVESTIGATOR = """You are an expert application security reviewer examining one pull request.

Work method (do this in your reasoning, not in the output):
1. Identify every place the new or changed code receives data an attacker could control: HTTP params, \
headers, bodies, file names and contents, archive entries, URLs, CLI args, environment, messages from other \
services, tool/LLM outputs, config loaded from user-writable places.
2. Follow that data to dangerous operations: filesystem paths, shell/process execution, eval/dynamic code, \
SQL/NoSQL queries, HTML/template output, outbound URL fetches, object merges/property assignment by key, \
deserialization, regexes on untrusted input, unbounded loops/allocations/recursion, authentication and \
authorization decisions, crypto and token handling.
3. For each path, look for defenses on the way: validation, normalization, allowlists, escaping, auth checks, \
size limits, and check the callers shown under "Call sites" too.
4. Keep only paths where the defense is missing or broken in THIS code.

Report at most 5 candidates, most likely first. For each: file (as shown), line (real line number of the \
dangerous operation or the missing check), cwe ("CWE-<n>"), title, explanation (source -> sink, why defenses \
fail, impact), confidence (0 to 1).
If nothing is exploitable, return an empty list. Respond with JSON only:
{"findings": [{"file": "...", "line": 1, "cwe": "CWE-...", "title": "...", "explanation": "...", "confidence": 0.0}]}"""

REFUTER = """You are a skeptical principal security engineer. A colleague claims the code below contains a \
vulnerability. Your job is to try hard to refute the claim, and to confirm it only if it survives.

Check, using the code shown (including the call sites):
(a) Is the claimed source really attacker-controlled in a realistic deployment of this project?
(b) Is there validation, sanitization, normalization, an allowlist, an auth check, or a limit anywhere on \
the path that stops it?
(c) Does the claimed sink actually do what the claim says, with real security impact?
(d) Is the location right (the dangerous operation or missing check is at or near the cited line)?

Respond with JSON only: {"verdict": "confirmed" or "refuted", "confidence": 0.0 to 1.0, "reason": "..."}"""


def _chat(system: str, user: str, max_tokens: int, model: str, seed: int = 1729) -> tuple[str, dict]:
    body = {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.6, "top_p": 0.95, "max_tokens": max_tokens, "seed": seed,
            "chat_template_kwargs": {"enable_thinking": True}}
    req = urllib.request.Request(f"{VLLM}/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=2400) as r:
        resp = json.load(r)
    ch = resp["choices"][0]
    content = ch["message"].get("content") or ""
    if ch.get("finish_reason") == "length" and "{" not in content:
        raise RuntimeError("hit max_tokens before answering")
    return content, resp.get("usage") or {}


def _lang(path: str) -> str:
    return "py" if path.endswith(".py") else "js"


def _regions(item: dict) -> dict[str, list[tuple[int, int]]]:
    if item.get("framing") == "newcode":
        return {f: [tuple(w) for w in ws] for f, ws in item["views"].items()}
    return hunk_ranges(item["diff"])


def changed_symbols(item: dict, limit: int = 12) -> list[str]:
    """Names of functions/classes defined in (or enclosing) the changed region, nearest-def heuristic."""
    names: list[str] = []
    for f, wins in _regions(item).items():
        content = file_at(item["repo"], item["head"], f)
        if not content:
            continue
        lines = content.splitlines()
        rx = DEF_RE[_lang(f)]
        defs = []
        for i, l in enumerate(lines, 1):
            m = rx.match(l)
            if m:
                n = next((g for g in m.groups() if g), None)
                if n and n not in NOT_NAMES and len(n) > 2:
                    defs.append((i, n))
        for s, e in wins:
            inside = [n for i, n in defs if s <= i <= e]
            above = [n for i, n in defs if i < s]
            for n in inside + above[-1:]:
                if n not in names:
                    names.append(n)
    return names[:limit]


def _scope(files: list[str]) -> list[str]:
    """Pathspecs limited to the changed files' package directories (first 2 path components).
    Blobless clones fetch every blob a grep touches, so a whole-repo grep on a large repo is too slow."""
    dirs = sorted({"/".join(f.split("/")[:2]) if f.count("/") >= 2 else (f.split("/")[0] if "/" in f else "")
                   for f in files})
    if "" in dirs:
        return CODE_GLOBS
    return [f"{d}/**/{g}" for d in dirs for g in CODE_GLOBS]


def call_sites(item: dict, symbols: list[str], per_symbol: int = 3, ctx: int = 8, budget: int = 14000,
               timeout_s: int = 60) -> str:
    d = repo_dir(item["repo"])
    regions = _regions(item)
    scope = _scope(list(regions))
    out, used = [], 0
    for sym in symbols:
        try:
            r = subprocess.run(["git", "-C", str(d), "grep", "-n", "-w", "-F", sym, item["head"], "--", *scope],
                               capture_output=True, text=True, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            continue  # skip this symbol's call sites rather than fail the item
        hits = []
        for line in r.stdout.splitlines():
            parts = line.split(":", 3)  # <sha>:<path>:<line>:<text>
            if len(parts) < 4 or not parts[2].isdigit():
                continue
            path, ln, text = parts[1], int(parts[2]), parts[3]
            if any(s <= ln <= e for s, e in regions.get(path, [])):
                continue  # already shown
            if DEF_RE[_lang(path)].match(text):
                continue  # the definition itself, not a call
            if "/test" in path or path.startswith("test"):
                continue
            hits.append((path, ln))
            if len(hits) >= per_symbol:
                break
        for path, ln in hits:
            content = file_at(item["repo"], item["head"], path) or ""
            lines = content.splitlines()
            lo, hi = max(1, ln - ctx), min(len(lines), ln + ctx)
            block = f"\n# {path} (calls `{sym}` at line {ln})\n" + "\n".join(
                f"{i:5d}  {redact(lines[i - 1])}" for i in range(lo, hi + 1)) + "\n"
            if used + len(block) > budget:
                return "".join(out)
            out.append(block); used += len(block)
    return "".join(out)


REFUTER_V2 = """You are a senior security engineer reviewing a colleague's vulnerability finding. Decide whether \
it is a real vulnerability. Be fair, not adversarial: most findings that name a concrete source and sink are \
worth confirming.

Refute ONLY if one of these holds, and say which:
(a) you can point to a specific line in the code shown that blocks the attack (validation, escaping, \
allowlist, auth check, limit) -- quote it;
(b) the claimed source is clearly not attacker-controlled in any realistic deployment;
(c) the claimed sink does not exist or does not do what the claim says.
Otherwise confirm, even if exploitation needs some setup.

Respond with JSON only: {"verdict": "confirmed" or "refuted", "confidence": 0.0 to 1.0, \
"blocking_line": "<quoted code or empty>", "reason": "..."}"""

REFUTERS = {"v1": REFUTER, "v2": REFUTER_V2}


def build_context(item: dict, semgrep_review=None, budget_chars: int = 80000) -> tuple[str, dict]:
    """The investigator's user message: shown code + call sites + optional semgrep hints."""
    base = build_user(item, budget_chars)
    syms = changed_symbols(item)
    sites = call_sites(item, syms)
    hints = ""
    if semgrep_review is not None:
        sg, _ = semgrep_review(item)
        if sg:
            hints = "\n## Static analyzer hints (semgrep; may be false positives)\n" + "\n".join(
                f"- {h['file']}:{h['line']} {h.get('cwe') or ''} {h['title']}: {(h.get('explanation') or '')[:200]}"
                for h in sg[:15]) + "\n"
    user = base + (f"\n## Call sites elsewhere in the repository\n```\n{sites}```\n" if sites else "") + hints
    return user, {"symbols": syms, "n_call_site_chars": len(sites), "hints": bool(hints)}


def refute_one(user: str, cand: dict, variant: str, model: str = "qwen3.6-35b-a3b") -> tuple[dict, dict]:
    claim = (f"\n\n## Claimed vulnerability\nfile: {cand['file']}\nline: {cand['line']}\ncwe: {cand['cwe']}\n"
             f"title: {cand['title']}\nexplanation: {cand['explanation']}\n")
    try:
        vt, u = _chat(REFUTERS[variant], user + claim, 8192, model)
        return json.loads(vt[vt.find("{"): vt.rfind("}") + 1]), u
    except Exception as e:  # noqa: BLE001  refuter failure: verdict "error" (dropped by keep())
        return {"verdict": "error", "confidence": 0.0, "reason": str(e)[:200]}, {}


def make_review(semgrep_review=None, model: str = "qwen3.6-35b-a3b", budget_chars: int = 80000,
                threshold: float = 0.5, refute: str | None = "v1"):
    """refute=None: investigator only, every candidate is kept (refuters are swept offline: scripts/refute.py)."""
    def review(item: dict):
        user, ctx = build_context(item, semgrep_review, budget_chars)
        text, u1 = _chat(INVESTIGATOR, user, 24576, model)
        cands = parse_findings_with_conf(text)
        tok_in, tok_out = u1.get("prompt_tokens") or 0, u1.get("completion_tokens") or 0
        verdicts = []
        if refute:
            for c in cands:
                v, u2 = refute_one(user, c, refute, model)
                tok_in += u2.get("prompt_tokens") or 0; tok_out += u2.get("completion_tokens") or 0
                verdicts.append(v)
            kept = [c for c, v in zip(cands, verdicts) if keep(c, v, threshold)]
        else:
            kept = list(cands)
        raw = json.dumps({**ctx, "candidates": cands, "verdicts": verdicts})
        return kept, {"tokens_in": tok_in, "tokens_out": tok_out, "raw": raw}
    return review


def keep(cand: dict, verdict: dict, threshold: float) -> bool:
    """Survives refutation: confirmed with refuter confidence >= threshold. Errors are dropped."""
    return verdict.get("verdict") == "confirmed" and float(verdict.get("confidence") or 0) >= threshold


def parse_findings_with_conf(text: str) -> list[dict]:
    fs = parse_findings(text)
    # parse_findings keeps the five scoring fields; recover confidence from the raw JSON if present
    try:
        obj = json.loads(text[text.find("{"): text.rfind("}") + 1])
        confs = [f.get("confidence") for f in obj.get("findings", []) if isinstance(f, dict)]
    except Exception:  # noqa: BLE001
        confs = []
    for i, f in enumerate(fs):
        f["confidence"] = confs[i] if i < len(confs) else None
    return fs[:5]


CONFIG = {"tool": "harness", "version": "u2-v1", "prompt": "vs/prompt.py@v2-redact", "model": "qwen3.6-35b-a3b", "budget_chars": 80000,
          "threshold": 0.5, "investigator_max_tokens": 24576, "refuter_max_tokens": 8192,
          "context": "nearest-def symbols + git grep call sites in changed package dirs (3/symbol, +-8 lines, 14k chars, 60s/symbol)",
          "hints": "semgrep diff-aware"}
