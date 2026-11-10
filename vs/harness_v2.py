"""Harness v2 (plan: ~/.claude/plans/can-we-leverage-what-expressive-brook.md). v1 (vs/harness.py) stays
frozen for its test run; every v2 change is an option so each is measured as its own ablation step.

opts:
  context: "v1" | "v2"   v2 = :(glob) scoping (v1's `dir/**/x` missed files directly under dir), generic
                         names dropped, plus callee definitions (sanitizers/validators the code calls)
  prompt:  "v1" | "v2"   v2 = cite the line where the fix belongs; most specific CWE, CWE-20 only as last resort
  lenses:  []  | ["dos", "auth"]   focused extra passes on the same context
  samples: 1..k          independent investigator samples (different seeds)
  analyzers: [] | ["redos", "recursion", "codeql"]   deterministic hints (vs/analyzers.py), context v2 only
Every pass's candidates are stored in raw["passes"]; the returned findings are the deduped union
(scripts/combine_harness.py re-scores other combinations offline).
"""
from __future__ import annotations

import json
import re
import subprocess

from . import cwe as cwemod
from .bench import file_at, repo_dir
from .harness import CODE_GLOBS, DEF_RE, INVESTIGATOR, NOT_NAMES, _chat, _lang, _regions, parse_findings_with_conf
from .prompt import build_user, redact

GENERIC = {"read", "write", "get", "set", "run", "main", "init", "close", "open", "update", "handle", "process",
           "parse", "load", "save", "call", "apply", "create", "delete", "render", "start", "stop", "send", "next",
           "value", "values", "items", "keys", "name", "data", "test", "setup", "build", "execute", "fetch", "append",
           "default", "index", "length", "toString", "constructor", "then", "push", "map", "filter", "reduce"}
CALL_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(")
METHOD_CALL_RE = re.compile(r"\.([A-Za-z_$][\w$]*)\s*\(")
BUILTINS = {"py": {"len", "str", "int", "float", "bool", "list", "dict", "set", "tuple", "print", "isinstance", "range",
                   "open", "super", "getattr", "setattr", "hasattr", "enumerate", "zip", "sorted", "min", "max", "any",
                   "all", "type", "repr", "format", "iter", "next", "map", "filter", "abs", "sum", "round", "id",
                   "Exception", "ValueError", "TypeError", "KeyError", "RuntimeError", "if", "for", "while", "return",
                   "not", "and", "or", "elif", "with", "lambda", "yield", "await", "assert", "raise", "except"},
            "js": {"require", "if", "for", "while", "switch", "catch", "function", "return", "typeof", "new", "await",
                   "String", "Number", "Boolean", "Array", "Object", "Promise", "Error", "JSON", "Math", "Date",
                   "parseInt", "parseFloat", "setTimeout", "clearTimeout", "console", "Symbol", "Map", "Set",
                   "Buffer", "encodeURIComponent", "decodeURIComponent", "isNaN", "super", "import", "export"}}


def scope_v2(files: list[str]) -> list[str]:
    """`:(glob)` makes `**` match zero or more directories, so files directly under the package dir match."""
    dirs = sorted({"/".join(f.split("/")[:2]) if f.count("/") >= 2 else (f.split("/")[0] if "/" in f else "")
                   for f in files})
    if "" in dirs:
        return CODE_GLOBS
    return [f":(glob){d}/**/{g}" for d in dirs for g in CODE_GLOBS]


def _grep(d, sha, args, scope, timeout_s=60) -> list[tuple[str, int, str]]:
    try:
        r = subprocess.run(["git", "-C", str(d), "grep", "-n", *args, sha, "--", *scope],
                           capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return []
    out = []
    for line in r.stdout.splitlines():
        parts = line.split(":", 3)
        if len(parts) == 4 and parts[2].isdigit():
            out.append((parts[1], int(parts[2]), parts[3]))
    return out


def _is_test(path: str) -> bool:
    return bool(re.search(r"(^|/)(tests?|__tests__|spec|e2e|fixtures?)/|(^|/)test_[^/]*\.py$|_test\.py$|\.(test|spec)\.[cm]?[jt]sx?$", path))


def _snippet(item, path, ln, ctx) -> str:
    lines = (file_at(item["repo"], item["head"], path) or "").splitlines()
    lo, hi = max(1, ln - ctx), min(len(lines), ln + ctx)
    return "\n".join(f"{i:5d}  {redact(lines[i - 1])}" for i in range(lo, hi + 1))


def region_text(item) -> dict[str, list[str]]:
    out = {}
    for f, wins in _regions(item).items():
        lines = (file_at(item["repo"], item["head"], f) or "").splitlines()
        out[f] = [l for s, e in wins for l in lines[s - 1:e]]
    return out


def defined_symbols(item) -> list[str]:
    """Functions/classes defined in (or enclosing) the changed region; generic and dunder names dropped."""
    names = []
    for f, wins in _regions(item).items():
        lines = (file_at(item["repo"], item["head"], f) or "").splitlines()
        rx = DEF_RE[_lang(f)]
        defs = []
        for i, l in enumerate(lines, 1):
            m = rx.match(l)
            if m:
                n = next((g for g in m.groups() if g), None)
                if n and n not in NOT_NAMES and n not in GENERIC and len(n) > 3 and not n.startswith("__"):
                    defs.append((i, n))
        for s, e in wins:
            for n in [n for i, n in defs if s <= i <= e] + [n for i, n in defs if i < s][-1:]:
                if n not in names:
                    names.append(n)
    return names


def called_names(item, limit: int = 10) -> list[str]:
    """Names the changed region calls but does not define (candidates for sanitizers/validators/sinks)."""
    defined = set(defined_symbols(item))
    counts: dict[str, int] = {}
    for f, lines in region_text(item).items():
        lang = _lang(f)
        for l in lines:
            for rx in (CALL_RE, METHOD_CALL_RE):
                for n in rx.findall(l):
                    if n in BUILTINS[lang] or n in GENERIC or n in defined or len(n) <= 3:
                        continue
                    counts[n] = counts.get(n, 0) + 1
    return [n for n, _ in sorted(counts.items(), key=lambda kv: -kv[1])][:limit]


def context_v2(item, caller_budget=10000, callee_budget=10000) -> tuple[str, dict]:
    d = repo_dir(item["repo"])
    regions = _regions(item)
    scope = scope_v2(list(regions))
    inside = lambda p, ln: any(s <= ln <= e for s, e in regions.get(p, []))  # noqa: E731
    callers, used = [], 0
    syms = defined_symbols(item)[:10]
    for sym in syms:
        hits = [(p, ln) for p, ln, t in _grep(d, item["head"], ["-w", "-F", sym], scope)
                if not inside(p, ln) and not DEF_RE[_lang(p)].match(t) and not _is_test(p)][:3]
        for p, ln in hits:
            block = f"\n# {p} (calls `{sym}` at line {ln})\n{_snippet(item, p, ln, 8)}\n"
            if used + len(block) > caller_budget:
                break
            callers.append(block); used += len(block)
    callees, used2 = [], 0
    names = called_names(item)
    for n in names:
        pat = (rf"^\s*(async\s+)?def\s+{re.escape(n)}\b|^\s*class\s+{re.escape(n)}\b|"
               rf"function\s*\*?\s*{re.escape(n)}\b|\b{re.escape(n)}\s*[:=]\s*(async\s*)?(function|\([^)]*\)\s*=>)|"
               rf"^\s*(async\s+)?{re.escape(n)}\s*\([^)]*\)\s*\{{")
        hits = [(p, ln) for p, ln, _ in _grep(d, item["head"], ["-E", pat], scope)
                if not inside(p, ln) and not _is_test(p)][:1]
        if not hits:  # defined elsewhere in the repo (shared utils)
            hits = [(p, ln) for p, ln, _ in _grep(d, item["head"], ["-E", pat], CODE_GLOBS)
                    if not inside(p, ln) and not _is_test(p)][:1]
        for p, ln in hits:
            block = f"\n# {p}:{ln} (definition of `{n}`, called by the code above)\n{_snippet(item, p, ln + 12, 15)}\n"
            if used2 + len(block) > callee_budget:
                break
            callees.append(block); used2 += len(block)
    text = ""
    if callers:
        text += "\n## Call sites elsewhere in the repository\n```\n" + "".join(callers) + "```\n"
    if callees:
        text += "\n## Definitions of functions this code calls\n```\n" + "".join(callees) + "```\n"
    return text, {"symbols": syms, "callees": names, "n_call_site_chars": used, "n_callee_chars": used2}


PROMPT_V2_ADDENDUM = """

Reporting rules (important for usefulness):
- line: the line where the fix must be applied -- the missing or broken check, or the vulnerable statement \
itself if the fix is to change it. If both a sink and a missing check apply, report the missing check's line.
- cwe: the most specific CWE that fits (e.g. CWE-22, CWE-1333, CWE-400, CWE-770, CWE-918, CWE-1321, CWE-862). \
Use CWE-20 only if nothing more specific applies."""

PROMPT_V3_ADDENDUM = """
- Recall matters: report every plausible issue you found, with an honest confidence (0.3 = plausible but \
unconfirmed, 0.6 = likely, 0.9 = certain). Do not withhold a finding only because you are unsure; low-confidence \
findings are filtered later."""

MAP_SYS = """You are mapping the attack surface of the code shown, as preparation for a security review. Do not \
judge vulnerabilities yet. List (a) every place attacker-controllable data enters (parameters of handlers/tools/\
CLI/parsers, file or network input, headers, archive entries, LLM/tool output) and (b) every dangerous sink \
(filesystem paths, process execution, eval/templates, queries, HTML output, outbound requests, object merges by \
key, deserialization, regexes on input, loops/allocations/recursion sized by input, auth/permission decisions). \
Then list up to 12 source->sink paths worth checking. Respond with JSON only:
{"sources": [{"file": "...", "line": 1, "what": "..."}], "sinks": [{"file": "...", "line": 1, "what": "..."}],
 "paths": [{"file": "...", "source_line": 1, "sink_line": 1, "note": "..."}]}"""

INV_SYS = """From the code shown and the project documentation excerpts, list the security invariants this code \
is supposed to maintain: size/count/depth/time limits, authentication and authorization boundaries, trust \
boundaries (what is attacker-controlled), sanitization or confinement guarantees, and limits the project \
documents or configures. Respond with JSON only, at most 10:
{"invariants": [{"what": "...", "where": "file:line", "why": "..."}]}"""

CHECK_ADDENDUM = """

A colleague prepared the list below for this code. Check each item carefully against the code (it may be \
incomplete or wrong), and also report anything exploitable it missed."""

LENSES = {
    "dos": """Focus ONLY on resource-exhaustion and availability bugs reachable by an attacker:
- regular expressions applied to untrusted input with nested or overlapping quantifiers (ReDoS)
- loops or recursion whose bound or depth comes from untrusted input (including zero-length or self-referencing \
structures that never advance), missing depth limits on parsers
- allocations, reads, buffers, decompression or string building sized by untrusted input with no cap
- missing size, count, rate or time limits on requests, uploads, headers, query parameters, archive entries
For each, confirm the input is attacker-reachable and that no limit exists on the path.""",
    "auth": """Focus ONLY on authentication, authorization and session/token handling:
- endpoints, handlers or tool functions that perform a privileged action without checking who the caller is
- checks that can be bypassed (wrong order, fail-open on error, case/encoding tricks, path or method confusion)
- object access by id without verifying ownership (IDOR), tenant/namespace confusion
- token, signature, cookie or session validation that is missing, weak, or compared in non-constant time
- secrets or sensitive data returned to callers who should not see them""",
}


def _investigator(prompt_ver: str, lens: str | None) -> str:
    sysmsg = INVESTIGATOR + (PROMPT_V2_ADDENDUM if prompt_ver in ("v2", "v3") else "") + \
        (PROMPT_V3_ADDENDUM if prompt_ver == "v3" else "")
    if lens:
        sysmsg += "\n\nFOCUSED PASS. " + LENSES[lens] + "\nIgnore other bug classes in this pass."
    return sysmsg


def dedupe(cands: list[dict], window: int = 5) -> list[dict]:
    """Merge candidates at the same file, within +-window lines, in the same CWE family; keep the most confident."""
    out: list[dict] = []
    for c in sorted(cands, key=lambda c: -(float(c.get("confidence") or 0))):
        try:
            ln = int(c.get("line"))
        except (TypeError, ValueError):
            ln = None
        dup = False
        for o in out:
            try:
                oln = int(o.get("line"))
            except (TypeError, ValueError):
                oln = None
            if (o.get("file") == c.get("file") and ln is not None and oln is not None and abs(ln - oln) <= window
                    and cwemod.family(o.get("cwe")) == cwemod.family(c.get("cwe"))):
                o["votes"] = o.get("votes", 1) + 1
                dup = True
                break
        if not dup:
            out.append({**c, "votes": 1})
    return out


NEMOTRON = {"base": "http://127.0.0.1:8080/v1", "model": "nemotron", "budget_chars": 42000,
            "caller_budget": 5000, "callee_budget": 5000, "max_tokens": 8192}


def _chat_ep(system: str, user: str, max_tokens: int, base: str, model: str, seed: int = 1729) -> tuple[str, dict]:
    """OpenAI-compatible call to a non-vLLM local endpoint (llama.cpp): no vLLM-specific kwargs."""
    import urllib.request
    body = {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.6, "top_p": 0.95, "max_tokens": max_tokens, "seed": seed}
    req = urllib.request.Request(f"{base}/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=2400) as r:
        resp = json.load(r)
    ch = resp["choices"][0]
    content = ch["message"].get("content") or ""
    if ch.get("finish_reason") == "length" and "{" not in content:
        raise RuntimeError("hit max_tokens before answering")
    return content, resp.get("usage") or {}


DOC_RE = re.compile(r"limit|max|maximum|auth|permission|security|trust|sandbox|allow|deny|untrusted|sanitiz", re.I)


def project_docs(item, cap: int = 4000) -> str:
    """Security-relevant paragraphs from SECURITY.md / README* at the reviewed commit."""
    try:
        names = subprocess.run(["git", "-C", str(repo_dir(item["repo"])), "ls-tree", "--name-only", item["head"]],
                               capture_output=True, text=True, timeout=60).stdout.split()
    except subprocess.TimeoutExpired:
        return ""
    docs = [n for n in names if re.match(r"(SECURITY|README)(\.\w+)?$", n, re.I)]
    out, used = [], 0
    for n in sorted(docs, key=lambda x: not x.upper().startswith("SECURITY")):
        for para in (file_at(item["repo"], item["head"], n) or "").split("\n\n"):
            if DOC_RE.search(para) and used + len(para) < cap:
                out.append(f"[{n}] {redact(para.strip())}"); used += len(para)
    return "\n\n".join(out)


def make_review(opts: dict, semgrep_review=None, model: str = "qwen3.6-35b-a3b", budget_chars: int = 80000):
    from .harness import build_context as build_context_v1

    def build_v2_user(item, budget, caller_budget=10000, callee_budget=10000):
        base = build_user(item, budget)
        extra, ctx = context_v2(item, caller_budget, callee_budget)
        return base, extra, ctx

    def review(item: dict):
        hints = ""
        if opts.get("context", "v1") == "v2":
            base, extra, ctx = build_v2_user(item, budget_chars)
            if semgrep_review is not None:
                sg, _ = semgrep_review(item)
                if sg:
                    hints = "\n## Static analyzer hints (semgrep; may be false positives)\n" + "\n".join(
                        f"- {h['file']}:{h['line']} {h.get('cwe') or ''} {h['title']}: {(h.get('explanation') or '')[:200]}"
                        for h in sg[:15]) + "\n"
            if opts.get("analyzers"):
                from .analyzers import hints_text
                ah = hints_text(item, opts["analyzers"])
                hints += ah
                ctx["n_analyzer_hint_chars"] = len(ah)
            user = base + extra + hints
        else:
            user, ctx = build_context_v1(item, semgrep_review, budget_chars)
        passes, tok_in, tok_out = [], 0, 0
        pv = opts.get("prompt", "v1")
        n_main = 0 if opts.get("skip_main") else opts.get("samples", 1)
        plan = [("main", None, s) for s in range(n_main)] + [(f"lens_{l}", l, 0) for l in opts.get("lenses", [])]

        def add(name, text, u, seed=1729):
            nonlocal tok_in, tok_out
            tok_in += u.get("prompt_tokens") or 0; tok_out += u.get("completion_tokens") or 0
            passes.append({"name": name, "seed": seed, "candidates": parse_findings_with_conf(text)})

        for name, lens, s in plan:
            text, u = _chat(_investigator(pv, lens), user, 24576 if lens is None else 16384, model, seed=1729 + s)
            add(name, text, u, 1729 + s)
        if opts.get("twostep"):  # H8: map sources/sinks, then check with the map
            mtext, u = _chat(MAP_SYS, user, 12288, model)
            tok_in += u.get("prompt_tokens") or 0; tok_out += u.get("completion_tokens") or 0
            amap = mtext[mtext.find("{"): mtext.rfind("}") + 1]
            text, u = _chat(_investigator(pv, None) + CHECK_ADDENDUM, user + "\n## Attack-surface map\n" + amap + "\n",
                            24576, model)
            add("twostep", text, u)
        if opts.get("invariants"):  # H12: list invariants (code + docs), then check them
            docs = project_docs(item)
            iuser = user + (f"\n## Project documentation excerpts\n{docs}\n" if docs else "")
            itext, u = _chat(INV_SYS, iuser, 12288, model)
            tok_in += u.get("prompt_tokens") or 0; tok_out += u.get("completion_tokens") or 0
            inv = itext[itext.find("{"): itext.rfind("}") + 1]
            text, u = _chat(_investigator(pv, None) + CHECK_ADDENDUM, iuser + "\n## Security invariants\n" + inv + "\n",
                            24576, model)
            add("invariants", text, u)
            ctx["n_doc_chars"] = len(docs)
        if opts.get("nemotron") and opts.get("context") == "v2":  # H5: second local model on a context sized for its 32k window
            nb, nextra, _ = build_v2_user(item, NEMOTRON["budget_chars"], NEMOTRON["caller_budget"], NEMOTRON["callee_budget"])
            text, u = _chat_ep(_investigator(pv, None), nb + nextra + hints[:4000], NEMOTRON["max_tokens"],
                               NEMOTRON["base"], NEMOTRON["model"])
            add("nemotron", text, u)
        merged = dedupe([c for p in passes for c in p["candidates"]])
        raw = json.dumps({**ctx, "opts": opts, "passes": passes, "candidates": merged})
        return merged, {"tokens_in": tok_in, "tokens_out": tok_out, "raw": raw}
    return review


def config(opts: dict) -> dict:
    return {"tool": "harness_v2", "version": "v2-dev", "model": "qwen3.6-35b-a3b", "budget_chars": 80000,
            "prompt_file": "vs/prompt.py@v2-redact", "opts": opts}
