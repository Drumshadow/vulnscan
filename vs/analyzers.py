"""H13: deterministic analyzers whose output becomes investigator hints (like the semgrep hints).

redos:     regexes in the shown code, checked with regexploit (Doyensec, Apache-2.0). Python patterns come
           from re.* calls; JS patterns from /.../ literals and new RegExp("..."). All are analysed with the
           Python front end (backtracking behaviour is the same for these constructs). Only exponential or
           cubic-and-worse results are kept.
recursion: functions in the shown code that call themselves and take no depth/limit-like parameter.
codeql:    data-flow alerts from a cached CodeQL run (scripts/codeql_cache.py), restricted to shown files.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import tempfile

from .bench import ROOT, file_at
from .harness import _regions

REGEXPLOIT = ROOT / "tools" / "regexploit-venv" / "bin" / "regexploit-py"
CODEQL_CACHE = ROOT / "data" / "codeql-cache"
PY_RE_CALL = re.compile(r"""\bre\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn|split)\(\s*[rRbBuU]*(?P<q>'''|\"\"\"|'|")(?P<pat>.*?)(?P=q)""")
JS_RE_LIT = re.compile(r"""(?:^|[=(,:!&|?{};\s])/(?P<pat>(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\[\n])+)/[dgimsuyv]*""")
JS_NEW_RE = re.compile(r"""new\s+RegExp\(\s*(?P<q>'|"|`)(?P<pat>(?:\\.|(?!(?P=q)).)*)(?P=q)""")
DEPTH_PARAM = re.compile(r"depth|level|limit|max|remaining|budget|count|n_|ttl|hops", re.I)


def _shown(item) -> dict[str, list[tuple[int, str]]]:
    out = {}
    for f, wins in _regions(item).items():
        lines = (file_at(item["repo"], item["head"], f) or "").splitlines()
        out[f] = [(i, lines[i - 1]) for s, e in wins for i in range(max(1, s), min(len(lines), e) + 1)]
    return out


def redos_hints(item) -> list[dict]:
    pats = []  # (file, line, pattern)
    for f, lines in _shown(item).items():
        js = not f.endswith(".py")
        for ln, text in lines:
            if text.lstrip().startswith(("//", "#", "*")):
                continue
            rxs = (JS_RE_LIT, JS_NEW_RE) if js else (PY_RE_CALL,)
            for rx in rxs:
                for m in rx.finditer(text):
                    p = m.group("pat")
                    if js and rx is JS_NEW_RE:
                        p = p.replace("\\\\", "\\")
                    if any(c in p for c in "+*{") and len(p) < 2000:
                        pats.append((f, ln, p))
    if not pats:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tmp:
        tmp.write("import re\n")
        for _, _, p in pats:
            tmp.write(f"re.compile({p!r})\n")
        path = tmp.name
    try:
        r = subprocess.run([str(REGEXPLOIT), path], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return []
    finally:
        pathlib.Path(path).unlink(missing_ok=True)
    hints, cur = [], None
    for line in r.stdout.splitlines():
        m = re.match(r"Vulnerable regex in .* #(\d+)", line)
        if m:
            cur = int(m.group(1)) - 2  # line 1 is "import re"
            continue
        m = re.match(r"Worst-case complexity: (\d+).*\((\w+)\)", line)
        if m and cur is not None and 0 <= cur < len(pats):
            stars, kind = int(m.group(1)), m.group(2)
            if kind == "exponential" or stars >= 3:
                f, ln, p = pats[cur]
                hints.append({"file": f, "line": ln, "cwe": "CWE-1333",
                              "title": f"regex with {kind} backtracking (regexploit)",
                              "explanation": f"pattern {p[:120]!r}"})
            cur = None
    return hints


def recursion_hints(item) -> list[dict]:
    hints = []
    for f, lines in _shown(item).items():
        py = f.endswith(".py")
        defs = []
        for ln, text in lines:
            m = (re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)", text) if py else
                 re.match(r"\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\(([^)]*)", text)
                 or re.match(r"\s*(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{", text))
            if m:
                defs.append((ln, m.group(1), m.group(2)))
        for k, (ln, name, params) in enumerate(defs):
            end = defs[k + 1][0] if k + 1 < len(defs) else lines[-1][0] + 1
            body = [t for i, t in lines if ln < i < end]
            calls_self = any(re.search(rf"(?<![\w.]){re.escape(name)}\s*\(|(?:self|this)\.{re.escape(name)}\s*\(", t) for t in body)
            if calls_self and not DEPTH_PARAM.search(params):
                hints.append({"file": f, "line": ln, "cwe": "CWE-674",
                              "title": f"recursive `{name}` has no depth/limit parameter",
                              "explanation": "check whether recursion depth is bounded for attacker-controlled input"})
    return hints[:10]


def codeql_hints(item) -> list[dict]:
    key = CODEQL_CACHE / f"{item['repo'].replace('/', '__')}@{item['head'][:16]}.sarif"
    if not key.exists():
        return []
    try:
        sarif = json.loads(key.read_text())
    except json.JSONDecodeError:
        return []
    shown = _regions(item)
    hints = []
    for run in sarif.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            path = loc.get("artifactLocation", {}).get("uri", "")
            ln = loc.get("region", {}).get("startLine")
            if path not in shown or ln is None:
                continue
            rule = rules.get(res.get("ruleId"), {})
            tags = rule.get("properties", {}).get("tags", [])
            cwe = next((t.replace("external/cwe/cwe-", "CWE-").upper() for t in tags if "cwe-" in t), None)
            flow = ""
            cf = res.get("codeFlows") or []
            if cf:
                steps = cf[0].get("threadFlows", [{}])[0].get("locations", [])
                flow = " -> ".join(f"{s['location']['physicalLocation']['artifactLocation']['uri']}:"
                                   f"{s['location']['physicalLocation']['region']['startLine']}" for s in steps[:6]
                                   if "physicalLocation" in s.get("location", {}))
            hints.append({"file": path, "line": ln, "cwe": cwe, "title": f"CodeQL {res.get('ruleId')}",
                          "explanation": (res.get("message", {}).get("text", "")[:200] + (f" | flow: {flow}" if flow else ""))})
    return hints[:15]


ANALYZERS = {"redos": redos_hints, "recursion": recursion_hints, "codeql": codeql_hints}


def hints_text(item, names: list[str]) -> str:
    out = []
    for n in names:
        try:
            out += [(n, h) for h in ANALYZERS[n](item)]
        except Exception:  # noqa: BLE001  an analyzer failure must never fail the review
            continue
    if not out:
        return ""
    return "\n## Analyzer hints (deterministic checks; verify before reporting)\n" + "\n".join(
        f"- [{n}] {h['file']}:{h['line']} {h.get('cwe') or ''} {h['title']}: {h.get('explanation', '')}" for n, h in out) + "\n"
