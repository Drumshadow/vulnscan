"""H15 V3: write, run and judge a proof-of-concept for one candidate finding, inside vs-sandbox.

Outcome per candidate: confirmed | not_reproduced | unverifiable (+ attempts, stdout/stderr tails, code).
A PoC counts only if it (a) imports/requires the project's own module for the cited file (static check) and
(b) prints VULNSCAN_CONFIRMED:<nonce> (fresh random nonce per attempt). The sandbox gives no network, no writes
outside the throwaway workspace, a cgroup cap on tasks/memory (no swap) and a wall-clock kill.
Oracle honesty is measured, not assumed: confirmations on patched (nc_fixed) code are false confirmations.
"""
from __future__ import annotations

import json
import pathlib
import re
import secrets
import shutil
import subprocess
import tempfile

from .bench import ROOT, file_at
from .harness import _chat
from .poc_env import ensure_env

SANDBOX = ROOT / "sandbox" / "target" / "release" / "vs-sandbox"
SCOPE = ["systemd-run", "--user", "--scope", "--quiet", "-p", "TasksMax=64", "-p", "MemoryMax=3G",
         "-p", "MemorySwapMax=0", "-p", "OOMPolicy=continue", "-p", "CPUQuota=200%"]
WALL_S = 90

SYSTEM = """You write proof-of-concept exploits to VERIFY a suspected vulnerability in an open-source project, \
for a defensive security review. The PoC runs in a locked sandbox: no network, the project source is importable \
read-only, the current directory is a writable scratch workspace, about 90 seconds wall clock.

Rules:
- Call the project's REAL code at the cited location (import the module / require the file as instructed). \
Never re-implement or copy the vulnerable logic into the PoC; a PoC that does not use the project code is invalid.
- The PoC runs TWICE. Read os.environ["VULNSCAN_MODE"] (Python) / process.env.VULNSCAN_MODE (JS): \
"attack" = send the crafted malicious input; "control" = send a benign input of the same shape through the \
same code path. Everything else must be identical in both modes. Decide success from what the project code \
actually DID (its return value, raised error, files it created in the workspace, elapsed time, mutated \
objects), then print exactly the confirmation token on success, otherwise VULNSCAN_NOT_CONFIRMED and a reason. \
A finding is confirmed only if the attack run prints the token and the control run does not.
- Never read, inspect or pattern-match the project's source text (no inspect.getsource, no reading .py/.js \
source files to look for patterns). Execute the code; static analysis is not a proof.
- Good checks: a computed/opened path resolves outside its intended base directory (check with realpath; do not \
write outside the workspace, it is blocked anyway); Object.prototype / a class attribute gets polluted; a \
command or template executes and creates a marker file in the workspace; untrusted input reaches a sink \
unescaped (inspect the returned value); for denial of service, time the call on growing crafted inputs and \
confirm super-linear growth or > 5 s on an input under 1 MB while a benign input of the same size is fast.
- Keep it small, deterministic and self-contained. Mock network clients, servers or credentials if needed.
Respond with JSON only: {"language": "python" | "javascript", "filename": "poc.py" | "poc.mjs" | "poc.ts", \
"code": "..."}"""


def import_hint(meta: dict, path: str) -> str:
    if meta["lang"] == "python":
        rel = pathlib.PurePosixPath(path)
        parts = list(rel.with_suffix("").parts)
        if parts and parts[0] == "src":
            parts = parts[1:]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return f"Python: `import {'.'.join(parts)}` (PYTHONPATH already points at the project source)."
    return (f"JavaScript/TypeScript: the project is at {meta['src']}; load the file with "
            f"`await import('{meta['src']}/{path}')` (ESM) or `require('{meta['src']}/{path}')` (CJS). "
            "TypeScript files load under Node 22 type stripping; node_modules is installed (no dev deps).")


SOURCE_READ_RE = re.compile(r"inspect\.getsource|getsourcelines|readFileSync\([^)]*\.(?:js|ts|mjs|cjs)|"
                            r"open\([^)]*\.py['\"]|\.read_text\(\)[^\n]*\.py|__file__\)\.read")


def reads_source(code: str) -> bool:
    return bool(SOURCE_READ_RE.search(code))


def uses_project(code: str, meta: dict, path: str) -> bool:
    if meta["lang"] == "python":
        mod = import_hint(meta, path).split("`import ", 1)[1].split("`", 1)[0]
        top = mod.split(".")[0]
        return bool(re.search(rf"^\s*(from|import)\s+{re.escape(top)}\b", code, re.M))
    return meta["src"] in code and pathlib.PurePosixPath(path).stem in code


def enclosing_function(item, path, line) -> str | None:
    from .harness import DEF_RE, _lang
    lines = (file_at(item["repo"], item["head"], path) or "").splitlines()
    try:
        ln = min(int(line), len(lines))
    except (TypeError, ValueError):
        return None
    rx = DEF_RE[_lang(path)]
    for i in range(ln, 0, -1):
        m = rx.match(lines[i - 1])
        if m:
            return next((g for g in m.groups() if g), None)
    return None


TEST_PATH_RE = re.compile(r"((^|/)(tests?|__tests__|spec)/.*|(^|/)test_[^/]*|_test|\.(test|spec))\.([cm]?[jt]sx?|py)$")
GENERIC_FN = {"validate", "run", "main", "__init__", "get", "set", "handle", "process", "call", "execute", "parse"}


def _tokens(path: str) -> set[str]:
    words = re.split(r"[^a-zA-Z0-9]+|(?<=[a-z])(?=[A-Z])", str(pathlib.PurePosixPath(path).with_suffix("")))
    out = set()
    for w in words:
        w = w.lower()
        if len(w) < 3 or w in {"src", "lib", "test", "tests", "spec", "index", "init", "main", "utils"}:
            continue
        out.add(w[:-1] if w.endswith("s") and len(w) > 4 else w)
    return out


def test_usage(item, path, line, max_snippets: int = 2, ctx: int = 25, head_lines: int = 60) -> str:
    """How the project's own tests exercise the cited code: valid arguments, fixtures and mocks for the PoC.
    Test files are ranked by shared path tokens with the source file (singularised: reads ~ read); the snippet
    is centred on the enclosing function name, or else on identifiers from the cited line (e.g. an argument name),
    or else is the top of the test file (imports + fixtures)."""
    from .bench import repo_dir
    name = enclosing_function(item, path, line)
    src_lines = (file_at(item["repo"], item["head"], path) or "").splitlines()
    try:
        cited = src_lines[int(line) - 1] if 0 < int(line) <= len(src_lines) else ""
    except (TypeError, ValueError):
        cited = ""
    idents = [w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", cited)
              if w not in {"self", "return", "raise", "import", "await", "async", "lambda", "field_name"}]
    try:
        files = subprocess.run(["git", "-C", str(repo_dir(item["repo"])), "ls-tree", "-r", "--name-only", item["head"]],
                               capture_output=True, text=True, timeout=60).stdout.splitlines()
    except subprocess.TimeoutExpired:
        return ""
    src_tok = _tokens(path)
    scored = []
    for f in files:
        if TEST_PATH_RE.search(f) and pathlib.PurePosixPath(f).suffix == pathlib.PurePosixPath(path).suffix:
            shared = len(src_tok & _tokens(f))
            if shared:
                scored.append((-shared, len(f), f))
    out = []
    for _, _, tp in sorted(scored)[:12]:
        lines = (file_at(item["repo"], item["head"], tp) or "").splitlines()
        terms = ([name] if name and name not in GENERIC_FN else []) + idents
        idx = next((i for t in terms for i, l in enumerate(lines, 1) if re.search(rf"\b{re.escape(t)}\b", l)), None)
        lo, hi = (max(1, idx - ctx), min(len(lines), idx + ctx)) if idx else (1, min(len(lines), head_lines))
        out.append(f"### {tp}\n```\n" + "\n".join(lines[lo - 1:hi]) + "\n```")
        if len(out) >= max_snippets:
            break
    return ("## How the project's own tests exercise this code (valid arguments, fixtures, mocks)\n"
            + "\n".join(out) + "\n") if out else ""


def _excerpt(item, path, line, ctx=40) -> str:
    lines = (file_at(item["repo"], item["head"], path) or "").splitlines()
    try:
        ln = int(line)
    except (TypeError, ValueError):
        ln = 1
    lo, hi = max(1, ln - ctx), min(len(lines), ln + ctx)
    return "\n".join(f"{i:5d}  {lines[i - 1]}" for i in range(lo, hi + 1))


PY_TRACER = r"""
import json, os, runpy, sys
_target, _out, _hits = os.environ["VS_COV_FILE"], os.environ["VS_COV_OUT"], set()
def _t(frame, event, arg):
    if frame.f_code.co_filename == _target:
        if event == "line":
            _hits.add(frame.f_lineno)
        return _t
    return None
def _save():
    with open(_out, "w") as f:
        json.dump(sorted(_hits), f)
import atexit; atexit.register(_save)
sys.settrace(_t)
sys.argv = [sys.argv[1]]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


def _js_covered(cov_dir: pathlib.Path, target: str, line: int) -> bool | None:
    """V8 coverage: did a function containing `line` of `target` run (count > 0)? None if no data."""
    try:
        src = pathlib.Path(target).read_text(errors="replace")
    except OSError:
        return None
    starts = [0]
    for i, ch in enumerate(src):
        if ch == "\n":
            starts.append(i + 1)
    if not 0 < line <= len(starts):
        return None
    off = starts[line - 1]
    seen = False
    for f in cov_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for script in data.get("result", []):
            if not script.get("url", "").endswith(target):
                continue
            seen = True
            for fn in script.get("functions", []):
                for rg in fn.get("ranges", []):
                    if rg["startOffset"] <= off < rg["endOffset"] and rg["count"] > 0 and fn.get("functionName"):
                        return True
    return False if seen else None


def run_poc(meta: dict, lang: str, filename: str, code: str, mode: str = "attack",
            cov_target: str | None = None, cov_line: int | None = None) -> dict:
    """Run one PoC in vs-sandbox. With cov_target/cov_line, also report whether the cited code executed
    (Python: exact lines via a tracer; JS/TS: the enclosing function via V8 coverage)."""
    ws = pathlib.Path(tempfile.mkdtemp(prefix="vs-poc-", dir="/tmp"))
    try:
        name = re.sub(r"[^\w.]", "_", filename or ("poc.py" if lang == "python" else "poc.mjs"))
        (ws / name).write_text(code)
        extra_env = {"TMPDIR": str(ws), "HOME": str(ws), "VULNSCAN_MODE": mode}
        if lang == "python":
            cmd = [meta.get("python") or "/usr/bin/python3", "-B"]
            if cov_target:
                (ws / "_vs_tracer.py").write_text(PY_TRACER)
                extra_env.update(VS_COV_FILE=cov_target, VS_COV_OUT=str(ws / ".vs_cov.json"))
                cmd += ["_vs_tracer.py", name]
            else:
                cmd.append(name)
        else:
            cmd = [meta.get("node") or str(ROOT / "tools/node/bin/node")]
            if name.endswith(".ts"):
                cmd.append("--experimental-strip-types")
            cmd.append(name)
            if cov_target:
                (ws / ".v8cov").mkdir()
                extra_env["NODE_V8_COVERAGE"] = str(ws / ".v8cov")
        status = ws / ".status.json"
        args = [*SCOPE, str(SANDBOX), "--rw", str(ws), "--wall-s", str(WALL_S), "--cpu-s", str(WALL_S),
                "--status", str(status)]
        for p in [*meta["ro"], "/dev/null", "/dev/urandom", "/dev/zero"]:
            if pathlib.Path(p).exists():
                args += ["--ro", p]
        for k, v in {**meta["env"], **extra_env}.items():
            args += ["--env", f"{k}={v}"]
        args += ["--", *cmd]
        r = subprocess.run(args, capture_output=True, text=True, timeout=WALL_S + 60)
        st = json.loads(status.read_text()) if status.exists() else {"exit": None, "signal": None, "timed_out": False}
        out = {"stdout": r.stdout[-4000:], "stderr": r.stderr[-3000:], **st}
        if cov_target and cov_line:
            if lang == "python":
                f = ws / ".vs_cov.json"
                hits = set(json.loads(f.read_text())) if f.exists() else None
                out["covered"] = None if hits is None else any(abs(h - cov_line) <= 5 for h in hits)
            else:
                out["covered"] = _js_covered(ws / ".v8cov", cov_target, cov_line)
        return out
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def verify(item: dict, cand: dict, model: str = "qwen3.6-35b-a3b", attempts: int = 3, coverage_gate: bool = False) -> dict:
    """coverage_gate (v2): a confirmation also requires the attack run to execute the cited code."""
    path = cand.get("file") or ""
    if not path or file_at(item["repo"], item["head"], path) is None:
        return {"outcome": "unverifiable", "reason": "cited file not in the reviewed code", "attempts": 0}
    try:
        meta = ensure_env(item)
    except Exception as e:  # noqa: BLE001
        return {"outcome": "unverifiable", "reason": f"env build failed: {e}"[:300], "attempts": 0}
    history = ""
    last = {}
    tests = test_usage(item, path, cand.get("line"))
    for k in range(1, attempts + 1):
        nonce = secrets.token_hex(6)
        token = f"VULNSCAN_CONFIRMED:{nonce}"
        user = (f"## Suspected vulnerability\nfile: {path}\nline: {cand.get('line')}\ncwe: {cand.get('cwe')}\n"
                f"title: {cand.get('title')}\nexplanation: {cand.get('explanation')}\n\n"
                f"## Code around the cited line ({path})\n```\n{_excerpt(item, path, cand.get('line'))}\n```\n\n"
                f"## How to load the project code\n{import_hint(meta, path)}\n\n" + tests +
                f"## Confirmation token for this attempt\nPrint exactly `{token}` only if your check succeeds.\n"
                + history)
        try:
            text, _ = _chat(SYSTEM, user, 12288, model)
            obj = json.loads(text[text.find("{"): text.rfind("}") + 1])
            code, lang, fname = obj.get("code") or "", obj.get("language") or meta["lang"], obj.get("filename") or ""
        except Exception as e:  # noqa: BLE001
            history += f"\n## Attempt {k} failed\nYour answer was not valid JSON ({e}). Respond with JSON only.\n"
            continue
        if reads_source(code):
            history += (f"\n## Attempt {k} rejected\nThe PoC reads or pattern-matches the project's source text. "
                        "That is static analysis, not a proof. Execute the project code with crafted input.\n")
            last = {"code": code, "reason": "read project source instead of executing it"}
            continue
        if not uses_project(code, meta, path):
            history += (f"\n## Attempt {k} rejected\nThe PoC does not import/require the project module for {path}. "
                        "Use the real project code.\n")
            last = {"code": code, "reason": "did not use project code"}
            continue
        try:
            cl = int(cand.get("line"))
        except (TypeError, ValueError):
            cl = None
        target = str(pathlib.Path(meta["src"]) / path) if coverage_gate and cl else None
        res = run_poc(meta, lang, fname, code, "attack", cov_target=target, cov_line=cl)
        last = {"code": code, **res}
        if token in res["stdout"] and target and res.get("covered") is False:
            history += (f"\n## Attempt {k} rejected\nThe PoC printed the token, but the attack run never executed "
                        f"{path} around line {cl}. Exercise the cited code path itself.\n")
            last["coverage"] = False
            continue
        if token in res["stdout"]:
            ctl = run_poc(meta, lang, fname, code, "control")
            last["control_stdout"] = ctl["stdout"][-1500:]
            if token not in ctl["stdout"] and "VULNSCAN_NOT_CONFIRMED" in ctl["stdout"]:
                return {"outcome": "confirmed", "attempts": k, **last}
            why = ("the control run ALSO printed the token, so the check does not depend on the exploit"
                   if token in ctl["stdout"] else "the control run did not finish cleanly with VULNSCAN_NOT_CONFIRMED")
            history += (f"\n## Attempt {k} rejected\nThe attack run printed the token, but {why}. Control stdout "
                        f"tail:\n{ctl['stdout'][-800:]}\nstderr tail:\n{ctl['stderr'][-800:]}\nMake the success "
                        "check depend on what the project code does with the malicious input.\n")
            continue
        if "VULNSCAN_NOT_CONFIRMED" in res["stdout"] and res.get("exit") == 0:
            last["verdict_seen"] = True
            history += (f"\n## Attempt {k}: not confirmed\nstdout tail:\n{res['stdout'][-1200:]}\nIf this failed "
                        "because of setup (invalid unrelated arguments, missing mocks, wrong entry point) rather "
                        "than because the code is actually safe, fix the PoC and try again. If the code is "
                        "genuinely safe against this attack, return the same PoC unchanged.\n")
            continue
        history += (f"\n## Attempt {k} did not reach a verdict\nexit={res.get('exit')} signal={res.get('signal')} "
                    f"timed_out={res.get('timed_out')}\nstdout tail:\n{res['stdout'][-1200:]}\nstderr tail:\n"
                    f"{res['stderr'][-1800:]}\nFix the PoC (imports, setup, mocks) and try again.\n")
    if last.get("verdict_seen"):
        return {"outcome": "not_reproduced", "attempts": attempts,
                **{k: v for k, v in last.items() if k in ("code", "stdout", "stderr", "exit")}}
    return {"outcome": "unverifiable", "attempts": attempts, "reason": "no verdict after repairs",
            **{k: v for k, v in last.items() if k in ("code", "stdout", "stderr", "exit", "signal", "timed_out")}}
