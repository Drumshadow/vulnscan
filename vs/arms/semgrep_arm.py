"""semgrep OSS baseline, diff-aware like `semgrep ci`: scan the changed files at base and at head with the
pinned semgrep-rules checkout, report head findings whose (rule, file, line text) did not exist at base.

semgrep OSS no longer returns matched source text ("requires login"), so line text is read from the file.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile

from ..bench import ROOT, file_at

SEMGREP = ROOT / "tools" / "semgrep-venv" / "bin" / "semgrep"
RULES = ROOT / "tools" / "semgrep-rules"
LANG_RULES = {
    ".py": ["python"], ".go": ["go"], ".rs": ["rust"],
    ".c": ["c"], ".h": ["c"], ".cc": ["c"], ".cpp": ["c"], ".cxx": ["c"], ".hpp": ["c"], ".hh": ["c"],
    ".js": ["javascript"], ".mjs": ["javascript"], ".cjs": ["javascript"], ".jsx": ["javascript"],
    ".ts": ["javascript", "typescript"], ".tsx": ["javascript", "typescript"],
    ".mts": ["javascript", "typescript"], ".cts": ["javascript", "typescript"],
}


def _scan(root: pathlib.Path, rule_dirs: list[str]) -> list[dict]:
    if not any(root.rglob("*")):
        return []
    cmd = [str(SEMGREP), "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
           "--timeout", "30", "--jobs", "2", "--no-git-ignore"]
    for d in rule_dirs:
        cmd += ["--config", str(RULES / d)]
    cmd.append(str(root))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                       env={"PATH": f"{SEMGREP.parent}:/usr/bin:/bin", "HOME": str(ROOT / "tools"),
                            "SEMGREP_SEND_METRICS": "off"})
    if r.returncode not in (0, 1):
        raise RuntimeError(f"semgrep rc={r.returncode}: {r.stderr[-400:]}")
    return json.loads(r.stdout).get("results", [])


def _key(res: dict, root: pathlib.Path, texts: dict[str, list[str]]) -> tuple[str, str, str]:
    rel = str(pathlib.Path(res["path"]).resolve().relative_to(root.resolve()))
    lines = texts.get(rel, [])
    ln = res["start"]["line"]
    text = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""
    return res["check_id"].rsplit(".", 1)[-1], rel, text


def _cwe(res: dict) -> str | None:
    c = (res.get("extra", {}).get("metadata") or {}).get("cwe")
    if isinstance(c, list):
        c = c[0] if c else None
    return c


def review(item: dict) -> tuple[list[dict], dict]:
    rule_dirs = sorted({d for f in item["files"] for d in LANG_RULES.get(pathlib.PurePosixPath(f).suffix.lower(), [])})
    with tempfile.TemporaryDirectory(prefix="vs-sg-") as td:
        base_root, head_root = pathlib.Path(td, "base"), pathlib.Path(td, "head")
        texts = {"base": {}, "head": {}}
        sides = [("head", head_root, item["head"])]
        if item.get("base"):
            sides.insert(0, ("base", base_root, item["base"]))
        for side, root, sha in sides:
            for f in item["files"]:
                content = file_at(item["repo"], sha, f)
                if content is None:
                    continue
                p = root / f
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
                texts[side][f] = content.splitlines()
        base_res = _scan(base_root, rule_dirs) if item.get("base") else []
        head_res = _scan(head_root, rule_dirs)
        base_keys = {_key(r, base_root, texts["base"]) for r in base_res}
        findings = []
        for r in head_res:
            k = _key(r, head_root, texts["head"])
            if k in base_keys:
                continue
            views = item.get("views")
            if views is not None and not any(a <= r["start"]["line"] <= b for a, b in views.get(k[1], [])):
                continue  # outside what the reviewer was shown (parity with the LLM arms)
            sev = r.get("extra", {}).get("severity", "")
            findings.append({"file": k[1], "line": r["start"]["line"], "cwe": _cwe(r),
                             "title": f"[{sev}] {r['check_id']}",
                             "explanation": (r.get("extra", {}).get("message") or "")[:1000]})
    return findings, {"raw": json.dumps({"n_base": len(base_res), "n_head": len(head_res)})}


CONFIG = {"tool": "semgrep", "rules": "semgrep-rules@16b9e6d", "mode": "diff-aware(base vs head, changed files)"}
