"""`vulnscan review`: run the harness on a real repository and commit range (or a whole codebase).

Builds bench-shaped items in the regression framing (diff + head checkout), batched so each item stays within
the limits the harness was evaluated on (<= 10 files, <= 400 changed lines). Findings are unverified model
output; the report says so.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import subprocess
import sys

from .bench import file_at

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
from materialize import keep_file  # noqa: E402

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
DEFAULT_OPTS = None  # None = the frozen reviewer: harness v1 investigator-only (vs/harness.py), semgrep hints.
# Chosen 2026-11-06 by the pre-stated rule (best pair accuracy with benign flags <= 30%, adopted only if the
# repo-disjoint check set agrees). No v2 lever passed; see writeup/draft.md.


SAFE_GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "diff.external=",
            "-c", "core.pager=cat"]  # a reviewed repo's own .git/config must never run code


def git(repo: pathlib.Path, *args: str) -> str:
    r = subprocess.run([*SAFE_GIT, "-C", str(repo), "--no-pager", *args], capture_output=True, text=True,
                       timeout=600, env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "HOME": "/nonexistent"})
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])}: {r.stderr.strip()[:300]}")
    return r.stdout


GENERATED_RE = re.compile(r"(^|/)(dist|build|vendor|node_modules|static/assets|third_party)/|\.min\.[cm]?js$|\.d\.ts$")


def _generated(repo: pathlib.Path, sha: str, path: str) -> bool:
    """Built, vendored, minified or type-stub files are not reviewed (long average line = minified)."""
    if GENERATED_RE.search(path):
        return True
    text = file_at(str(repo), sha, path) or ""
    lines = text.splitlines() or [""]
    return len(text) / len(lines) > 300


def build_items(repo: pathlib.Path, rng: str | None, max_files: int = 10, max_lines: int = 400,
                paths: list[str] | None = None) -> list[dict]:
    repo = repo.resolve()
    if rng is None:  # audit the whole codebase at HEAD as if newly added
        base, head = EMPTY_TREE, git(repo, "rev-parse", "HEAD").strip()
    else:
        a, _, b = rng.partition("..")
        base = git(repo, "rev-parse", "--verify", f"{a}^{{commit}}").strip()
        head = git(repo, "rev-parse", "--verify", f"{b or 'HEAD'}^{{commit}}").strip()
    names = [n for n in git(repo, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames",
                            "--diff-filter=AM", base, head, "--", *(paths or [])).splitlines()
             if n and keep_file(n) and not _generated(repo, head, n)]
    sizes = {}
    for line in git(repo, "diff", "--no-ext-diff", "--no-textconv", "--numstat", "--no-renames", base, head, "--", *names).splitlines() if names else []:
        add, _rem, path = line.split("\t", 2)
        sizes[path] = int(add) if add.isdigit() else 0
    batches, cur, cur_lines = [], [], 0
    for n in names:
        sz = sizes.get(n, 0)
        if cur and (len(cur) >= max_files or cur_lines + sz > max_lines):
            batches.append(cur); cur, cur_lines = [], 0
        cur.append(n); cur_lines += sz
    if cur:
        batches.append(cur)
    items = []
    for i, files in enumerate(batches):
        if rng is None:
            # whole-codebase audit: new-code framing (files shown once, whole, with line numbers), the framing
            # the harness is tuned on; no diff to duplicate them
            views = {f: [[1, max(1, len((file_at(str(repo), head, f) or "").splitlines()))]] for f in files}
            items.append({"id": f"review:{i}", "kind": "review", "repo": str(repo), "base": None, "head": head,
                          "files": files, "views": views, "diff": "", "truth": {}, "framing": "newcode"})
            continue
        diff = git(repo, "diff", "--no-ext-diff", "--no-textconv", "-U3", "--no-renames", "--no-color", base, head, "--", *files)
        items.append({"id": f"review:{i}", "kind": "review", "repo": str(repo), "base": base, "head": head,
                      "files": files, "diff": diff, "truth": {}, "framing": "regression"})
    return items


def _excerpt(item, path, line, ctx=3) -> str:
    lines = (file_at(item["repo"], item["head"], path) or "").splitlines()
    try:
        ln = int(line)
    except (TypeError, ValueError):
        return ""
    lo, hi = max(1, ln - ctx), min(len(lines), ln + ctx)
    return "\n".join(f"{'>' if i == ln else ' '}{i:5d}  {lines[i - 1]}" for i in range(lo, hi + 1))


def run(repo: str, rng: str | None, out: str, opts: dict | None = None, use_semgrep: bool = True,
        paths: list[str] | None = None) -> pathlib.Path:
    from . import harness, harness_v2
    from .arms import semgrep_arm
    opts = opts or DEFAULT_OPTS
    items = build_items(pathlib.Path(repo), rng, paths=paths)
    sg = semgrep_arm.review if use_semgrep else None
    review = (harness_v2.make_review(opts, semgrep_review=sg) if opts
              else harness.make_review(semgrep_review=sg, refute=None))
    findings, errors = [], []
    for n, it in enumerate(items, 1):
        print(f"  batch {n}/{len(items)}: {len(it['files'])} files", flush=True)
        try:
            fs, _ = review(it)
        except Exception as e:  # noqa: BLE001
            errors.append({"batch": n, "files": it["files"], "error": str(e)[:300]}); continue
        for f in fs:
            findings.append({**f, "excerpt": _excerpt(it, f.get("file"), f.get("line")), "batch": n})
    findings.sort(key=lambda f: -(float(f.get("confidence") or 0)))
    outdir = pathlib.Path(out); outdir.mkdir(parents=True, exist_ok=True)
    meta = {"repo": str(pathlib.Path(repo).resolve()), "range": rng or "(whole codebase at HEAD)",
            "head": items[0]["head"] if items else None, "batches": len(items),
            "reviewer": opts or "frozen harness v1 (investigator only, semgrep hints)",
            "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "errors": errors}
    (outdir / "findings.json").write_text(json.dumps({"meta": meta, "findings": findings}, indent=2) + "\n")
    md = [f"# Security review: {pathlib.Path(repo).name}", "",
          f"Range: `{meta['range']}` · head `{(meta['head'] or '')[:12]}` · {len(items)} batches · "
          f"generated {meta['generated']}", "",
          f"Reviewer: {meta['reviewer']}", "",
          "**Unverified model output.** Each finding is a hypothesis from a local model (vulnscan). "
          "Confirm reachability and impact by hand before acting on it or reporting it.", ""]
    if errors:
        md += [f"> {len(errors)} batch(es) failed; see findings.json.", ""]
    if not findings:
        md += ["No findings."]
    for k, f in enumerate(findings, 1):
        md += [f"## {k}. {f.get('title') or 'Finding'}", "",
               f"- **Location:** `{f.get('file')}:{f.get('line')}`",
               f"- **Weakness:** {f.get('cwe') or 'unspecified'}",
               f"- **Model confidence:** {f.get('confidence') if f.get('confidence') is not None else 'n/a'}", "",
               (f.get("explanation") or "").strip(), ""]
        if f.get("excerpt"):
            md += ["```", f["excerpt"], "```", ""]
    (outdir / "report.md").write_text("\n".join(md) + "\n")
    return outdir / "report.md"


