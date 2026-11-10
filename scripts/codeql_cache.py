"""Build CodeQL security-extended SARIF for each (repo, head) of a bench sample; cached in data/codeql-cache.
CodeQL's Python/JS extractors read source only (no build, no dependency install), so nothing from the
reviewed repo is executed. Per-repo time cap; failures are logged and skipped (the analyzer then gives no hints).

  codeql_cache.py --split dev_nc --sample frontier [--workers 3] [--timeout 900]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import pathlib
import shutil
import subprocess
import sys
import os
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import ROOT, load_items, repo_dir, sample_ids  # noqa: E402

CODEQL = ROOT / "tools" / "codeql" / "codeql"
# TypeScript extraction needs node; tools/node is the checksum-verified official arm64 build (v22 LTS)
ENV = {**os.environ, "PATH": f"{ROOT / 'tools' / 'node' / 'bin'}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
CACHE = ROOT / "data" / "codeql-cache"
SUITES = {"python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
          "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"}


def langs(files: list[str]) -> set[str]:
    return {"python" if f.endswith(".py") else "javascript" for f in files}


def build(repo: str, head: str, ls: set[str], timeout: int) -> tuple[str, str]:
    out = CACHE / f"{repo.replace('/', '__')}@{head[:16]}.sarif"
    if out.exists():
        return repo, "cached"
    work = pathlib.Path(tempfile.mkdtemp(prefix="vs-cq-", dir="/tmp"))
    try:
        src = work / "src"; src.mkdir()
        arch = subprocess.run(["git", "-C", str(repo_dir(repo)), "archive", head], capture_output=True, timeout=1800)
        subprocess.run(["tar", "-x", "-C", str(src)], input=arch.stdout, check=True, timeout=600)
        runs = []
        for lang in sorted(ls):
            db = work / f"db-{lang}"
            r = subprocess.run([str(CODEQL), "database", "create", str(db), f"--language={lang}", f"--source-root={src}",
                                "--threads=4", "--overwrite"], capture_output=True, text=True, timeout=timeout, env=ENV)
            if r.returncode != 0:
                return repo, f"create {lang} failed: {r.stderr[-200:]}"
            sarif = work / f"{lang}.sarif"
            r = subprocess.run([str(CODEQL), "database", "analyze", str(db), SUITES[lang], "--format=sarif-latest",
                                f"--output={sarif}", "--threads=4", "--ram=4000"], capture_output=True, text=True, timeout=timeout, env=ENV)
            if r.returncode != 0:
                return repo, f"analyze {lang} failed: {r.stderr[-200:]}"
            runs += json.loads(sarif.read_text()).get("runs", [])
        CACHE.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"runs": runs}))
        return repo, f"ok ({sum(len(r.get('results', [])) for r in runs)} alerts)"
    except subprocess.TimeoutExpired:
        return repo, "timeout"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev_nc")
    ap.add_argument("--sample", default="frontier")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    jobs = {}
    for it in load_items(a.split):
        if it["id"] in sample_ids(a.split, a.sample):
            jobs.setdefault((it["repo"], it["head"]), set()).update(langs(it["files"]))
    todo = list(jobs.items())[: a.limit or None]
    print(f"{len(todo)} (repo, commit) builds", flush=True)
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for n, (repo, status) in enumerate(ex.map(lambda kv: build(kv[0][0], kv[0][1], kv[1], a.timeout), todo), 1):
            print(f"  [{n}/{len(todo)}] {repo}: {status}", flush=True)


if __name__ == "__main__":
    main()
