"""Stage the benchmark for release WITHOUT third-party code: metadata only (advisory ids, repos, commit
shas, files, view windows, truth / fix-site lines, leak flags). scripts/rebuild_from_release.py
regenerates every diff and view from the shas.

  stage_release.py [--out hf_staging/dataset]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import BENCH  # noqa: E402

KEEP = ["id", "kind", "framing", "repo", "ecosystem", "ghsa_id", "cve_id", "cwes", "published_at", "severity",
        "base", "head", "files", "views", "truth", "fix_site", "pair", "leak", "changed_lines", "shown_lines"]
FILES = {"dev": "regression/dev.jsonl", "test": "regression/test.jsonl",
         "dev_nc": "newcode/dev.jsonl", "test_nc": "newcode/test.jsonl"}


SAFE_STR = re.compile(r"^[\w@./:+~\- ]{0,300}$")
LEAK_KEYS = {"code", "comment", "cve_id"}
PATH_STR = re.compile(r"^[^\n\r\t]{1,400}$")  # real paths hold $ [ ] ( ) (Next.js routes); one bounded line only


def _lines(v) -> bool:
    return isinstance(v, list) and all(type(x) is int for x in v)


CHECKS = {
    "cwes": lambda v: isinstance(v, list) and all(isinstance(x, str) and re.fullmatch(r"CWE-\d+", x) for x in v),
    "files": lambda v: isinstance(v, list) and all(isinstance(x, str) and PATH_STR.match(x) for x in v),
    "truth": lambda v: isinstance(v, dict) and all(PATH_STR.match(k) and _lines(x) for k, x in v.items()),
    "fix_site": lambda v: isinstance(v, dict) and all(PATH_STR.match(k) and _lines(x) for k, x in v.items()),
    "views": lambda v: isinstance(v, dict) and all(PATH_STR.match(k) and all(_lines(w) and len(w) == 2 for w in x) for k, x in v.items()),
    "leak": lambda v: isinstance(v, dict) and set(v) <= LEAK_KEYS and all(type(x) is bool for x in v.values()),
    "changed_lines": lambda v: type(v) is int,
    "shown_lines": lambda v: type(v) is int,
}


_TREES: dict = {}


def tree(repo: str, sha: str | None) -> set[str]:
    """All paths in the repo at a commit (cached). Published paths must be real paths, not free text."""
    if not sha:
        return set()
    key = (repo, sha)
    if key not in _TREES:
        import subprocess
        from vs.bench import repo_dir
        r = subprocess.run(["git", "-C", str(repo_dir(repo)), "ls-tree", "-r", "--name-only", sha],
                           capture_output=True, text=True, errors="replace", timeout=300)
        _TREES[key] = set(r.stdout.splitlines())
    return _TREES[key]


def assert_paths_exist(rec: dict) -> None:
    paths = set(rec.get("files") or []) | set((rec.get("truth") or {})) | set((rec.get("fix_site") or {})) | set((rec.get("views") or {}))
    known = tree(rec["repo"], rec.get("head")) | tree(rec["repo"], rec.get("base"))
    missing = paths - known
    assert not missing, f"{rec.get('id')}: paths not in the repository at base/head: {sorted(missing)[:3]}"


def assert_metadata_only(rec: dict) -> None:
    """Allow-list on every published value: ints, booleans, ids and paths. Prose or code cannot pass."""
    unknown = set(rec) - set(KEEP)
    assert not unknown, f"unexpected fields {unknown}"
    for k, v in rec.items():
        if v is None:
            continue
        ok = CHECKS[k](v) if k in CHECKS else (isinstance(v, str) and SAFE_STR.match(v) is not None)
        assert ok, f"{rec.get('id')}: field {k} is not plain metadata: {str(v)[:80]!r}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="hf_staging/dataset")
    ap.add_argument("--skip-tree-check", action="store_true", help="tests only: skip the git path check")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    if out.exists():
        shutil.rmtree(out)  # the release is exactly what this run writes
    manifest = {}
    for split, rel in FILES.items():
        src = BENCH / f"{split}.jsonl"
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with dst.open("w") as f:
            for line in src.open():
                it = json.loads(line)
                if it.get("framing") != "newcode":
                    it.setdefault("framing", "regression")
                rec = {k: it[k] for k in KEEP if k in it}
                assert_metadata_only(rec)
                if not args.skip_tree_check:
                    assert_paths_exist(rec)
                f.write(json.dumps(rec, sort_keys=True) + "\n")
                n += 1
        manifest[rel] = {"items": n, "source_sha256": hashlib.sha256(src.read_bytes()).hexdigest(),
                         "sha256": hashlib.sha256(dst.read_bytes()).hexdigest()}
        print(f"{rel}: {n} items")
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
