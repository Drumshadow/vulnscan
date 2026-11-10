"""vulnscan CLI.

  vulnscan.py review <repo> <base>..<head> [--out DIR]   review a commit range (a PR)
  vulnscan.py review <repo> --all [--out DIR]            audit the whole codebase at HEAD
Needs the local vLLM (:8000). Never executes code from the reviewed repository.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def main() -> None:
    ap = argparse.ArgumentParser(prog="vulnscan")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review")
    r.add_argument("repo")
    r.add_argument("range", nargs="?")
    r.add_argument("--all", action="store_true", help="audit every source file at HEAD")
    r.add_argument("--out", default="review-out")
    r.add_argument("--opts", help="harness_v2 options as JSON (default: vs/review.py DEFAULT_OPTS)")
    r.add_argument("--no-semgrep", action="store_true")
    r.add_argument("--path", action="append", help="limit to these paths (repeatable), e.g. --path src/server")
    r.add_argument("--dry-run", action="store_true", help="only list the batches that would be reviewed")
    a = ap.parse_args()
    if not a.all and not a.range:
        ap.error("give a range like main..feature, or --all")
    from vs import review
    if a.dry_run:
        for it in review.build_items(pathlib.Path(a.repo), None if a.all else a.range, paths=a.path):
            print(it["id"], len(it["files"]), "files:", it["files"][:4])
        return
    path = review.run(a.repo, None if a.all else a.range, a.out, json.loads(a.opts) if a.opts else None,
                      use_semgrep=not a.no_semgrep, paths=a.path)
    print(f"report: {path}")


if __name__ == "__main__":
    main()
