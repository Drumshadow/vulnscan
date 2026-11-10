"""Rebuild full bench items (diffs) from the released metadata, then verify they match our frozen files.

Clones each repo (blobless, bare) and regenerates:
  regression items: git diff base..head restricted to `files`, then scripts/sanitize_bench.py's sanitize()
  new-code items:   nothing to regenerate (views are read from git at review time)
  --verify          compare regenerated regression diffs against data/bench/<split>.jsonl (maintainers only)

  rebuild_from_release.py <release_dir> --repos data/repos [--verify]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent)); sys.path.insert(0, str(HERE))
from materialize import ensure_clone, git, resolve  # noqa: E402
from sanitize_bench import sanitize  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("release")
    ap.add_argument("--repos", default="data/repos")
    ap.add_argument("--out", default="data/rebuilt")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    rel, root, out = pathlib.Path(args.release), pathlib.Path(args.repos), pathlib.Path(args.out)
    root.mkdir(parents=True, exist_ok=True); out.mkdir(parents=True, exist_ok=True)
    for split in ("dev", "test"):
        items = [json.loads(l) for l in (rel / "regression" / f"{split}.jsonl").open()]
        bad = 0
        with (out / f"{split}.jsonl").open("w") as f:
            for it in items:
                d = ensure_clone(root, it["repo"])
                for sha in (it["base"], it["head"]):
                    resolve(d, sha)
                raw = git(d, "diff", "-U3", "--no-renames", "--no-color", it["base"], it["head"], "--", *it["files"])
                it["diff"] = sanitize(raw)
                f.write(json.dumps(it) + "\n")
        if args.verify:
            ours = {json.loads(l)["id"]: json.loads(l)["diff"] for l in (HERE.parent / "data/bench" / f"{split}.jsonl").open()}
            with (out / f"{split}.jsonl").open() as f:
                for line in f:
                    it = json.loads(line)
                    if ours.get(it["id"]) != it["diff"]:
                        bad += 1
            print(f"{split}: {len(items)} rebuilt, {bad} differ from the frozen bench")
        else:
            print(f"{split}: {len(items)} rebuilt")


if __name__ == "__main__":
    main()
