"""Pre-download the blobs of every bench commit into the blobless clones, in one batch per repo.

Blobless clones fetch each missing blob lazily, one round trip at a time, which made harness `git grep`
call-site lookups time out on large repos. This only changes speed: reviews read the same content either way.
Uses the same mechanism as git's own lazy fetch (blob ids on stdin to a promisor fetch); git 2.43 has no
`git backfill`.

  hydrate.py [--splits dev test dev_nc test_nc] [--workers 4]
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import BENCH, REPOS  # noqa: E402


def missing(d: pathlib.Path, sha: str) -> list[str]:
    r = subprocess.run(["git", "-C", str(d), "rev-list", "--objects", "--missing=print", sha],
                       capture_output=True, text=True, timeout=1800)
    return [l[1:].split()[0] for l in r.stdout.splitlines() if l.startswith("?")]


def hydrate(repo: str, shas: set[str]) -> tuple[str, int, int]:
    d = REPOS / repo.replace("/", "__")
    oids = sorted({o for s in shas for o in missing(d, s)})
    for i in range(0, len(oids), 5000):
        subprocess.run(["git", "-C", str(d), "-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "origin",
                        "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin"],
                       input="\n".join(oids[i:i + 5000]) + "\n", text=True, capture_output=True, timeout=3600,
                       env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin"})
    left = sum(len(missing(d, s)) for s in shas)
    return repo, len(oids), left


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits", nargs="+", default=["dev", "test", "dev_nc", "test_nc"])
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    by_repo: dict[str, set[str]] = collections.defaultdict(set)
    for s in args.splits:
        for line in (BENCH / f"{s}.jsonl").open():
            it = json.loads(line)
            by_repo[it["repo"]].add(it["head"])
            if it.get("base"):
                by_repo[it["repo"]].add(it["base"])
    print(f"{len(by_repo)} repos, {sum(map(len, by_repo.values()))} commits", flush=True)
    total_left = 0
    with cf.ThreadPoolExecutor(args.workers) as ex:
        for n, (repo, fetched, left) in enumerate(ex.map(lambda kv: hydrate(*kv), by_repo.items()), 1):
            total_left += left
            if left or n % 25 == 0:
                print(f"  [{n}/{len(by_repo)}] {repo}: fetched {fetched} blobs, still missing {left}", flush=True)
    print(f"done; blobs still missing across all commits: {total_left}", flush=True)


if __name__ == "__main__":
    main()
