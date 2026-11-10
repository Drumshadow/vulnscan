"""Split GHSA fix records into train / dev / test with repo-level isolation.

Rules (see DATA.md):
  * test and dev hold advisories published on/after --cutoff only, single fix commit, >=1 CWE.
  * The split unit is the repository. A repo chosen for test (or dev) contributes NOTHING to any
    other split, including its pre-cutoff advisories. At most --per-repo advisories are sampled
    from one repo; the rest of that repo's advisories are dropped ("held_unused").
  * train = pre-cutoff advisories from repos in neither test nor dev.
  * Post-cutoff advisories from train repos are dropped (train stays strictly pre-cutoff).
Aborts before writing anything if any repo, commit sha or GHSA id appears in two splits.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import random
import sys


def load(path: pathlib.Path) -> list[dict]:
    return [json.loads(l) for l in path.open()]


def eligible_eval(r: dict, cutoff: str) -> bool:
    return (r["published_at"] or "") >= cutoff and len(r["commits"]) == 1 and bool(r["cwes"])


def pick(repos: list[str], by_repo: dict, cutoff: str, n: int, per_repo: int, rng: random.Random):
    chosen_repos, chosen = [], []
    for repo in repos:
        if len(chosen) >= n:
            break
        cand = [r for r in by_repo[repo] if eligible_eval(r, cutoff)]
        if not cand:
            continue
        rng.shuffle(cand)
        take = cand[: min(per_repo, n - len(chosen))]
        chosen_repos.append(repo)
        chosen.extend(take)
    return chosen_repos, chosen


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixes", default="data/interim/fixes.jsonl")
    ap.add_argument("--out", default="data/splits")
    ap.add_argument("--ecosystems", nargs="+", default=["pip", "npm"])
    ap.add_argument("--cutoff", default="2026-07-01")
    ap.add_argument("--test-n", type=int, default=100)
    ap.add_argument("--dev-n", type=int, default=100)
    ap.add_argument("--per-repo", type=int, default=2)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--exclude-splits", nargs="*", default=[],
                    help="split dirs whose repos (any split) are excluded entirely, e.g. data/splits for wave 2")
    ap.add_argument("--n-by-eco", default="{}", help='per-ecosystem sizes, e.g. {"rust": {"test": 60, "dev": 60}}')
    args = ap.parse_args()

    rng = random.Random(args.seed)
    excluded = set()
    for d in args.exclude_splits:
        for f in pathlib.Path(d).glob("*.jsonl"):
            excluded |= {json.loads(l)["repo"] for l in f.open()}
    recs = [r for r in load(pathlib.Path(args.fixes)) if r["ecosystem"] in args.ecosystems and r["repo"] not in excluded]
    n_by_eco = json.loads(args.n_by_eco)
    # A repo can appear under several ecosystems (e.g. pip + npm); isolation is by repo globally.
    by_repo: dict[str, list[dict]] = collections.defaultdict(list)
    for r in recs:
        by_repo[r["repo"]].append(r)

    splits = {"test": [], "dev": [], "train": []}
    repo_split: dict[str, str] = {}
    for eco in args.ecosystems:
        eco_repos = sorted({r["repo"] for r in recs if r["ecosystem"] == eco and r["repo"] not in repo_split})
        rng.shuffle(eco_repos)
        eco_by_repo = {k: [r for r in by_repo[k] if r["ecosystem"] == eco] for k in eco_repos}
        tn = n_by_eco.get(eco, {}).get("test", args.test_n)
        dn = n_by_eco.get(eco, {}).get("dev", args.dev_n)
        t_repos, t = pick(eco_repos, eco_by_repo, args.cutoff, tn, args.per_repo, rng)
        for k in t_repos:
            repo_split[k] = "test"
        rest = [k for k in eco_repos if k not in repo_split]
        d_repos, d = pick(rest, eco_by_repo, args.cutoff, dn, args.per_repo, rng)
        for k in d_repos:
            repo_split[k] = "dev"
        splits["test"] += t
        splits["dev"] += d
        if len(t) < tn or len(d) < dn:
            print(f"WARNING {eco}: test {len(t)}/{tn} dev {len(d)}/{dn}", file=sys.stderr)

    held_unused = 0
    for r in recs:
        if r["repo"] in repo_split:
            continue
        if (r["published_at"] or "") < args.cutoff and r["commits"]:
            splits["train"].append(r)
        else:
            held_unused += 1

    # ---- leak checks: abort before writing ----
    errors = []
    names = list(splits)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            for key, getter in (("repo", lambda r: {r["repo"]}),
                                ("commit", lambda r: set(r["commits"])),
                                ("ghsa", lambda r: {r["ghsa_id"]})):
                sa = set().union(*(getter(r) for r in splits[a])) if splits[a] else set()
                sb = set().union(*(getter(r) for r in splits[b])) if splits[b] else set()
                ov = sa & sb
                if ov:
                    errors.append(f"{key} overlap {a}/{b}: {len(ov)} e.g. {sorted(ov)[:3]}")
    for s in ("test", "dev"):
        bad = [r["ghsa_id"] for r in splits[s] if (r["published_at"] or "") < args.cutoff]
        if bad:
            errors.append(f"{s} has pre-cutoff advisories: {bad[:3]}")
    bad = [r["ghsa_id"] for r in splits["train"] if (r["published_at"] or "") >= args.cutoff]
    if bad:
        errors.append(f"train has post-cutoff advisories: {bad[:3]}")
    if errors:
        print("LEAK CHECK FAILED; nothing written", *errors, sep="\n  ", file=sys.stderr)
        sys.exit(2)

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stats = {"args": vars(args), "held_unused": held_unused, "excluded_repos": len(excluded), "splits": {}}
    for s, rows in splits.items():
        rows.sort(key=lambda r: r["ghsa_id"])
        with (out / f"{s}.jsonl").open("w") as f:
            for r in rows:
                f.write(json.dumps({**r, "split": s}) + "\n")
        stats["splits"][s] = {
            "advisories": len(rows),
            "repos": len({r["repo"] for r in rows}),
            "by_ecosystem": dict(collections.Counter(r["ecosystem"] for r in rows)),
            "top_cwes": collections.Counter(c for r in rows for c in r["cwes"]).most_common(10),
        }
    (out / "stats.json").write_text(json.dumps(stats, indent=2) + "\n")
    print("leak check passed")
    print(json.dumps(stats["splits"], indent=1))


if __name__ == "__main__":
    main()
