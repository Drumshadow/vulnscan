"""Headline tables for the release: the fix-after-cutoff subset (the only pairs where "no model trained on this
fix" can hold) beside all pairs. Repo-cluster bootstrap CIs on pair-level outcomes.

  headline.py [--nc test_nc] [--reg test] [--cutoff 2026-07-01] > evidence/headline-<wave>.md
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from judge import load_judgments, semantic, twin  # noqa: E402
from release_checks import ARMS, commit_date  # noqa: E402
from vs import store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.score import ROLE, judge_item  # noqa: E402


def ci(pairs: list[tuple[str, bool]], iters: int = 2000, seed: int = 0) -> tuple[float, float]:
    by = collections.defaultdict(list)
    for repo, ok in pairs:
        by[repo].append(ok)
    repos = sorted(by)
    rng = random.Random(seed)
    vals = []
    for _ in range(iters):
        draw = [x for r in (rng.choice(repos) for _ in repos) for x in by[r]]
        vals.append(sum(draw) / max(len(draw), 1))
    vals.sort()
    return vals[int(0.025 * iters)], vals[int(0.975 * iters)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nc", default="test_nc")
    ap.add_argument("--reg", default="test")
    ap.add_argument("--cutoff", default="2026-07-01")
    ap.add_argument("--out-pairs", default="")
    a = ap.parse_args()
    db = store.connect()
    items = [i for i in load_items(a.nc) if i["id"] in sample_ids(a.nc, "frontier")]
    after = set()
    for it in items:
        if it["kind"] == "nc_fixed":
            _, c = commit_date(it["repo"], it["head"])
            if c and c[:10] >= a.cutoff:
                after.add(it["pair"])
    all_pairs = {i["pair"] for i in items if i.get("pair")}
    print(f"# Headline tables: {a.nc}\n\n{len(after)} of {len(all_pairs)} pairs have a fix committed on/after {a.cutoff}. "
          f"Ordinary commits in the sample: {sum(i['kind'] == 'nc_benign' for i in items)}.\n")
    if a.out_pairs:
        pathlib.Path(a.out_pairs).write_text(json.dumps(sorted(after), indent=0) + "\n")
    for title, keep in ((f"Fix committed after {a.cutoff} (headline)", after), ("All pairs", all_pairs)):
        print(f"## {title}\n\n| reviewer | pairs | pair acc, semantic (95% CI) | pair acc, line window (95% CI) | recall, semantic | recall, line window | patched still flagged, semantic | ordinary commits flagged |\n|---|---|---|---|---|---|---|---|")
        for k, (h, _) in ARMS.items():
            rid = f"{k}:{a.nc}:{h}"
            F, _e = store.load_findings(db, rid)
            r = semantic(items, F, load_judgments(db, rid))
            assert not r["missing"] and not r["unjudged"], f"{rid}: incomplete semantic results"
            absent = [i["id"] for i in items if i["id"] not in F]
            assert not absent, f"{rid}: {len(absent)} sampled items have no stored result, e.g. {absent[:3]}"
            pos = [i for i in items if i["kind"] == "nc_vuln" and i["pair"] in keep]
            J = {i["id"]: judge_item(i, F[i["id"]]) for i in items if i["id"] in F}
            sem_ok = [(i["repo"], r["sem"][i["id"]] and not r["sem"][twin(i["id"])]) for i in pos]
            lin_ok = [(i["repo"], J[i["id"]]["hit_strict"] and not J[twin(i["id"])]["site_flag"]) for i in pos]
            rate = lambda xs: sum(x for _, x in xs) / len(xs)  # noqa: E731
            s_lo, s_hi = ci(sem_ok); l_lo, l_hi = ci(lin_ok)
            ben = [i for i in items if i["kind"] == "nc_benign"]
            print(f"| {k} | {len(pos)} | {rate(sem_ok):.0%} ({s_lo:.0%}-{s_hi:.0%}) | {rate(lin_ok):.0%} ({l_lo:.0%}-{l_hi:.0%}) | "
                  f"{sum(r['sem'][i['id']] for i in pos) / len(pos):.0%} | {sum(J[i['id']]['hit_strict'] for i in pos) / len(pos):.0%} | "
                  f"{sum(r['sem'][twin(i['id'])] for i in pos) / len(pos):.0%} | {sum(J[i['id']]['flagged'] for i in ben) / len(ben):.0%} |")
        print()
    print("## Same advisories, two framings (line-window recall)\n\n| reviewer | reversed-fix | new-code | ratio |\n|---|---|---|---|")
    reg = [i for i in load_items(a.reg) if i["id"] in sample_ids(a.reg, "frontier") and i["kind"] == "vuln_intro" and i["ghsa_id"] in after]
    nc = [i for i in items if i["kind"] == "nc_vuln" and i["pair"] in after]
    for k, (h, _) in ARMS.items():
        rrow = db.execute("SELECT 1 FROM runs WHERE run_id=?", (f"{k}:{a.reg}:{h}",)).fetchone()
        if not rrow:
            print(f"| {k} | not run | | |"); continue
        Fr, _e = store.load_findings(db, f"{k}:{a.reg}:{h}")
        Fn, _e = store.load_findings(db, f"{k}:{a.nc}:{h}")
        assert all(i["id"] in Fr for i in reg) and all(i["id"] in Fn for i in nc), f"{k}: missing stored results"
        rr = sum(judge_item(i, Fr[i["id"]])["hit_strict"] for i in reg) / len(reg)
        rn = sum(judge_item(i, Fn[i["id"]])["hit_strict"] for i in nc) / len(nc)
        print(f"| {k} | {rr:.0%} (n={len(reg)}) | {rn:.0%} (n={len(nc)}) | {rr / rn:.1f}x |" if rn else f"| {k} | {rr:.0%} | 0% | n/a |")


if __name__ == "__main__":
    main()
