"""Reproducible versions of two analyses cited in the writeup.
  evidence_extra.py ensemble   # Nemotron vs Qwen on tune: alone, union, both-agree (paired vs harness v1)
  evidence_extra.py misses     # dev_nc vulnerable items missed by ours, Codex and Claude: behaviour taxonomy
"""
from __future__ import annotations

import collections
import json
import pathlib
import statistics as S
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from combine_harness import clusters, paired_ci, per_pair  # noqa: E402
from vs import cwe as C, store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.score import judge_item, metrics, norm_path  # noqa: E402

BASE = "harness_inv:dev_nc:af0d92409c"


def raws(db, rid):
    return {i: json.loads(r or "{}") for i, r in db.execute("select item_id, raw from items where run_id=? and ok=1", (rid,))}


def cands(r, name):
    return next((p["candidates"] for p in r.get("passes", []) if p["name"] == name), [])


def ensemble(db):
    items = [i for i in load_items("dev_nc") if i["id"] in sample_ids("dev_nc", "tune")]
    nem, h1 = raws(db, "harness_v2:dev_nc:24d3422811"), raws(db, "harness_v2:dev_nc:089bd80b2f")
    base, _ = store.load_findings(db, BASE)
    ids = set(nem) | set(h1)
    two = lambda i: clusters([("q", cands(h1.get(i, {}), "main")), ("n", cands(nem.get(i, {}), "nemotron"))])  # noqa: E731
    variants = {"nemotron alone": {i: cands(r, "nemotron") for i, r in nem.items()},
                "qwen (context fix) alone": {i: cands(r, "main") for i, r in h1.items()},
                "union": {i: [c["cand"] for c in two(i)] for i in ids},
                "both agree": {i: [c["cand"] for c in two(i) if len(c["passes"]) == 2] for i in ids}}
    bp = per_pair(items, base)
    print("# Local ensemble on tune (96 pairs + 50 ordinary commits), paired vs harness v1\n")
    print("| variant | pair acc | recall | ordinary flagged | delta vs v1 (95% CI) |\n|---|---|---|---|---|")
    for n, f in variants.items():
        m = metrics([(i, judge_item(i, f.get(i["id"], []))) for i in items])
        d, lo, hi, _ = paired_ci(per_pair(items, f), bp)
        print(f"| {n} | {m['pair_acc']:.0%} | {m['recall_strict']:.0%} | {m['benign_flag_rate']:.0%} | {d:+.1%} ({lo:+.1%}..{hi:+.1%}) |")


def misses(db):
    items = [i for i in load_items("dev_nc") if i["id"] in sample_ids("dev_nc", "frontier")]
    runs = {"ours": BASE, "codex": "codex:dev_nc:b0647dc368", "claude": "claude:dev_nc:e5968e37dd"}
    F = {k: store.load_findings(db, r)[0] for k, r in runs.items()}
    vul = [i for i in items if i["kind"] == "nc_vuln"]
    hit = lambda k, it: judge_item(it, F[k].get(it["id"], []))["hit_strict"]  # noqa: E731
    allmiss = [i for i in vul if not any(hit(k, i) for k in runs)]
    fam = collections.Counter(sorted({C.family(c) for c in i["cwes"]})[0] if i["cwes"] else "none" for i in allmiss)
    silent = sum(all(not F[k].get(i["id"]) for k in runs) for i in allmiss)
    consensus, in_truth = 0, 0
    for it in allmiss:
        tf, tfam = {norm_path(k) for k in it["truth"]}, {C.family(c) for c in it["cwes"]}
        agree = collections.Counter(x for k in runs for x in {(norm_path(f.get("file")), C.family(f.get("cwe"))) for f in F[k].get(it["id"], [])})
        top = [x for x, n in agree.items() if n >= 2]
        consensus += bool(top)
        in_truth += any(x[0] in tf and x[1] in tfam for x in top)
    fix = {json.loads(l)["ghsa_id"]: json.loads(l)["changed_lines"] for l in open("data/bench/dev.jsonl") if json.loads(l)["kind"] == "fix"}
    am = {i["id"] for i in allmiss}
    sz_m = [fix[i["ghsa_id"]] for i in allmiss if i["ghsa_id"] in fix]
    sz_h = [fix[i["ghsa_id"]] for i in vul if i["id"] not in am and i["ghsa_id"] in fix]
    print(f"# Dev vulnerabilities missed by all three reviewers (line window)\n\nMissed by all: {len(allmiss)} of {len(vul)}")
    print(f"Every reviewer silent: {silent}\n>=2 reviewers agree on file+family: {consensus}; of those in the truth file+family: {in_truth}")
    print(f"Families: {fam.most_common(8)}\nMedian fix size (changed lines): all-miss {S.median(sz_m)}, caught by someone {S.median(sz_h)}")


def poc(db):
    """PoC verification v1 outcomes on vulnerable-version candidates, split by whether the candidate is the advisory's
    bug (line-window hit / semantic-judge match / neither)."""
    items = {i["id"]: i for i in load_items("dev_nc") if i["id"] in sample_ids("dev_nc", "tune")}
    rid = "harness_v2:dev_nc:089bd80b2f"
    F, _ = store.load_findings(db, rid)
    V = {(a, b): o for a, b, o in db.execute("select item_id, idx, outcome from verifications where run_id=?", (rid,))}
    J = {(a, b): m for a, b, m in db.execute("select item_id, idx, match from judgments where run_id=? and judge='j1'", (rid,))}
    c = collections.defaultdict(collections.Counter)
    for iid, fs in F.items():
        it = items.get(iid)
        if not it or it["kind"] != "nc_vuln":
            continue
        for idx, f in enumerate(fs):
            cls = ("line-window hit" if judge_item(it, [f])["hit_strict"] else
                   "semantic match only" if J.get((iid, idx)) else "not the advisory bug")
            c[cls][V.get((iid, idx), "unchecked")] += 1
    print("# PoC verification v1: outcome on vulnerable-version candidates (tune)\n")
    print("| candidate is | n | confirmed | not reproduced | unverifiable |\n|---|---|---|---|---|")
    for cls, cc in c.items():
        print(f"| {cls} | {sum(cc.values())} | {cc['confirmed']} | {cc['not_reproduced']} | {cc['unverifiable']} |")


if __name__ == "__main__":
    db = store.connect()
    {"ensemble": ensemble, "misses": misses, "poc": poc}[sys.argv[1]](db)
