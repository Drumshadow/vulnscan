"""Score combinations of stored harness_v2 passes offline and compare each with a baseline run, paired.

  combine_harness.py <v2_run_id> --baseline harness_inv:dev_nc:af0d92409c --sample tune [--split dev_nc]

Combinations (from raw["passes"]):
  main1            first investigator sample only (= prompt/context ablation without extra passes)
  union_k          union of all main samples
  vote2            main-sample clusters found by >= 2 distinct samples
  +lenses          the above plus every lens candidate
Clusters: same file, line within +-5, same CWE family. Paired difference in pair accuracy vs the baseline on
the same pairs, with a repo-cluster bootstrap 95% CI.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs import cwe as cwemod  # noqa: E402
from vs import store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.score import judge_item, metrics  # noqa: E402


def clusters(passes: list[tuple[str, list[dict]]], window: int = 5) -> list[dict]:
    out: list[dict] = []
    for pname, cands in passes:
        for c in cands:
            try:
                ln = int(c.get("line"))
            except (TypeError, ValueError):
                ln = None
            hit = None
            for o in out:
                if (o["file"] == c.get("file") and ln is not None and o["line"] is not None
                        and abs(o["line"] - ln) <= window and o["fam"] == cwemod.family(c.get("cwe"))):
                    hit = o
                    break
            if hit:
                hit["passes"].add(pname)
                if float(c.get("confidence") or 0) > hit["conf"]:
                    hit.update(cand=c, conf=float(c.get("confidence") or 0))
            else:
                out.append({"file": c.get("file"), "line": ln, "fam": cwemod.family(c.get("cwe")), "passes": {pname},
                            "cand": c, "conf": float(c.get("confidence") or 0)})
    return out


def combos(raw: dict) -> dict[str, list[dict]]:
    passes = raw.get("passes") or [{"name": "main", "candidates": raw.get("candidates", [])}]
    mains = [(f"{p['name']}:{p.get('seed')}", p["candidates"]) for p in passes if p["name"] == "main"]
    lenses = [(p["name"], p["candidates"]) for p in passes if p["name"].startswith("lens_")]
    extras = [(p["name"], p["candidates"]) for p in passes if p["name"] in ("twostep", "invariants", "nemotron", "sft7b")]
    k = len(mains)
    sel = {
        "main1": clusters(mains[:1]),
        f"union{k}": clusters(mains),
        "vote2": [c for c in clusters(mains) if len(c["passes"]) >= 2],
    }
    if lenses:
        sel["main1+lenses"] = clusters(mains[:1] + lenses)
        sel[f"union{k}+lenses"] = clusters(mains + lenses)
        main_vote = {(c["file"], c["line"], c["fam"]) for c in sel["vote2"]}
        sel["vote2+lenses"] = [c for c in clusters(mains + lenses)
                               if any(p.startswith("lens_") for p in c["passes"]) or (c["file"], c["line"], c["fam"]) in main_vote]
    for name, cands in extras:  # each extra pass alone, and unioned with the first main sample
        sel[name] = clusters([(name, cands)])
        if mains:
            sel[f"main1+{name}"] = clusters(mains[:1] + [(name, cands)])
    if len(extras) > 1 and mains:
        sel["main1+" + "+".join(n for n, _ in extras)] = clusters(mains[:1] + extras)
    return {name: [c["cand"] for c in cl] for name, cl in sel.items()}


def per_pair(items, findings) -> dict[str, bool]:
    rows = {i["id"]: judge_item(i, findings.get(i["id"], [])) for i in items}
    out = {}
    for i in items:
        if i["kind"] == "nc_vuln":
            fx = i["id"].replace(":nc_vuln", ":nc_fixed")
            if fx in rows:
                out[i["repo"] + "|" + i["pair"]] = rows[i["id"]]["hit_strict"] and not rows[fx]["site_flag"]
    return out


def paired_ci(a: dict[str, bool], b: dict[str, bool], iters: int = 2000, seed: int = 0):
    keys = sorted(set(a) & set(b))
    by_repo = collections.defaultdict(list)
    for k in keys:
        by_repo[k.split("|")[0]].append(k)
    repos = sorted(by_repo)
    rng = random.Random(seed)
    diffs = []
    for _ in range(iters):
        ks = [k for r in (rng.choice(repos) for _ in repos) for k in by_repo[r]]
        diffs.append(sum(a[k] - b[k] for k in ks) / max(len(ks), 1))
    diffs.sort()
    point = sum(a[k] - b[k] for k in keys) / max(len(keys), 1)
    return point, diffs[int(0.025 * iters)], diffs[int(0.975 * iters)], len(keys)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--split", default="dev_nc")
    ap.add_argument("--sample", default="tune")
    args = ap.parse_args()
    db = store.connect()
    items = [i for i in load_items(args.split) if i["id"] in sample_ids(args.split, args.sample)]
    raws = {iid: json.loads(raw or "{}") for iid, raw in db.execute(
        "SELECT item_id, raw FROM items WHERE run_id=? AND ok=1", (args.run_id,))}
    done = {iid for iid, in db.execute("SELECT item_id FROM items WHERE run_id=?", (args.run_id,))}
    items = [i for i in items if i["id"] in done]
    base_f, _ = store.load_findings(db, args.baseline)
    base_pairs = per_pair(items, base_f)
    names = sorted({n for r in raws.values() for n in combos(r)}, key=lambda n: (len(n), n))
    print(f"{len(items)} items done of sample '{args.sample}'; baseline {args.baseline}\n")
    print("| combination | pair acc | recall | precision | benign flagged | fix-site flagged | Δ pair acc vs baseline (95% CI) |")
    print("|---|---|---|---|---|---|---|")
    bm = metrics([(i, judge_item(i, base_f.get(i["id"], []))) for i in items])
    f = lambda m, k: "n/a" if m[k] != m[k] else f"{m[k]:.0%}"  # noqa: E731
    print(f"| baseline | {f(bm,'pair_acc')} | {f(bm,'recall_strict')} | {f(bm,'precision_strict')} | "
          f"{f(bm,'benign_flag_rate')} | {f(bm,'fix_site_flag_rate')} | - |")
    for name in names:
        fnd = {iid: combos(r).get(name, []) for iid, r in raws.items()}
        m = metrics([(i, judge_item(i, fnd.get(i["id"], []))) for i in items])
        d, lo, hi, n = paired_ci(per_pair(items, fnd), base_pairs)
        print(f"| {name} | {f(m,'pair_acc')} | {f(m,'recall_strict')} | {f(m,'precision_strict')} | "
              f"{f(m,'benign_flag_rate')} | {f(m,'fix_site_flag_rate')} | {d:+.1%} ({lo:+.1%}..{hi:+.1%}), n={n} pairs |")


if __name__ == "__main__":
    main()
