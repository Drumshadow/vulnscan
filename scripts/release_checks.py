"""Offline pre-publication checks requested by the Codex review. No reviewer reruns.

  release_checks.py --split test_nc --sample frontier > results/release-checks.md

1. overlap:     resolved base/head SHAs shared across splits or waves (forks can share commits across repos)
2. dates:       fix commits older than the cutoff (advisory date alone does not bound when the fix was public)
3. visibility:  are the truth / fix-site lines actually inside each arm's prompt under its context budget?
4. subsets:     line-window and semantic scores on: all, no-leak, fix-after-cutoff, fully-visible
5. sensitivity: pair accuracy under other line windows, CWE rules and fix-site rules
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from judge import load_judgments, pair_rate, semantic, truth_lines, twin  # noqa: E402
from vs import cwe as C, store  # noqa: E402
from vs.bench import BENCH, load_items, repo_dir, sample_ids  # noqa: E402
from vs.prompt import build_newcode  # noqa: E402
from vs.score import ROLE, fix_site, judge_item, norm_path  # noqa: E402

ARMS = {"harness_inv": ("af0d92409c", 80000), "qwen35b": ("0611bbe888", 90000), "claude": ("e5968e37dd", 90000),
        "codex": ("b0647dc368", 90000), "deephat": ("18befcd58a", 20000), "semgrep": ("0445397e3d", None)}


def overlap() -> None:
    print("## 1. Commit overlap across splits (resolved SHAs)\n")
    sets = {}
    for f in sorted(BENCH.glob("*.jsonl")):
        if f.name.endswith(("orig_diffs.jsonl",)) or f.stem.endswith("_nc"):
            continue
        shas = set()
        for line in f.open():
            it = json.loads(line)
            shas |= {x for x in (it.get("base"), it.get("head")) if x}
        sets[f.stem] = shas
    train = pathlib.Path("data/train/regions_v2.jsonl")
    if train.exists():
        sets["train"] = {json.loads(l)["sha"] for l in train.open()}
    names = sorted(sets)
    bad = 0
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            n = len(sets[a] & sets[b])
            bad += n
            if n:
                print(f"- {a} / {b}: {n} shared SHAs")
    print(f"\nSplits checked: {', '.join(f'{k} ({len(v)})' for k, v in sets.items())}. Total shared: {bad}.\n")


def commit_date(repo: str, sha: str) -> tuple[str, str]:
    r = subprocess.run(["git", "-C", str(repo_dir(repo)), "show", "-s", "--format=%aI %cI", sha],
                       capture_output=True, text=True, errors="replace", timeout=120)
    p = r.stdout.split()
    return (p[0], p[1]) if len(p) >= 2 else ("", "")


def dates(items: list[dict], cutoff: str) -> set[str]:
    print("## 2. Fix-commit dates vs the advisory cutoff\n")
    fixed = [i for i in items if i["kind"] == "nc_fixed"]
    pre_c, pre_a, unknown, after = 0, 0, 0, set()
    for it in fixed:
        a, c = commit_date(it["repo"], it["head"])
        if not c:
            unknown += 1; continue
        pre_c += c[:10] < cutoff
        pre_a += a[:10] < cutoff
        if c[:10] >= cutoff:
            after.add(it["pair"])
    print(f"{len(fixed)} advisories: fix committed before {cutoff}: {pre_c} ({pre_c / len(fixed):.0%}); "
          f"authored before it: {pre_a} ({pre_a / len(fixed):.0%}); date unknown: {unknown}.\n")
    return after


def original_anchors(split_nc: str) -> dict[str, dict[str, list[int]]]:
    """Truth / fix-site lines from the regression items BEFORE build_newcode dropped any file, keyed by nc item id."""
    from vs.diffutil import head_truth
    reg = split_nc[:-3] if split_nc.endswith("_nc") else split_nc
    out = {}
    for line in (BENCH / f"{reg}.jsonl").open():
        it = json.loads(line)
        if it["kind"] == "vuln_intro":
            out[f"{it['ghsa_id']}:nc_vuln"] = {norm_path(k): v for k, v in it["truth"].items()}
        elif it["kind"] == "fix":
            out[f"{it['ghsa_id']}:nc_fixed"] = {norm_path(k): v for k, v in head_truth(it["diff"]).items()}
    return out


def visible(items: list[dict], budget: int | None, anchors: dict) -> set[str]:
    """Pairs where EVERY original anchor line (vulnerable truth and patched fix site) is inside a shown window of a
    file that the prompt actually includes under this reviewer's budget."""
    ok_by_pair: dict[str, bool] = {}
    for it in items:
        if ROLE[it["kind"]] == "benign":
            continue
        need = anchors.get(it["id"]) or {}
        wins = {norm_path(k): v for k, v in it["views"].items()}
        fine = bool(need) and all(any(a <= ln <= b for a, b in wins.get(p, [])) for p, ls in need.items() for ln in ls)
        if fine and budget is not None:
            text = build_newcode(it, budget)
            fine = not any(f"### {p}\n(omitted" in text for p in need)
        ok_by_pair[it["pair"]] = ok_by_pair.get(it["pair"], True) and fine
    return {k for k, v in ok_by_pair.items() if v}


def line_outcomes(items, findings, window=5, cwe_mode="family", site_needs_family=False) -> dict:
    def cwe_ok(f, cwes):
        if cwe_mode == "none":
            return True
        if cwe_mode == "exact":
            return C.cwe_num(f.get("cwe")) in {C.cwe_num(c) for c in cwes}
        return C.matches(f.get("cwe"), cwes)

    def near(f, lines_by_file):
        ls = lines_by_file.get(norm_path(f.get("file")))
        return bool(ls) and f.get("line") is not None and min(abs(int(f["line"]) - t) for t in ls) <= window

    out = {}
    for it in items:
        if ROLE[it["kind"]] == "benign" or it["id"] not in findings:
            continue
        fs = findings[it["id"]]
        if ROLE[it["kind"]] == "pos":
            tl = {norm_path(k): v for k, v in it["truth"].items()}
            out[it["id"]] = any(near(f, tl) and cwe_ok(f, it.get("cwes") or []) for f in fs)
        else:
            site = fix_site(it)
            out[it["id"]] = any(near(f, site) and (not site_needs_family or cwe_ok(f, it.get("cwes") or [])) for f in fs)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test_nc")
    ap.add_argument("--sample", default="frontier")
    ap.add_argument("--cutoff", default="2026-07-01")
    a = ap.parse_args()
    db = store.connect()
    items = [i for i in load_items(a.split) if i["id"] in sample_ids(a.split, a.sample)]
    print(f"# Release checks: {a.split}, sample {a.sample}, {len(items)} items, "
          f"{dict(collections.Counter(i['kind'] for i in items))}\n")
    overlap()
    after = dates(items, a.cutoff)
    pairs = {i["pair"] for i in items if i.get("pair")}
    runs = {k: (f"{k}:{a.split}:{h}", b) for k, (h, b) in ARMS.items()}
    F = {k: store.load_findings(db, r)[0] for k, (r, _) in runs.items()}
    J = {k: load_judgments(db, r) for k, (r, _) in runs.items()}
    print("## 3. Is the vulnerable / patched code actually in the prompt?\n")
    vis = {}
    anchors = original_anchors(a.split)
    for k, (_, b) in runs.items():
        vis[k] = visible(items, b, anchors)
        print(f"- {k} (budget {b or 'whole file, findings limited to views'}): {len(vis[k])}/{len(pairs)} pairs with every "
              "original anchor line shown")
    print("\n## 4. Scores on subsets (pair accuracy: line window / semantic)\n")
    noleak = {i["pair"] for i in items if ROLE[i["kind"]] == "pos" and not ((i.get("leak") or {}).get("code") or (i.get("leak") or {}).get("comment"))}
    print("| reviewer | all | no leak flag | fix committed after cutoff | fully visible to that reviewer |\n|---|---|---|---|---|")
    for k in runs:
        cells = []
        for keep in (pairs, noleak, after, vis[k]):
            sub = [i for i in items if i.get("pair") in keep]
            lin, n = pair_rate(sub, line_outcomes(sub, F[k]))
            r = semantic(sub, F[k], J[k])
            sem, _ = pair_rate(sub, r["sem"])
            cells.append(f"{lin:.0%} / {'INCOMPLETE' if r['missing'] or r['unjudged'] else f'{sem:.0%}'} (n={n})")
        print(f"| {k} | " + " | ".join(cells) + " |")
    print("\n## 5. Sensitivity of line-window pair accuracy\n")
    variants = [("window 5, family (reported)", {}), ("window 3", {"window": 3}), ("window 10", {"window": 10}),
                ("window 25", {"window": 25}), ("exact CWE", {"cwe_mode": "exact"}), ("no CWE requirement", {"cwe_mode": "none"}),
                ("fix-site flag needs CWE family", {"site_needs_family": True})]
    print("| variant | " + " | ".join(runs) + " | order |\n|---|" + "---|" * (len(runs) + 1))
    for name, kw in variants:
        vals = {k: pair_rate(items, line_outcomes(items, F[k], **kw))[0] for k in runs}
        order = " > ".join(sorted(vals, key=lambda k: -vals[k]))
        print(f"| {name} | " + " | ".join(f"{vals[k]:.0%}" for k in runs) + f" | {order} |")
    _ = twin


if __name__ == "__main__":
    main()
