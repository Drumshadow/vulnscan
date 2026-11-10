"""Comparison table for runs in results/vulnscan.sqlite, on all items and on items without residual leakage.

  summarize.py [--split dev] [--runs RUN_ID ...] [--out results/summary-dev.md]
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs import store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.score import score_run  # noqa: E402

COLS = [("pair_acc", "pair acc"), ("recall_strict", "recall"), ("recall_loc", "recall@loc"), ("recall_file", "recall@file+cwe"), ("precision_strict", "precision"),
        ("benign_flag_rate", "benign flagged"), ("fp_per_benign", "FP/benign"), ("fix_site_flag_rate", "fix-site flagged"), ("fix_flag_rate", "fix flagged")]


def fmt(m, ci, k):
    v = m[k]
    if v != v:
        return "n/a"
    if k == "fp_per_benign":
        return f"{v:.2f}"
    lo, hi = ci.get(k, (v, v))
    return f"{v:.0%} ({lo:.0%}-{hi:.0%})"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev")
    ap.add_argument("--runs", nargs="*")
    ap.add_argument("--out")
    ap.add_argument("--sample", choices=["frontier", "tune", "check"], help="score every run on this common item subset only")
    args = ap.parse_args()
    db = store.connect()
    runs = args.runs or [r[0] for r in db.execute(
        "SELECT run_id FROM runs WHERE split=? AND finished_at IS NOT NULL ORDER BY started_at", (args.split,))
        if not __import__("re").search(r":n\d+$", r[0])]  # smoke runs (--limit) only when listed explicitly
    items = load_items(args.split)
    if args.sample:
        keep = sample_ids(args.split, args.sample)
        items = [i for i in items if i["id"] in keep]
    clean_ids = {i["id"] for i in items if not (i.get("leak") or {}).get("code") and not (i.get("leak") or {}).get("comment")}
    lines = []
    for label, subset in (("all items", items), ("excluding residual-leak items", [i for i in items if i["id"] in clean_ids])):
        lines.append(f"\n### {args.split}: {label}\n")
        lines.append("| run | n done | errors | " + " | ".join(c[1] for c in COLS) + " | median s |")
        lines.append("|---" * (len(COLS) + 4) + "|")
        for rid in runs:
            findings, errored = store.load_findings(db, rid)
            sub = [i for i in subset if i["id"] in findings]
            if not sub:
                continue
            r = score_run(sub, findings, errored & {i["id"] for i in sub}, iters=500)
            lat = sorted(x[0] for x in db.execute("SELECT latency_s FROM items WHERE run_id=? AND latency_s IS NOT NULL", (rid,)))
            med = f"{lat[len(lat) // 2]:.0f}" if lat else "-"
            lines.append(f"| {rid} | {len(sub)}/{len(subset)} | {r['n_errored']} | "
                         + " | ".join(fmt(r["metrics"], r["ci95"], k) for k, _ in COLS) + f" | {med} |")
    text = "\n".join(lines) + "\n"
    print(text)
    if args.out:
        pathlib.Path(args.out).write_text(text)


if __name__ == "__main__":
    main()
