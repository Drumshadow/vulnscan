"""Re-score a harness run at different refuter thresholds from the stored candidates/verdicts (no re-run).

  sweep_harness.py <run_id> [--split dev_nc] [--sample frontier]
Rows: 'no refuter' (every candidate kept), then refuter-confirmed at confidence >= t.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs import store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.harness import keep  # noqa: E402
from vs.score import score_run  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--split", default="dev_nc")
    ap.add_argument("--sample", choices=["frontier", "tune", "check"])
    ap.add_argument("--variant", default="inline", help="'inline' = verdicts stored in the run; else a refute.py variant")
    args = ap.parse_args()
    db = store.connect()
    items = load_items(args.split)
    if args.sample:
        keep_ids = sample_ids(args.split, args.sample)
        items = [i for i in items if i["id"] in keep_ids]
    rows = {iid: (ok, raw) for iid, ok, raw in db.execute(
        "SELECT item_id, ok, raw FROM items WHERE run_id=?", (args.run_id,))}
    items = [i for i in items if i["id"] in rows]
    errored = {iid for iid, (ok, _) in rows.items() if not ok}
    offline = {}
    if args.variant != "inline":
        for iid, idx, verdict, conf in db.execute(
                "SELECT item_id, idx, verdict, confidence FROM refutations WHERE run_id=? AND variant=?",
                (args.run_id, args.variant)):
            offline.setdefault(iid, {})[idx] = {"verdict": verdict, "confidence": conf}
        # score only items whose candidates have all been refuted (or that had none)
        def complete(iid, raw):
            n = len(json.loads(raw or "{}").get("candidates", []))
            return n == 0 or len(offline.get(iid, {})) == n
        items = [i for i in items if complete(i["id"], rows[i["id"]][1])]
    print(f"{len(items)} items scored, {len(errored & {i['id'] for i in items})} errored (variant {args.variant})\n")
    print("| setting | pair acc | recall | precision | benign flagged | fix-site flagged |\n|---|---|---|---|---|---|")
    settings = [("no refuter", None)] + [(f"confirmed, conf >= {t:.1f}", t) for t in (0.0, 0.3, 0.5, 0.6, 0.7, 0.8, 0.9)]
    for label, t in settings:
        findings = {}
        for iid, (ok, raw) in rows.items():
            if not ok or not raw:
                findings[iid] = []; continue
            r = json.loads(raw)
            cands = r.get("candidates", [])
            verdicts = r.get("verdicts", []) if args.variant == "inline" else \
                [offline.get(iid, {}).get(i, {"verdict": "missing"}) for i in range(len(cands))]
            findings[iid] = cands if t is None else [c for c, v in zip(cands, verdicts) if keep(c, v, t)]
        m = score_run(items, findings, errored, iters=200)["metrics"]
        f = lambda k: "n/a" if m[k] != m[k] else f"{m[k]:.0%}"  # noqa: E731
        print(f"| {label} | {f('pair_acc')} | {f('recall_strict')} | {f('precision_strict')} | "
              f"{f('benign_flag_rate')} | {f('fix_site_flag_rate')} |")


if __name__ == "__main__":
    main()
