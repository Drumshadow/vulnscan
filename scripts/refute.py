"""Run a refuter variant offline over the stored candidates of an investigator run.

Writes table refutations(run_id, item_id, idx, variant, verdict, confidence, reason); resumable.
  refute.py <run_id> --split dev_nc --variant v2 [--workers 4]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs import store  # noqa: E402
from vs.arms import semgrep_arm  # noqa: E402
from vs.bench import load_items  # noqa: E402
from vs.harness import REFUTERS, build_context, refute_one  # noqa: E402

SCHEMA = """CREATE TABLE IF NOT EXISTS refutations (run_id TEXT, item_id TEXT, idx INTEGER, variant TEXT,
  verdict TEXT, confidence REAL, reason TEXT, PRIMARY KEY (run_id, item_id, idx, variant))"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--split", default="dev_nc")
    ap.add_argument("--variant", required=True, choices=sorted(REFUTERS))
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    db = store.connect(); db.execute(SCHEMA); db.commit()
    items = {i["id"]: i for i in load_items(args.split)}
    done = {r[0] for r in db.execute("SELECT DISTINCT item_id FROM refutations WHERE run_id=? AND variant=?",
                                     (args.run_id, args.variant))}
    todo = []
    for iid, raw in db.execute("SELECT item_id, raw FROM items WHERE run_id=? AND ok=1", (args.run_id,)):
        cands = json.loads(raw or "{}").get("candidates", [])
        if cands and iid not in done:
            todo.append((iid, cands))
    print(f"{len(todo)} items with candidates to refute ({len(done)} done)", flush=True)

    def one(job):
        iid, cands = job
        user, _ = build_context(items[iid], semgrep_arm.review)
        return iid, [refute_one(user, c, args.variant)[0] for c in cands]

    with cf.ThreadPoolExecutor(args.workers) as ex:
        for n, (iid, verdicts) in enumerate(ex.map(one, todo), 1):
            for i, v in enumerate(verdicts):
                db.execute("INSERT OR REPLACE INTO refutations VALUES (?,?,?,?,?,?,?)",
                           (args.run_id, iid, i, args.variant, str(v.get("verdict")),
                            float(v.get("confidence") or 0), str(v.get("reason", ""))[:1000]))
            db.commit()
            if n % 10 == 0:
                print(f"  {n}/{len(todo)}", flush=True)
    print("done", flush=True)


if __name__ == "__main__":
    main()
