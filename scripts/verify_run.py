"""H15 V4/V5: run PoC verification over the stored candidates of a harness run (no new review pass), then score.

  verify_run.py <run_id> --split dev_nc --sample tune [--workers 2]          # verify (resumable)
  verify_run.py <run_id> --split dev_nc --sample tune --report              # rates + pair-accuracy variants

Table verifications(run_id, item_id, idx, outcome, attempts, code, stdout).
Report:
  * outcome rates by item kind. A confirmation on nc_fixed AT the fix site, or on nc_benign, is a false
    confirmation candidate; they are listed for hand review.
  * variants vs the unverified run: drop not_reproduced | confirmed + unverifiable | confirmed only.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vs import store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.poc import verify  # noqa: E402
from vs.score import ROLE, judge_item, metrics  # noqa: E402

SCHEMA = """CREATE TABLE IF NOT EXISTS verifications (run_id TEXT, item_id TEXT, idx INTEGER, outcome TEXT,
  attempts INTEGER, code TEXT, stdout TEXT, PRIMARY KEY (run_id, item_id, idx))"""


def run(a) -> None:
    db = store.connect(); db.execute(SCHEMA)
    if "stderr" not in {r[1] for r in db.execute("PRAGMA table_info(verifications)")}:
        db.execute("ALTER TABLE verifications ADD COLUMN stderr TEXT")
    db.commit()
    items = {i["id"]: i for i in load_items(a.split) if i["id"] in sample_ids(a.split, a.sample)}
    findings, _ = store.load_findings(db, a.run_id)
    vid = a.run_id + (":v2" if a.v2 else "")
    done = {(r[0], r[1]) for r in db.execute("SELECT item_id, idx FROM verifications WHERE run_id=?", (vid,))}
    jobs = [(iid, idx, f) for iid, fs in findings.items() if iid in items for idx, f in enumerate(fs) if (iid, idx) not in done]
    print(f"{len(jobs)} candidates to verify", flush=True)

    def one(job):
        iid, idx, f = job
        try:
            return iid, idx, verify(items[iid], f, coverage_gate=a.v2)
        except Exception as e:  # noqa: BLE001  infra failure: not recorded, retried next run
            return iid, idx, {"outcome": "error", "reason": str(e)[:200]}

    with cf.ThreadPoolExecutor(a.workers) as ex:
        for n, (iid, idx, v) in enumerate(ex.map(one, jobs), 1):
            if v["outcome"] != "error":
                db.execute("INSERT OR REPLACE INTO verifications (run_id, item_id, idx, outcome, attempts, code, stdout, stderr)"
                           " VALUES (?,?,?,?,?,?,?,?)",
                           (a.run_id + (":v2" if a.v2 else ""), iid, idx, v["outcome"], v.get("attempts"),
                            (v.get("code") or "")[:20000], (v.get("stdout") or "")[-2000:], (v.get("stderr") or "")[-3000:]))
                db.commit()
            if n % 10 == 0:
                print(f"  {n}/{len(jobs)}", flush=True)
    print("done", flush=True)


def report(a) -> None:
    db = store.connect(); db.execute(SCHEMA)
    items = [i for i in load_items(a.split) if i["id"] in sample_ids(a.split, a.sample)]
    byid = {i["id"]: i for i in items}
    findings, errored = store.load_findings(db, a.run_id)
    V = {(iid, idx): o for iid, idx, o in db.execute(
        "SELECT item_id, idx, outcome FROM verifications WHERE run_id=?", (a.run_id + (":v2" if a.v2 else ""),))}
    rates = collections.defaultdict(collections.Counter)
    false_conf = []
    for iid, fs in findings.items():
        if iid not in byid:
            continue
        it = byid[iid]
        for idx, f in enumerate(fs):
            o = V.get((iid, idx), "unchecked")
            rates[it["kind"]][o] += 1
            if o == "confirmed" and ROLE[it["kind"]] != "pos":
                site = ROLE[it["kind"]] == "fixed" and judge_item(it, [f]).get("site_flag")
                false_conf.append((iid, idx, "AT FIX SITE" if site else "elsewhere", f.get("title")))
    print("outcomes by item kind:")
    for kind, c in sorted(rates.items()):
        tot = sum(c.values())
        print(f"  {kind:10} n={tot:4}  " + "  ".join(f"{o} {c[o]} ({c[o] / tot:.0%})" for o in
                                                   ("confirmed", "not_reproduced", "unverifiable", "unchecked")))
    print(f"\nconfirmations on patched/benign code ({len(false_conf)}; AT FIX SITE = likely false, elsewhere = maybe a real other bug):")
    for row in false_conf[:30]:
        print("  ", row)
    variants = {
        "unverified": lambda o: True,
        "drop not_reproduced": lambda o: o != "not_reproduced",
        "confirmed + unverifiable": lambda o: o in ("confirmed", "unverifiable", "unchecked"),
        "confirmed only": lambda o: o == "confirmed",
    }
    print("\n| variant | pair acc | recall | precision | benign flagged | fix-site flagged |\n|---|---|---|---|---|---|")
    for name, keep in variants.items():
        fnd = {iid: [f for idx, f in enumerate(fs) if keep(V.get((iid, idx), "unchecked"))] for iid, fs in findings.items()}
        m = metrics([(i, judge_item(i, fnd.get(i["id"], []))) for i in items])
        f = lambda k: "n/a" if m[k] != m[k] else f"{m[k]:.0%}"  # noqa: E731
        print(f"| {name} | {f('pair_acc')} | {f('recall_strict')} | {f('precision_strict')} | {f('benign_flag_rate')} | {f('fix_site_flag_rate')} |")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--split", default="dev_nc")
    ap.add_argument("--sample", default="tune")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--v2", action="store_true", help="coverage-gated confirmation + stderr logging")
    a = ap.parse_args()
    report(a) if a.report else run(a)


if __name__ == "__main__":
    main()
