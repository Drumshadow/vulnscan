"""M1 hand audit: a CSV for Stephen to label. Two parts:
  A. ~60 judge decisions (balanced match / no-match), to validate the semantic judge.
  B. ~40 "false alarms" (findings on patched or benign items), to measure how many are real other bugs.

  audit_sheet.py <run_id> --split dev_nc [--sample frontier] --out results/audit_semantic.csv
Fill the `label` column: A rows -> same_bug / different_bug / unsure; B rows -> real_bug / not_a_bug / unsure.
"""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from judge import JUDGE, SCHEMA, advisories, excerpt, truth_lines  # noqa: E402
from vs import store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.score import ROLE, judge_item, norm_path  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_ids", nargs="+")
    ap.add_argument("--split", default="dev_nc")
    ap.add_argument("--sample", default="frontier")
    ap.add_argument("--n-judge", type=int, default=60)
    ap.add_argument("--n-fa", type=int, default=40)
    ap.add_argument("--out", default="results/audit_semantic.csv")
    a = ap.parse_args()
    db = store.connect(); db.execute(SCHEMA)
    adv = advisories()
    items = {i["id"]: i for i in load_items(a.split) if i["id"] in sample_ids(a.split, a.sample)}
    rng = random.Random(1729)
    F = {rid: store.load_findings(db, rid)[0] for rid in a.run_ids}
    J = [(rid, iid, idx, bool(m), reason) for rid in a.run_ids for iid, idx, m, reason in db.execute(
        "SELECT item_id, idx, match, reason FROM judgments WHERE run_id=? AND judge=?", (rid, JUDGE)) if iid in items]
    findings = {}  # (run, item) -> findings, for the false-alarm part
    matches = [j for j in J if j[3] and j[4] != "not in a file the fix touched"]
    nonm = [j for j in J if not j[3] and j[4] != "not in a file the fix touched"]
    rng.shuffle(matches); rng.shuffle(nonm)
    part_a = matches[: a.n_judge // 2] + nonm[: a.n_judge - min(len(matches), a.n_judge // 2)]
    fa = []
    for rid in a.run_ids:
        for iid, fs in F[rid].items():
            it = items.get(iid)
            if not it or ROLE[it["kind"]] == "pos":
                continue
            for idx, f in enumerate(fs):
                if ROLE[it["kind"]] == "fixed" and judge_item(it, [f]).get("site_flag"):
                    continue  # at the fix site: part A territory, not "another bug"
                fa.append((rid, iid, idx))
    rng.shuffle(fa)
    part_b = fa[: a.n_fa]
    rows = []
    for rid, iid, idx, m, reason in part_a:
        it, f = items[iid], F[rid][iid][idx]
        tl = truth_lines(it)
        rows.append({"part": "A_judge", "reviewer": rid.split(":")[0], "item": iid, "kind": it["kind"], "repo": it["repo"],
                     "advisory": adv.get(it.get("ghsa_id"), {}).get("summary", ""), "cwes": " ".join(it.get("cwes") or []),
                     "truth": json.dumps(tl), "finding": f"{f.get('file')}:{f.get('line')} {f.get('cwe')} {f.get('title')}",
                     "explanation": f.get("explanation") or "",
                     "code": excerpt(it, norm_path(f.get("file")), [int(f["line"])] if str(f.get("line") or "").isdigit() else []),
                     "judge": "match" if m else "no_match", "judge_reason": reason, "label": "", "notes": ""})
    for rid, iid, idx in part_b:
        it, f = items[iid], F[rid][iid][idx]
        rows.append({"part": "B_false_alarm", "reviewer": rid.split(":")[0], "item": iid, "kind": it["kind"], "repo": it["repo"],
                     "advisory": adv.get(it.get("ghsa_id"), {}).get("summary", "") if it.get("ghsa_id") else "",
                     "cwes": " ".join(it.get("cwes") or []), "truth": "",
                     "finding": f"{f.get('file')}:{f.get('line')} {f.get('cwe')} {f.get('title')}",
                     "explanation": f.get("explanation") or "",
                     "code": excerpt(it, norm_path(f.get("file")), [int(f["line"])] if str(f.get("line") or "").isdigit() else []),
                     "judge": "", "judge_reason": "", "label": "", "notes": ""})
    out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["part"])
        w.writeheader(); w.writerows(rows)
    print(f"{out}: {len(part_a)} judge rows ({len(matches)} matches / {len(nonm)} non-matches available), "
          f"{len(part_b)} false-alarm rows")


if __name__ == "__main__":
    main()
