"""M1: semantic judge. Does a finding describe the advisory's vulnerability (same root cause, same affected
code), regardless of the exact line? Runs offline on stored findings; reported NEXT TO the line-window score.

  judge.py <run_id> [<run_id> ...] --split dev_nc [--sample tune] [--workers 4]
  judge.py --report <run_id> ... --split dev_nc [--sample tune]

Only findings in a file the fix touched are judged (others cannot describe the fixed bug: auto no-match).
nc_vuln / vuln_intro: match = the finding is this vulnerability.
nc_fixed / fix:       match = the finding claims the PATCHED code still has this vulnerability.
Table: judgments(run_id, item_id, idx, judge, match, reason). Judge version is part of the key.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs import store  # noqa: E402
from vs.bench import BENCH, file_at, load_items, sample_ids  # noqa: E402
from vs.harness import _chat  # noqa: E402
from vs.score import ROLE, fix_site, norm_path  # noqa: E402

JUDGE = "j1"
SYSTEM = """You are grading a security code reviewer against a known, published vulnerability.

You get: the advisory (summary + CWE), the vulnerable lines the official fix changed (with code), and ONE \
finding from the reviewer (with the code it points at).

Decide whether the finding identifies THE SAME vulnerability as the advisory: the same root cause (the same \
missing or broken check, or the same unsafe operation) in the same component. It may cite a different line \
(for example the sink instead of where the fix was applied) and may use a different but related CWE; that is \
fine. It is NOT a match if it describes a different bug, a generic concern, or only shares the file.

Respond with JSON only: {"match": true or false, "reason": "<one sentence>"}"""

SYSTEM_FIXED = SYSTEM.replace(
    "Decide whether the finding identifies THE SAME vulnerability",
    "The code shown to the reviewer was the PATCHED version (the fix is applied). Decide whether the finding "
    "claims that the patched code still has THE SAME vulnerability")

def rubric_sha() -> str:
    return hashlib.sha256((SYSTEM + SYSTEM_FIXED).encode()).hexdigest()[:12]


# Judgments under key "j1" were produced with exactly this rubric. Any edit needs a new JUDGE name.
J1_RUBRIC_SHA = "707f25996671"
if JUDGE == "j1":
    assert rubric_sha() == J1_RUBRIC_SHA, "rubric changed: bump JUDGE so old and new judgments cannot mix"

SCHEMA = """CREATE TABLE IF NOT EXISTS judgments (run_id TEXT, item_id TEXT, idx INTEGER, judge TEXT,
  match INTEGER, reason TEXT, PRIMARY KEY (run_id, item_id, idx, judge))"""


def advisories() -> dict[str, dict]:
    out = {}
    for split in ("dev", "test"):
        for line in (BENCH / f"{split}.jsonl").open():
            it = json.loads(line)
            if it["kind"] == "vuln_intro":
                out[it["ghsa_id"]] = {"summary": it.get("summary") or "", "cwes": it.get("cwes") or []}
    return out


def excerpt(item, path, lines, ctx=4, cap=60) -> str:
    text = (file_at(item["repo"], item["head"], path) or "").splitlines()
    keep = sorted({j for ln in lines for j in range(max(1, ln - ctx), min(len(text), ln + ctx) + 1)})[:cap]
    out, prev = [], None
    for j in keep:
        if prev is not None and j != prev + 1:
            out.append("  ...")
        out.append(f"{j:5d}  {text[j - 1]}")
        prev = j
    return "\n".join(out)


def truth_lines(item) -> dict[str, list[int]]:
    if ROLE[item["kind"]] == "fixed":
        return fix_site(item)
    return {norm_path(k): v for k, v in item["truth"].items()}


def judge_one(item, f, adv) -> dict:
    tl = truth_lines(item)
    fpath = norm_path(f.get("file"))
    if fpath not in tl:
        return {"match": False, "reason": "not in a file the fix touched"}
    truth_txt = "\n".join(f"### {p}\n{excerpt(item, p, ls)}" for p, ls in tl.items())
    try:
        fl = [int(f.get("line"))]
    except (TypeError, ValueError):
        fl = []
    user = (f"## Advisory\n{adv['summary']}\nCWE: {', '.join(adv['cwes'])}\n\n"
            f"## Lines the official fix changed ({'patched' if ROLE[item['kind']] == 'fixed' else 'vulnerable'} version)\n"
            f"{truth_txt}\n\n## Reviewer finding\nfile: {f.get('file')}\nline: {f.get('line')}\ncwe: {f.get('cwe')}\n"
            f"title: {f.get('title')}\nexplanation: {f.get('explanation')}\n\n### Code at the finding\n"
            f"{excerpt(item, fpath, fl) if fl else '(no line given)'}\n")
    system = SYSTEM_FIXED if ROLE[item["kind"]] == "fixed" else SYSTEM
    text, _ = _chat(system, user, 6144, "qwen3.6-35b-a3b")
    obj = json.loads(text[text.find("{"): text.rfind("}") + 1])
    if not isinstance(obj.get("match"), bool):  # bool("false") is True; a non-boolean is a failed call, retried
        raise ValueError(f"non-boolean match: {obj.get('match')!r}")
    return {"match": obj["match"], "reason": str(obj.get("reason", ""))[:500]}


def run(args) -> None:
    db = store.connect(); db.execute(SCHEMA); db.commit()
    adv = advisories()
    items = {i["id"]: i for i in load_items(args.split)}
    if args.sample:
        keep = sample_ids(args.split, args.sample)
        items = {k: v for k, v in items.items() if k in keep}
    jobs = []
    for rid in args.runs:
        findings, _ = store.load_findings(db, rid)
        done = {(r[0], r[1]) for r in db.execute("SELECT item_id, idx FROM judgments WHERE run_id=? AND judge=?", (rid, JUDGE))}
        for iid, fs in findings.items():
            it = items.get(iid)
            if not it or ROLE[it["kind"]] == "benign" or it.get("ghsa_id") not in adv:
                continue
            for idx, f in enumerate(fs):
                if (iid, idx) not in done:
                    jobs.append((rid, it, idx, f))
    print(f"{len(jobs)} findings to judge", flush=True)

    def one(job):
        rid, it, idx, f = job
        try:
            return rid, it["id"], idx, judge_one(it, f, adv[it["ghsa_id"]])
        except Exception as e:  # noqa: BLE001  infra/parse failure: not recorded, retried next run
            return rid, it["id"], idx, {"error": str(e)[:200]}

    with cf.ThreadPoolExecutor(args.workers) as ex:
        for n, (rid, iid, idx, v) in enumerate(ex.map(one, jobs), 1):
            if "error" not in v:
                db.execute("INSERT OR REPLACE INTO judgments VALUES (?,?,?,?,?,?)",
                           (rid, iid, idx, JUDGE, int(v["match"]), v["reason"]))
                db.commit()
            if n % 25 == 0:
                print(f"  {n}/{len(jobs)}", flush=True)
    print("done", flush=True)


def semantic(items: list[dict], findings: dict, J: dict) -> dict:
    """Per-item semantic outcome over every expected non-benign item. Missing items or unjudged findings are
    counted, never silently treated as a clean result."""
    sem, missing, unjudged = {}, [], 0
    for it in items:
        if ROLE[it["kind"]] == "benign":
            continue
        if it["id"] not in findings:
            missing.append(it["id"]); continue
        tl = truth_lines(it)
        judged = J.get(it["id"], {})
        need = [i for i, f in enumerate(findings[it["id"]]) if norm_path(f.get("file")) in tl]
        unjudged += sum(1 for i in need if i not in judged)
        sem[it["id"]] = any(judged.get(i, False) for i in need)
    return {"sem": sem, "missing": missing, "unjudged": unjudged}


def twin(iid: str) -> str:
    return iid.replace(":nc_vuln", ":nc_fixed").replace(":intro", ":fix")


def pair_rate(items: list[dict], d: dict) -> tuple[float, int]:
    pos = [i for i in items if ROLE[i["kind"]] == "pos" and twin(i["id"]) in d and i["id"] in d]
    ok = sum(d[i["id"]] and not d[twin(i["id"])] for i in pos)
    return (ok / len(pos) if pos else float("nan")), len(pos)


def load_judgments(db, rid: str) -> dict:
    J: dict = {}
    for iid, idx, m in db.execute("SELECT item_id, idx, match FROM judgments WHERE run_id=? AND judge=?", (rid, JUDGE)):
        J.setdefault(iid, {})[idx] = bool(m)
    return J


def report(args) -> None:
    from vs.score import judge_item
    db = store.connect(); db.execute(SCHEMA)
    items = [i for i in load_items(args.split) if not args.sample or i["id"] in sample_ids(args.split, args.sample)]
    if args.exclude_leak:
        items = [i for i in items if not ((i.get("leak") or {}).get("code") or (i.get("leak") or {}).get("comment"))]
    print(f"judge {JUDGE} rubric {rubric_sha()}; {len(items)} items" + (" (leak-flagged excluded)" if args.exclude_leak else ""))
    print("| run | pairs | pair acc (lines) | pair acc (semantic) | recall (lines) | recall (semantic) | patched still flagged (semantic) | missing | unjudged |")
    print("|---|---|---|---|---|---|---|---|---|")
    for rid in args.runs:
        findings, _ = store.load_findings(db, rid)
        r = semantic(items, findings, load_judgments(db, rid))
        lin = {}
        for it in items:
            if ROLE[it["kind"]] != "benign" and it["id"] in findings:
                j = judge_item(it, findings[it["id"]])
                lin[it["id"]] = j["hit_strict"] if ROLE[it["kind"]] == "pos" else j["site_flag"]
        pos = [i for i in items if ROLE[i["kind"]] == "pos" and i["id"] in r["sem"]]
        fixed = [i for i in items if ROLE[i["kind"]] == "fixed" and i["id"] in r["sem"]]
        rate = lambda d, xs: sum(d[i["id"]] for i in xs) / len(xs) if xs else float("nan")  # noqa: E731
        pl, n = pair_rate(items, lin); ps, _ = pair_rate(items, r["sem"])
        bad = bool(r["missing"] or r["unjudged"])
        sem = (lambda v: "INCOMPLETE" if bad else f"{v:.0%}")
        print(f"| {rid} | {n} | {pl:.0%} | {sem(ps)} | {rate(lin, pos):.0%} | {sem(rate(r['sem'], pos))} | "
              f"{sem(rate(r['sem'], fixed))} | {len(r['missing'])} | {r['unjudged']} |")


def recheck(args) -> None:
    """Size the old bool("false") risk: re-judge a random sample of stored matches with the strict parser."""
    import random
    db = store.connect()
    adv = advisories()
    items = {i["id"]: i for i in load_items(args.split)}
    rows = []
    for rid in args.runs:
        findings, _ = store.load_findings(db, rid)
        for iid, idx in db.execute("SELECT item_id, idx FROM judgments WHERE run_id=? AND judge=? AND match=1", (rid, JUDGE)):
            if iid in items:
                rows.append((rid, items[iid], idx, findings[iid][idx]))
    random.Random(1729).shuffle(rows)
    rows = rows[: args.recheck]
    def one(r):
        try:
            return judge_one(r[1], r[3], adv[r[1]["ghsa_id"]])["match"], ""
        except Exception as e:  # noqa: BLE001
            return None, str(e)[:120]
    res = list(cf.ThreadPoolExecutor(args.workers).map(one, rows))
    nonbool = [e for v, e in res if "non-boolean" in e]
    other = [e for v, e in res if v is None and "non-boolean" not in e]
    print(f"rechecked {len(res)} stored matches: still match {sum(v is True for v, _ in res)}, "
          f"now no-match {sum(v is False for v, _ in res)}, non-boolean answers {len(nonbool)}, other failures {len(other)}")
    print("examples of non-boolean:", nonbool[:5])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--split", default="dev_nc")
    ap.add_argument("--sample", choices=["frontier", "tune", "check"])
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--exclude-leak", action="store_true")
    ap.add_argument("--recheck", type=int, default=0, help="re-judge N stored matches with the strict parser")
    args = ap.parse_args()
    recheck(args) if args.recheck else (report(args) if args.report else run(args))


if __name__ == "__main__":
    main()
