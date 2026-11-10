"""Score findings against benchmark items.

Item kinds, by role (regression framing / new-code framing):
  positive: vuln_intro / nc_vuln   (one known vulnerability)
  fixed:    fix        / nc_fixed  (the patched version; expected: nothing at the fix site)
  benign:   benign     / nc_benign (expected: no finding)

Per vuln_intro item:
  hit_strict = some finding in a truth file, line within +-window of a truth line, CWE family match
  hit_loc    = same without the CWE requirement
  hit_file   = right file + CWE family at any line (the sink can sit far from the fix site)
Per fixed / benign item:
  flagged    = at least one finding
  site_flag  = (fixed only) a finding within +-window of the lines the fix added: the reviewer still
               calls the patched spot vulnerable
Pairs (same advisory, positive + fixed):
  pair_acc   = positive hit_strict AND fixed not site_flag (can it tell vulnerable from patched?)

Metrics (all reported per kind, so the 1:1:2 intro:fix:benign mix is never hidden in one number):
  recall_strict, recall_loc      over vuln_intro items
  benign_flag_rate, fix_flag_rate, fp_per_benign (mean #findings on benign items)
  precision_strict = hit-strict intro items / all flagged items (intro + fix + benign), at the bench's mix
Errored items count as misses / unflagged and are reported separately; they are never dropped.
CIs: repo-cluster bootstrap (items from one repo are resampled together).
"""
from __future__ import annotations

import collections
import random

from . import cwe as cwemod
from .diffutil import head_truth

ROLE = {"vuln_intro": "pos", "nc_vuln": "pos", "fix": "fixed", "nc_fixed": "fixed",
        "benign": "benign", "nc_benign": "benign"}


def norm_path(p: str | None) -> str:
    p = (p or "").strip().replace("\\", "/")
    for pre in ("./", "a/", "b/"):
        if p.startswith(pre):
            p = p[len(pre):]
    return p


def _near(f: dict, lines_by_file: dict[str, list[int]], window: int) -> bool:
    lines = lines_by_file.get(norm_path(f.get("file")))
    return bool(lines) and f.get("line") is not None and min(abs(int(f["line"]) - t) for t in lines) <= window


def fix_site(item: dict) -> dict[str, list[int]]:
    site = item.get("fix_site")
    if site is None:  # regression-framing fix item: the lines this diff adds
        site = head_truth(item.get("diff") or "")
    return {norm_path(k): v for k, v in site.items()}


def judge_item(item: dict, findings: list[dict], window: int = 5) -> dict:
    role = ROLE[item["kind"]]
    if role != "pos":
        out = {"flagged": bool(findings), "n_findings": len(findings)}
        if role == "fixed":
            site = fix_site(item)
            out["site_flag"] = any(_near(f, site, window) for f in findings)
        return out
    truth = {norm_path(k): v for k, v in item["truth"].items()}
    hit_loc = hit_strict = hit_strict_loose = hit_file = False
    for f in findings:
        lines = truth.get(norm_path(f.get("file")))
        if not lines:
            continue
        if cwemod.matches(f.get("cwe"), item.get("cwes") or []):
            hit_file = True  # right file + CWE family, any line (sink vs fix-site disagreement)
        if f.get("line") is None:
            continue
        if min(abs(int(f["line"]) - t) for t in lines) > window:
            continue
        hit_loc = True
        if cwemod.matches(f.get("cwe"), item.get("cwes") or []):
            hit_strict = True
        if cwemod.matches(f.get("cwe"), item.get("cwes") or [], loose=True):
            hit_strict_loose = True
    return {"hit_loc": hit_loc, "hit_strict": hit_strict, "hit_loose": hit_strict_loose, "hit_file": hit_file,
            "flagged": bool(findings), "n_findings": len(findings)}


def metrics(rows: list[tuple[dict, dict]]) -> dict:
    by = collections.defaultdict(list)
    pos_by_pair, fixed_by_pair = {}, {}
    for item, j in rows:
        role = ROLE[item["kind"]]
        by[role].append(j)
        key = item.get("pair") or item.get("ghsa_id")
        if key and role == "pos":
            pos_by_pair[key] = j
        elif key and role == "fixed":
            fixed_by_pair[key] = j
    intro, fix, ben = by["pos"], by["fixed"], by["benign"]
    def rate(xs, k):
        return sum(x[k] for x in xs) / len(xs) if xs else float("nan")
    flagged = sum(x["flagged"] for x in intro + fix + ben)
    pairs = [(pos_by_pair[k], fixed_by_pair[k]) for k in pos_by_pair if k in fixed_by_pair]
    return {
        "n_pairs": len(pairs),
        "pair_acc": (sum(p["hit_strict"] and not f["site_flag"] for p, f in pairs) / len(pairs)) if pairs else float("nan"),
        "fix_site_flag_rate": rate(fix, "site_flag"),
        "n_intro": len(intro), "n_fix": len(fix), "n_benign": len(ben),
        "recall_strict": rate(intro, "hit_strict"),
        "recall_loose": rate(intro, "hit_loose"),
        "recall_loc": rate(intro, "hit_loc"),
        "recall_file": rate(intro, "hit_file"),
        "fix_flag_rate": rate(fix, "flagged"),
        "benign_flag_rate": rate(ben, "flagged"),
        "fp_per_benign": (sum(x["n_findings"] for x in ben) / len(ben)) if ben else float("nan"),
        "precision_strict": (sum(x["hit_strict"] for x in intro) / flagged) if flagged else float("nan"),
    }


def resample_rows(by_repo: dict, pick: list[str]) -> list[tuple[dict, dict]]:
    """Rows for one bootstrap draw. A repo drawn twice must count twice, so each draw gets its own pair keys;
    otherwise metrics() collapses the duplicates."""
    out = []
    for draw, k in enumerate(pick):
        for item, j in by_repo[k]:
            key = item.get("pair") or item.get("ghsa_id")
            out.append(({**item, "pair": f"{key}#{draw}"} if key else item, j))
    return out


def bootstrap(rows: list[tuple[dict, dict]], iters: int = 1000, seed: int = 0) -> dict[str, tuple[float, float]]:
    by_repo = collections.defaultdict(list)
    for r in rows:
        by_repo[r[0]["repo"]].append(r)
    repos = sorted(by_repo)
    rng = random.Random(seed)
    samples = collections.defaultdict(list)
    for _ in range(iters):
        pick = [rng.choice(repos) for _ in repos]
        resampled = resample_rows(by_repo, pick)
        m = metrics(resampled)
        for k, v in m.items():
            if not k.startswith("n_") and v == v:  # skip NaN
                samples[k].append(v)
    ci = {}
    for k, vs in samples.items():
        vs.sort()
        ci[k] = (vs[int(0.025 * len(vs))], vs[min(len(vs) - 1, int(0.975 * len(vs)))])
    return ci


def score_run(items: list[dict], findings: dict[str, list[dict]], errored: set[str],
              window: int = 5, iters: int = 1000) -> dict:
    missing = [it["id"] for it in items if it["id"] not in findings]
    rows = [(it, judge_item(it, findings.get(it["id"], []), window)) for it in items]
    return {"metrics": metrics(rows), "ci95": bootstrap(rows, iters),
            "n_errored": len(errored), "n_missing": len(missing), "missing": missing[:20]}
