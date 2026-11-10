"""Extract fix-commit candidates from raw GHSA advisories.

Output: data/interim/fixes.jsonl, one row per advisory that links >=1 GitHub commit:
  {ghsa_id, cve_id, ecosystem, published_at, severity, cwes, packages, repo, commits:[sha], pr_urls}
Advisories whose commit links span several repos keep only commits in the dominant repo
(the advisory's source_code_location when present).

Prints a coverage table: per ecosystem, total / with fix commit / published on or after --cutoff.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re

COMMIT_RE = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})", re.I)
PR_COMMIT_RE = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/pull/\d+/commits/([0-9a-f]{7,40})", re.I)
PR_RE = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/pull/(\d+)", re.I)
SRC_RE = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.I)


def _repo(owner: str, name: str) -> str:
    return f"{owner}/{name}".lower()


def extract(adv: dict) -> dict | None:
    urls = list(adv.get("references") or [])
    commits: dict[str, list[str]] = collections.defaultdict(list)
    prs: dict[str, list[str]] = collections.defaultdict(list)
    for u in urls:
        for rx in (COMMIT_RE, PR_COMMIT_RE):
            m = rx.match(u)
            if m:
                sha = m.group(3).lower()
                r = _repo(m.group(1), m.group(2))
                if sha not in commits[r]:
                    commits[r].append(sha)
                break
        else:
            m = PR_RE.match(u)
            if m:
                prs[_repo(m.group(1), m.group(2))].append(u)
    src = None
    m = SRC_RE.match(adv.get("source_code_location") or "")
    if m:
        src = _repo(m.group(1), m.group(2))
    if not commits and not prs:
        return None
    if src and (src in commits or src in prs):
        repo = src
    elif commits:
        repo = max(commits, key=lambda r: len(commits[r]))
    else:
        repo = max(prs, key=lambda r: len(prs[r]))
    return {
        "ghsa_id": adv["ghsa_id"],
        "cve_id": adv.get("cve_id"),
        "ecosystem": None,  # filled by caller
        "published_at": adv.get("published_at"),
        "severity": adv.get("severity"),
        "cwes": [c["cwe_id"] for c in (adv.get("cwes") or [])],
        "packages": sorted({(v.get("package") or {}).get("name", "") for v in adv.get("vulnerabilities") or []} - {""}),
        "repo": repo,
        "commits": commits.get(repo, []),
        "pr_urls": prs.get(repo, []),
        "summary": adv.get("summary"),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="data/raw/ghsa")
    ap.add_argument("--out", default="data/interim/fixes.jsonl")
    ap.add_argument("--cutoff", default="2026-07-01", help="eval candidates are published on/after this date")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    table = {}
    with out.open("w") as f:
        for p in sorted(pathlib.Path(args.raw).glob("*.jsonl")):
            eco = p.stem
            tot = with_commit = with_pr_only = post = post_commit = 0
            for line in p.open():
                adv = json.loads(line)
                tot += 1
                if adv.get("withdrawn_at"):
                    continue
                rec = extract(adv)
                is_post = (adv.get("published_at") or "") >= args.cutoff
                post += is_post
                if not rec:
                    continue
                rec["ecosystem"] = eco
                if rec["commits"]:
                    with_commit += 1
                    post_commit += is_post
                else:
                    with_pr_only += 1
                f.write(json.dumps(rec) + "\n")
            table[eco] = dict(total=tot, fix_commit=with_commit, pr_only=with_pr_only,
                              post_cutoff=post, post_cutoff_fix_commit=post_commit)
    print(f"{'eco':6} {'total':>7} {'commit':>7} {'pr_only':>8} {'post':>6} {'post_commit':>12}")
    for eco, t in table.items():
        print(f"{eco:6} {t['total']:7} {t['fix_commit']:7} {t['pr_only']:8} {t['post_cutoff']:6} {t['post_cutoff_fix_commit']:12}")


if __name__ == "__main__":
    main()
