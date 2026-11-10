"""Wave 3 source: C/C++ vulnerability fix commits from NVD (GHSA has no C/C++ ecosystem).

For CVEs published in [--since, --until): keep those whose references link a GitHub commit, keep only repos
whose GitHub primary language is C or C++, and write records in extract_fixes.py's format
(ghsa_id = CVE id, ecosystem = "c" | "cpp") to data/interim/fixes_cc.jsonl.

NVD API 2.0, unauthenticated: <= 5 requests / 30 s, publication windows <= 120 days (118 used).
GitHub token: /srv/gateway/secrets/github_token (read, never printed). Repo languages are cached.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from extract_fixes import COMMIT_RE  # noqa: E402

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TOKEN = pathlib.Path("/srv/gateway/secrets/github_token")
LANGS = {"C": "c", "C++": "cpp"}


def get_json(url: str, headers: dict | None = None, tries: int = 6):
    for k in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-research", **(headers or {})})
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(min(60, 6 * 2 ** k))
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(min(60, 6 * 2 ** k))
    raise RuntimeError(f"giving up on {url}")


def nvd_window(start: dt.datetime, end: dt.datetime):
    idx = 0
    while True:
        q = urllib.parse.urlencode({"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                                    "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                                    "resultsPerPage": 2000, "startIndex": idx})
        page = get_json(f"{NVD}?{q}")
        time.sleep(6.5)  # stay under the unauthenticated rate limit
        vulns = page.get("vulnerabilities", []) if page else []
        for v in vulns:
            yield v["cve"]
        idx += len(vulns)
        if not page or idx >= page.get("totalResults", 0) or not vulns:
            return


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="2026-07-01")
    ap.add_argument("--until", default=dt.date.today().isoformat())
    ap.add_argument("--out", default="data/interim/fixes_cc.jsonl")
    ap.add_argument("--lang-cache", default="data/interim/repo_lang.json")
    a = ap.parse_args()
    token = TOKEN.read_text().strip()
    cache_p = pathlib.Path(a.lang_cache)
    cache = json.loads(cache_p.read_text()) if cache_p.exists() else {}
    start = dt.datetime.fromisoformat(a.since)
    stop = dt.datetime.fromisoformat(a.until)
    by_repo_cve, seen = [], 0
    while start < stop:
        end = min(start + dt.timedelta(days=118), stop)
        for cve in nvd_window(start, end):
            seen += 1
            commits: dict[str, list[str]] = {}
            for ref in cve.get("references", []):
                m = COMMIT_RE.match(ref.get("url", ""))
                if m:
                    repo = f"{m.group(1)}/{m.group(2)}".lower()
                    sha = m.group(3).lower()
                    commits.setdefault(repo, [])
                    if sha not in commits[repo]:
                        commits[repo].append(sha)
            if not commits:
                continue
            repo = max(commits, key=lambda r: len(commits[r]))
            cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                           if re.match(r"CWE-\d+$", d.get("value", ""))})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            by_repo_cve.append({"ghsa_id": cve["id"], "cve_id": cve["id"], "published_at": cve.get("published", "")[:19] + "Z",
                                "severity": None, "cwes": cwes, "packages": [], "repo": repo, "commits": commits[repo],
                                "pr_urls": [], "summary": desc[:500]})
        print(f"  window {start.date()}..{end.date()}: {seen} CVEs seen, {len(by_repo_cve)} with GitHub commits", flush=True)
        start = end
    out, kept = pathlib.Path(a.out), 0
    with out.open("w") as f:
        for rec in by_repo_cve:
            r = rec["repo"]
            if r not in cache:
                meta = get_json(f"https://api.github.com/repos/{r}",
                                {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
                cache[r] = (meta or {}).get("language")
                time.sleep(0.2)
            eco = LANGS.get(cache[r] or "")
            if eco:
                f.write(json.dumps({**rec, "ecosystem": eco}) + "\n")
                kept += 1
    cache_p.write_text(json.dumps(cache))
    print(f"done: {seen} CVEs, {len(by_repo_cve)} with GitHub fix commits, {kept} in C/C++ repos -> {out}", flush=True)


if __name__ == "__main__":
    main()
