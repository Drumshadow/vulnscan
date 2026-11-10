"""Fetch reviewed GitHub Security Advisories (GHSA) per ecosystem into data/raw/ghsa/.

Writes one JSONL per ecosystem (raw API objects, unmodified) plus MANIFEST.json with counts,
fetch time and the query used. Fix commits are NOT resolved here; see extract_fixes.py.

The token is read from /srv/gateway/secrets/github_token and never printed or logged.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com/advisories"
TOKEN_PATH = pathlib.Path("/srv/gateway/secrets/github_token")
ECOSYSTEMS = ["pip", "npm", "go", "rust"]  # C/C++ come from PrimeVul/MegaVul (no GHSA ecosystem)


def _token() -> str:
    return TOKEN_PATH.read_text().strip()


def _get(url: str, token: str) -> tuple[list, str | None]:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "vulnscan-fetch",
    })
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                remaining = int(r.headers.get("X-RateLimit-Remaining", "1000"))
                if remaining < 50:
                    reset = int(r.headers.get("X-RateLimit-Reset", "0"))
                    wait = max(0, reset - int(time.time())) + 5
                    print(f"  rate limit low ({remaining}); sleeping {wait}s", flush=True)
                    time.sleep(wait)
                link = r.headers.get("Link", "")
                nxt = None
                for part in link.split(","):
                    if 'rel="next"' in part:
                        nxt = part[part.find("<") + 1: part.find(">")]
                return json.load(r), nxt
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 502, 503) and attempt < 4:
                time.sleep(2 ** attempt * 5)
                continue
            raise
        except urllib.error.URLError:
            if attempt < 4:
                time.sleep(2 ** attempt * 5)
                continue
            raise
    raise RuntimeError("unreachable")


def fetch(ecosystem: str, out: pathlib.Path, token: str) -> int:
    q = urllib.parse.urlencode({"type": "reviewed", "ecosystem": ecosystem, "per_page": 100,
                                "sort": "published", "direction": "asc"})
    url: str | None = f"{API}?{q}"
    n = 0
    seen: set[str] = set()
    with out.open("w") as f:
        while url:
            items, url = _get(url, token)
            for adv in items:
                if adv["ghsa_id"] in seen:
                    continue
                seen.add(adv["ghsa_id"])
                f.write(json.dumps(adv) + "\n")
                n += 1
            print(f"  {ecosystem}: {n}", flush=True)
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/raw/ghsa")
    ap.add_argument("--ecosystems", nargs="+", default=ECOSYSTEMS)
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    token = _token()
    manifest = {"fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "source": API, "query": {"type": "reviewed", "sort": "published"},
                "license_note": "GHSA database content is CC-BY-4.0 (github/advisory-database).",
                "counts": {}}
    for eco in args.ecosystems:
        print(f"fetching {eco}", flush=True)
        manifest["counts"][eco] = fetch(eco, out / f"{eco}.jsonl", token)
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest["counts"]))


if __name__ == "__main__":
    main()
