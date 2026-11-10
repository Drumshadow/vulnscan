"""Measure answer leakage in vuln_intro diffs: removed lines (the fix's code/comments) that name the
vulnerability. Reports how many items leak via comments vs via identifiers/strings.
"""
from __future__ import annotations

import collections
import json
import re
import sys

LEAK_RE = re.compile(r"CVE-\d{4}-\d+|GHSA-[\w-]+|secur|vulnerab|exploit|attack|malicious|\bDoS\b|"
                     r"inject|travers|\bXSS\b|\bSSRF\b|prototype pollution|sanitiz", re.I)
COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*|\"\"\"|''')")


def scan(item: dict) -> dict:
    removed = [l[1:] for l in item["diff"].splitlines() if l.startswith("-") and not l.startswith("---")]
    hits = [l for l in removed if LEAK_RE.search(l)]
    return {"comment": any(COMMENT_RE.match(l) for l in hits),
            "code": any(not COMMENT_RE.match(l) for l in hits),
            "cve_id": any(re.search(r"CVE-\d{4}-\d+|GHSA-", l) for l in hits)}


def main(path: str) -> None:
    c = collections.Counter()
    n = 0
    for line in open(path):
        it = json.loads(line)
        if it["kind"] != "vuln_intro":
            continue
        n += 1
        s = scan(it)
        c["any"] += s["comment"] or s["code"]
        for k, v in s.items():
            c[k] += v
    print(f"{path}: {n} vuln_intro items")
    for k in ("any", "comment", "code", "cve_id"):
        print(f"  {k:8} {c[k]:4}  ({c[k] / max(n, 1):.0%})")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        main(p)
