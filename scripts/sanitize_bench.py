"""Strip comment-only removed lines from every bench diff (all kinds, so it is not itself a signal),
rewrite hunk headers, drop hunks left with no change, recompute vuln_intro truth, and flag residual
leakage. Original diffs go to <split>.orig_diffs.jsonl (never read by eval arms).

Removed lines are base-side only, so the head checkout the arms read is unaffected.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from leak_scan import COMMENT_RE, scan  # noqa: E402
from materialize import HUNK_RE, head_truth  # noqa: E402

ADVISORY_ID_RE = re.compile(r"CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-", re.I)


def sanitize(diff: str) -> str:
    out: list[str] = []
    hunk: list[str] = []
    header = None

    def flush():
        nonlocal hunk, header
        if header is None:
            return
        if any(l[:1] in "+-" for l in hunk):
            m = HUNK_RE.match(header)
            old_start, new_start = int(m.group(1)), int(m.group(3))
            old_n = sum(1 for l in hunk if l[:1] in " -")
            new_n = sum(1 for l in hunk if l[:1] in " +")
            tail = header[m.end():]
            out.append(f"@@ -{old_start},{old_n} +{new_start},{new_n} @@{tail}")
            out.extend(hunk)
        hunk, header = [], None

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            flush(); out.append(line); continue
        if HUNK_RE.match(line):
            flush(); header = line; continue
        if header is None:
            out.append(line); continue
        if line.startswith("-") and (COMMENT_RE.match(line[1:]) or ADVISORY_ID_RE.search(line)):
            continue  # comment-only removed line, or one naming an advisory id: drop
        hunk.append(line)
    flush()
    # drop file sections that lost every hunk
    text, files, cur = [], [], []
    for line in out:
        if line.startswith("diff --git ") and cur:
            files.append(cur); cur = []
        cur.append(line)
    if cur:
        files.append(cur)
    for sec in files:
        if any(HUNK_RE.match(l) for l in sec):
            text.extend(sec)
    return "\n".join(text) + ("\n" if text else "")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("splits", nargs="+")
    ap.add_argument("--bench", default="data/bench")
    args = ap.parse_args()
    for s in args.splits:
        src = pathlib.Path(args.bench) / f"{s}.jsonl"
        items = [json.loads(l) for l in src.open()]
        orig_path = pathlib.Path(args.bench) / f"{s}.orig_diffs.jsonl"
        if any("leak" in it for it in items):
            # re-run: restore original diffs (truth is recomputed from them below)
            orig = {o["id"]: o["diff"] for o in map(json.loads, orig_path.open())}
            for it in items:
                it["diff"] = orig[it["id"]]
                it.pop("leak", None)
        else:
            with orig_path.open("w") as f:
                for it in items:
                    f.write(json.dumps({"id": it["id"], "diff": it["diff"]}) + "\n")
        dropped = 0
        kept = []
        for it in items:
            new = sanitize(it["diff"])
            if not new.strip():
                dropped += 1  # diff was comments only
                continue
            it["diff"] = new
            it["changed_lines"] = sum(1 for l in new.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---")))
            if it["kind"] == "vuln_intro":
                it["truth"] = head_truth(new)
            it["leak"] = scan(it) if it["kind"] == "vuln_intro" else {}
            kept.append(it)
        with src.open("w") as f:
            for it in kept:
                f.write(json.dumps(it) + "\n")
        intro = [i for i in kept if i["kind"] == "vuln_intro"]
        flag = sum(1 for i in intro if i["leak"].get("code") or i["leak"].get("comment"))
        cve = sum(1 for i in intro if i["leak"].get("cve_id"))
        print(f"{s}: {len(kept)} items ({dropped} comment-only dropped); vuln_intro {len(intro)}, "
              f"residual-leak flagged {flag}, cve-id {cve}")


if __name__ == "__main__":
    main()
