"""Build the paired "new code" framing from an existing (frozen) regression bench split.

Why: on the reversed-fix framing, surface diff statistics alone separate vuln_intro from benign/fix at
AUC 0.95 (scripts/shortcut_probe.py): reversed fixes are mostly deletions. Here every item is
presented as a PR that ADDS code, so diff shape carries no label signal.

For every advisory with both a vuln_intro and a fix item:
  nc_vuln  : the changed files at fix^ (vulnerable), shown as new code.   Expected: finding at truth.
  nc_fixed : the same files at fix (patched), shown as new code.          Expected: nothing at fix_site.
For every benign item:
  nc_benign: the changed files at the commit, shown as new code.          Expected: nothing.
Files of <= --whole lines are shown whole; larger files as +-pad-line windows around that version's own
hunks (true line numbers kept). Both versions of a pair get identical treatment.
Writes data/bench/<split>_nc.jsonl. No new git clones; reads the bare repos.
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import BENCH, file_at  # noqa: E402
from vs.diffutil import head_truth, hunk_ranges, merge_windows  # noqa: E402


def views(item: dict, whole: int, pad: int) -> tuple[dict, int] | None:
    ranges = hunk_ranges(item["diff"])
    out, total = {}, 0
    for f in item["files"]:
        content = file_at(item["repo"], item["head"], f)
        if content is None:
            continue  # file deleted on this side: nothing to show
        n = len(content.splitlines())
        if n <= whole:
            out[f] = [[1, n]]; total += n
        else:
            w = merge_windows(ranges.get(f, []), pad, n)
            if not w:
                continue
            out[f] = [list(x) for x in w]; total += sum(e - s + 1 for s, e in w)
    return (out, total) if out else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("split")
    ap.add_argument("--whole", type=int, default=600)
    ap.add_argument("--pad", type=int, default=150)
    args = ap.parse_args()
    items = [json.loads(l) for l in (BENCH / f"{args.split}.jsonl").open()]
    by_ghsa = collections.defaultdict(dict)
    for it in items:
        if it["kind"] in ("vuln_intro", "fix"):
            by_ghsa[it["ghsa_id"]][it["kind"]] = it
    common = ("repo", "ecosystem", "cwes", "published_at")
    out, skipped = [], collections.Counter()
    for ghsa, pair in sorted(by_ghsa.items()):
        if "vuln_intro" not in pair or "fix" not in pair:
            skipped["unpaired"] += 1; continue
        vi, fx = pair["vuln_intro"], pair["fix"]
        v, f = views(vi, args.whole, args.pad), views(fx, args.whole, args.pad)
        if not v or not f:
            skipped["no_view"] += 1; continue
        truth = {k: ls for k, ls in vi["truth"].items() if k in v[0]}
        fix_site = {k: ls for k, ls in head_truth(fx["diff"]).items() if k in f[0]}
        if not truth:
            skipped["truth_not_shown"] += 1; continue
        meta = {k: vi.get(k) for k in common} | {"ghsa_id": ghsa, "pair": ghsa, "framing": "newcode",
                                                 "leak": vi.get("leak", {})}
        out.append({**meta, "id": f"{ghsa}:nc_vuln", "kind": "nc_vuln", "head": vi["head"], "base": None,
                    "files": list(v[0]), "views": v[0], "shown_lines": v[1], "truth": truth, "diff": ""})
        out.append({**meta, "id": f"{ghsa}:nc_fixed", "kind": "nc_fixed", "head": fx["head"], "base": None,
                    "files": list(f[0]), "views": f[0], "shown_lines": f[1], "truth": {}, "fix_site": fix_site,
                    "diff": ""})
    for it in items:
        if it["kind"] != "benign":
            continue
        b = views(it, args.whole, args.pad)
        if not b:
            skipped["benign_no_view"] += 1; continue
        out.append({"id": it["id"].replace(":benign", ":nc_benign"), "kind": "nc_benign", "framing": "newcode",
                    "repo": it["repo"], "ecosystem": it["ecosystem"], "cwes": [], "published_at": it["published_at"],
                    "head": it["head"], "base": None, "files": list(b[0]), "views": b[0], "shown_lines": b[1],
                    "truth": {}, "diff": "", "pair": None})
    out.sort(key=lambda x: x["id"])
    dst = BENCH / f"{args.split}_nc.jsonl"
    with dst.open("w") as fh:
        for it in out:
            fh.write(json.dumps(it) + "\n")
    c = collections.Counter(f"{i['ecosystem']}/{i['kind']}" for i in out)
    sl = sorted(i["shown_lines"] for i in out if i["kind"] == "nc_vuln")
    print(f"{dst}: {dict(sorted(c.items()))}; skipped {dict(skipped)}; median shown lines (vuln) {sl[len(sl) // 2]}")


if __name__ == "__main__":
    main()
