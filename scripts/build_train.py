"""Build paired region-level training data for the U3 triage model from the TRAIN split only.

Per train advisory (each linked fix commit in the advisory's repo):
  pos   : region around each fix hunk at fix^ (vulnerable), label = CWE family of the advisory
  neg   : the same region at fix (patched)                   -- the hard, paired negative
  far   : one region at fix^ at least --far lines from every hunk (easy negative; may rarely hold
          another bug -- documented label noise)
Regions = hunk +-pad lines, merged, capped at --max-region lines. Comment lines that cite an advisory
id are removed from both versions; pairs whose texts are identical after that are dropped.
Resumable: repos already listed in <out>.done are skipped. Never touches dev/test repos (asserted).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from materialize import ensure_clone, filtered_diff, git, keep_file, resolve  # noqa: E402
from vs import cwe as cwemod  # noqa: E402
from vs.diffutil import head_truth, hunk_ranges, merge_windows  # noqa: E402
from vs.prompt import redact  # noqa: E402

ADVISORY_ID_RE = re.compile(r"CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-", re.I)


def show(d, sha, path) -> list[str] | None:
    r = git(d, "show", f"{sha}:{path}", check=False)
    return r.splitlines() if r else None


def redacted(lines: list[str]) -> list[str]:
    """v2: redact advisory-id lines IN PLACE (same as the review prompt) so real line numbers stay valid."""
    return [redact(l) for l in lines]


def clean(lines: list[str]) -> list[str]:
    return [l for l in lines if not ADVISORY_ID_RE.search(l)]


def regions(diff: str, side_lines: dict[str, list[str]], pad: int, cap: int) -> dict[str, list[tuple[int, int]]]:
    out = {}
    for f, rs in hunk_ranges(diff).items():
        n = len(side_lines.get(f) or [])
        if not n:
            continue
        ws = merge_windows(rs, pad, n)
        out[f] = [(s, min(e, s + cap - 1)) for s, e in ws]
    return out


def do_repo(root, repo, advs, args):
    try:
        d = ensure_clone(root, repo)
    except Exception as e:  # noqa: BLE001
        return [], {"repo": repo, "skip": "clone_failed", "detail": str(e)[:200]}
    rows = []
    for a in advs:
        fam = sorted({cwemod.family(c) for c in a["cwes"] if cwemod.family(c)}) or ["unknown"]
        for c in a["commits"][: args.max_commits]:
            sha = resolve(d, c)
            if not sha:
                continue
            parents = git(d, "rev-list", "--parents", "-n1", sha).split()[1:]
            if len(parents) != 1:
                continue
            parent = parents[0]
            res, why = filtered_diff(d, parent, sha, args.max_lines, args.max_files)  # forward fix diff
            if why:
                continue
            diff, files, _ = res
            rev, rwhy = filtered_diff(d, sha, parent, args.max_lines, args.max_files)  # reverse: fix^ side as "new"
            if rwhy:
                continue
            rdiff = rev[0]
            for f in files:
                if not keep_file(f):
                    continue
                vuln = show(d, parent, f)
                fixed = show(d, sha, f)
                if not vuln or not fixed:
                    continue
                vr = regions(rdiff, {f: vuln}, args.pad, args.max_region).get(f, [])
                fr = regions(diff, {f: fixed}, args.pad, args.max_region).get(f, [])
                for i, ((vs, ve), (fs, fe)) in enumerate(zip(vr, fr)):
                    vt, ft = redacted(vuln[vs - 1:ve]), redacted(fixed[fs - 1:fe])
                    if "\n".join(x.strip() for x in vt) == "\n".join(x.strip() for x in ft):
                        continue
                    base = {"ghsa_id": a["ghsa_id"], "repo": repo, "ecosystem": a["ecosystem"], "file": f,
                            "families": fam, "cwes": a["cwes"], "pair": f"{a['ghsa_id']}:{sha[:12]}:{f}:{i}"}
                    vtruth = [ln for ln in head_truth(rdiff).get(f, []) if vs <= ln <= ve]
                    fsite = [ln for ln in head_truth(diff).get(f, []) if fs <= ln <= fe]
                    rows.append({**base, "label": 1, "kind": "pos", "sha": parent, "span": [vs, ve], "text": "\n".join(vt),
                                 "truth_lines": vtruth, "summary": a.get("summary") or ""})
                    rows.append({**base, "label": 0, "kind": "neg", "sha": sha, "span": [fs, fe], "text": "\n".join(ft),
                                 "fix_site": fsite, "summary": a.get("summary") or ""})
                if vr and len(vuln) > 2 * args.far:
                    hunks = [x for r in vr for x in r]
                    for start in range(1, len(vuln) - args.max_region, args.max_region // 2):
                        end = start + min(args.max_region, 80) - 1
                        if all(abs(start - h) >= args.far and abs(end - h) >= args.far for h in hunks):
                            rows.append({"ghsa_id": a["ghsa_id"], "repo": repo, "ecosystem": a["ecosystem"],
                                         "file": f, "families": [], "cwes": [], "pair": None, "label": 0,
                                         "kind": "far", "sha": parent, "span": [start, end],
                                         "text": "\n".join(redacted(vuln[start - 1:end])), "truth_lines": []})
                            break
    return rows, None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits", default="data/splits")
    ap.add_argument("--repos", default="data/repos")
    ap.add_argument("--out", default="data/train/regions_v2.jsonl")
    ap.add_argument("--pad", type=int, default=40)
    ap.add_argument("--max-region", type=int, default=160)
    ap.add_argument("--far", type=int, default=120)
    ap.add_argument("--max-lines", type=int, default=400)
    ap.add_argument("--max-files", type=int, default=10)
    ap.add_argument("--max-commits", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit-repos", type=int, default=0)
    args = ap.parse_args()
    split_dir = pathlib.Path(args.splits)
    train = [json.loads(l) for l in (split_dir / "train.jsonl").open()]
    held = {json.loads(l)["repo"] for s in ("dev", "test") for l in (split_dir / f"{s}.jsonl").open()}
    assert not held & {a["repo"] for a in train}, "train repo overlaps dev/test"
    by_repo: dict[str, list[dict]] = {}
    for a in train:
        by_repo.setdefault(a["repo"], []).append(a)
    out = pathlib.Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    done_path = out.with_suffix(".done")
    done = set(done_path.read_text().split()) if done_path.exists() else set()
    todo = [r for r in sorted(by_repo) if r not in done][: args.limit_repos or None]
    root = pathlib.Path(args.repos)
    print(f"{len(by_repo)} train repos, {len(done)} done, {len(todo)} to go", flush=True)
    n = 0
    with cf.ThreadPoolExecutor(args.workers) as ex, out.open("a") as fo, done_path.open("a") as fd, \
            (out.parent / "skips.jsonl").open("a") as fs:
        futs = {ex.submit(do_repo, root, r, by_repo[r], args): r for r in todo}
        for fut in cf.as_completed(futs):
            repo = futs[fut]
            try:
                rows, skip = fut.result()
            except Exception as e:  # noqa: BLE001
                rows, skip = [], {"repo": repo, "skip": "error", "detail": str(e)[:200]}
            for r in rows:
                fo.write(json.dumps(r) + "\n")
            if skip:
                fs.write(json.dumps(skip) + "\n")
            fd.write(repo + "\n"); fo.flush(); fd.flush()
            n += 1
            if n % 50 == 0:
                print(f"  {n}/{len(todo)} repos", flush=True)
    print("done", flush=True)


if __name__ == "__main__":
    main()
