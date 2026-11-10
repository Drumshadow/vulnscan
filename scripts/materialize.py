"""Turn split records into PR-shaped benchmark items (git work; CPU + network only).

For each advisory in --split:
  positive  ("vuln_intro"): diff fix -> fix^ (the reverse of the fix), i.e. a PR that introduces
            the vulnerability. Checkout for context = fix^ (head). Ground truth = head-side lines the
            fix removed; a pure-addition fix is anchored at the head line where the fix inserted code.
  hard neg  ("fix"):        diff fix^ -> fix (the fix itself). Expected: no finding.
For each repo in the split, --neg-ratio x (#positives) benign commits ("benign"): non-merge commits
authored on/after --cutoff, not linked to any advisory, no security-ish words in the message,
forward diff parent -> commit. Expected: no finding (label noise acknowledged in DATA.md).

Only source files are kept in diffs (tests, docs, changelogs, lockfiles stripped) so the PR does not
leak the fix's regression test. Items above --max-lines changed lines or --max-files files are skipped.

Repos are blobless bare clones under data/repos/. Output: data/bench/<split>.jsonl + <split>.skips.json.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import json
import pathlib
import random
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.diffutil import HUNK_RE, head_truth  # noqa: E402,F401

SRC_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", ".go", ".rs",  # .go/.rs: wave 2
           ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}  # wave 3
TEST_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|testing|e2e|fixtures?|examples?|docs?|benches|testdata|fuzz|fuzzing|oss-fuzz)/"
                     r"|_test\.go$"
                     r"|(^|/)(test_[^/]*|[^/]*_test|conftest)\.py$"
                     r"|\.(test|spec)\.[cm]?[jt]sx?$", re.I)
SEC_MSG_RE = re.compile(r"cve|ghsa|secur|vuln|xss|csrf|ssrf|inject|saniti|escap|travers|exploit|overflow"
                        r"|\bdos\b|redos|auth|permission|privilege|sandbox|leak|unsafe|cwe|bypass|harden", re.I)


def git(repo: pathlib.Path, *args: str, check: bool = True) -> str:
    # C/C++ history holds non-UTF-8 bytes (Latin-1 comments, binary-ish headers); never crash a build on them
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, errors="replace", timeout=600)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:3])}: {r.stderr.strip()[:300]}")
    return r.stdout


def repo_dir(root: pathlib.Path, repo: str) -> pathlib.Path:
    return root / repo.replace("/", "__")


def ensure_clone(root: pathlib.Path, repo: str) -> pathlib.Path:
    d = repo_dir(root, repo)
    if not (d / "HEAD").exists():
        subprocess.run(["git", "clone", "-q", "--bare", "--filter=blob:none",
                        f"https://github.com/{repo}.git", str(d)],
                       check=True, capture_output=True, text=True, timeout=1800,
                       env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin"})
    return d


def resolve(d: pathlib.Path, sha: str) -> str | None:
    out = git(d, "rev-parse", "--verify", "-q", f"{sha}^{{commit}}", check=False).strip()
    if out:
        return out
    git(d, "fetch", "-q", "--filter=blob:none", "origin", sha, check=False)
    return git(d, "rev-parse", "--verify", "-q", f"{sha}^{{commit}}", check=False).strip() or None


def keep_file(path: str) -> bool:
    return pathlib.PurePosixPath(path).suffix.lower() in SRC_EXT and not TEST_RE.search(path)


def filtered_diff(d: pathlib.Path, a: str, b: str, max_lines: int, max_files: int):
    """Diff a->b restricted to kept source files. Returns (diff, files, n_lines) or (None, reason)."""
    names = [n for n in git(d, "diff", "--name-only", "--no-renames", a, b).splitlines() if n]
    files = [n for n in names if keep_file(n)]
    if not files:
        return None, "no_source_change"
    if len(files) > max_files:
        return None, "too_many_files"
    diff = git(d, "diff", "-U3", "--no-renames", "--no-color", a, b, "--", *files)
    n = sum(1 for l in diff.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---")))
    if n == 0:
        return None, "empty_diff"
    if n > max_lines:
        return None, "too_large"
    return (diff, files, n), None


def do_repo(root: pathlib.Path, repo: str, advs: list[dict], all_adv_commits: set[str], args) -> tuple[list, list]:
    items, skips = [], []
    try:
        d = ensure_clone(root, repo)
    except Exception as e:  # noqa: BLE001
        return [], [{"repo": repo, "reason": "clone_failed", "detail": str(e)[:200]}]
    n_pos = 0
    for a in advs:
        sha = resolve(d, a["commits"][0])
        if not sha:
            skips.append({"ghsa_id": a["ghsa_id"], "reason": "commit_unreachable"}); continue
        parents = git(d, "rev-list", "--parents", "-n1", sha).split()[1:]
        if len(parents) != 1:
            skips.append({"ghsa_id": a["ghsa_id"], "reason": "merge_or_root"}); continue
        parent = parents[0]
        res, why = filtered_diff(d, sha, parent, args.max_lines, args.max_files)
        if why:
            skips.append({"ghsa_id": a["ghsa_id"], "reason": why}); continue
        diff, files, n = res
        meta = {k: a[k] for k in ("ghsa_id", "cve_id", "ecosystem", "published_at", "severity", "cwes", "summary")}
        items.append({"id": f"{a['ghsa_id']}:intro", "kind": "vuln_intro", "repo": repo, "base": sha, "head": parent,
                      "files": files, "changed_lines": n, "diff": diff, "truth": head_truth(diff), **meta})
        fres, fwhy = filtered_diff(d, parent, sha, args.max_lines, args.max_files)
        if not fwhy:
            fdiff, ffiles, fn = fres
            items.append({"id": f"{a['ghsa_id']}:fix", "kind": "fix", "repo": repo, "base": parent, "head": sha,
                          "files": ffiles, "changed_lines": fn, "diff": fdiff, "truth": {}, **meta})
        n_pos += 1
    if n_pos == 0:
        return items, skips
    want = args.neg_ratio * n_pos
    log = git(d, "log", "--all", "--no-merges", f"--since={args.cutoff}", "--format=%H%x09%P%x09%aI%x09%s")
    cands = []
    for line in log.splitlines():
        h, p, date, subj = (line.split("\t", 3) + ["", "", "", ""])[:4]
        if h in all_adv_commits or len(p.split()) != 1 or SEC_MSG_RE.search(subj) or date[:10] < args.cutoff:
            continue
        cands.append((h, p, date, subj))
    random.Random(f"{args.seed}:{repo}").shuffle(cands)
    got = 0
    for h, p, date, subj in cands[: want * 8]:
        if got >= want:
            break
        res, why = filtered_diff(d, p, h, args.max_lines, args.max_files)
        if why:
            continue
        diff, files, n = res
        items.append({"id": f"{repo}@{h[:12]}:benign", "kind": "benign", "repo": repo, "base": p, "head": h,
                      "files": files, "changed_lines": n, "diff": diff, "truth": {}, "commit_subject": subj,
                      "published_at": date, "ecosystem": advs[0]["ecosystem"], "cwes": []})
        got += 1
    if got < want:
        skips.append({"repo": repo, "reason": "benign_short", "wanted": want, "got": got})
    return items, skips


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", required=True, help="split file name in --splits (test, dev, ...)")
    ap.add_argument("--name", help="output name in --out (default: the split name)")
    ap.add_argument("--splits", default="data/splits")
    ap.add_argument("--fixes", default="data/interim/fixes.jsonl")
    ap.add_argument("--repos", default="data/repos")
    ap.add_argument("--out", default="data/bench")
    ap.add_argument("--cutoff", default="2026-07-01")
    ap.add_argument("--neg-ratio", type=int, default=2)
    ap.add_argument("--max-lines", type=int, default=400)
    ap.add_argument("--max-files", type=int, default=10)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--limit-repos", type=int, default=0)
    args = ap.parse_args()

    root = pathlib.Path(args.repos); root.mkdir(parents=True, exist_ok=True)
    out = pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True)
    rows = [json.loads(l) for l in (pathlib.Path(args.splits) / f"{args.split}.jsonl").open()]
    all_adv_commits = {c for l in pathlib.Path(args.fixes).open() for c in json.loads(l)["commits"]}
    by_repo: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        by_repo[r["repo"]].append(r)
    repos = sorted(by_repo)[: args.limit_repos or None]

    items, skips = [], []
    with cf.ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(do_repo, root, k, by_repo[k], all_adv_commits, args): k for k in repos}
        for i, f in enumerate(cf.as_completed(futs), 1):
            it, sk = f.result()
            items += it; skips += sk
            print(f"[{i}/{len(repos)}] {futs[f]}: +{len(it)} items, {len(sk)} skips", flush=True)
    # Full-sha resolution can surface a commit that is also another split's commit; re-check here.
    items.sort(key=lambda x: x["id"])
    with (out / f"{args.name or args.split}.jsonl").open("w") as f:
        for it in items:
            f.write(json.dumps(it) + "\n")
    summary = {"items": dict(collections.Counter(i["kind"] for i in items)),
               "by_ecosystem": dict(collections.Counter((i["ecosystem"], i["kind"]) and f"{i['ecosystem']}/{i['kind']}" for i in items)),
               "skips": dict(collections.Counter(s["reason"] for s in skips))}
    (out / f"{args.name or args.split}.skips.json").write_text(json.dumps({"summary": summary, "skips": skips}, indent=1) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
