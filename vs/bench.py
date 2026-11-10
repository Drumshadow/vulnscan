"""Bench item loading, file access from the blobless bare clones, and the run loop shared by all arms."""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import traceback

from . import store

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPOS = ROOT / "data" / "repos"
BENCH = ROOT / "data" / "bench"


def load_items(split: str) -> list[dict]:
    return [json.loads(l) for l in (BENCH / f"{split}.jsonl").open()]


def sample_ids(split: str, name: str) -> set[str]:
    """Deterministic item subsets (seed 1729).
    'frontier' on a regression split = every vuln_intro + 80 benign + 80 fix;
    on a new-code split (*_nc) = every nc_vuln + every nc_fixed (pairs stay whole) + 80 nc_benign."""
    import random
    if name in ("tune", "check"):
        # repo-level split of the dev_nc frontier sample (scripts/split_dev.py); iterate on tune, confirm on check
        ids = json.loads((BENCH / f"{split}_{name}_ids.json").read_text())
        return set(ids)
    if name != "frontier":
        raise ValueError(f"unknown sample {name}")
    items = load_items(split)
    if split.endswith("_nc"):
        ids = {i["id"] for i in items if i["kind"] in ("nc_vuln", "nc_fixed")}
        pool = sorted(i["id"] for i in items if i["kind"] == "nc_benign")
        return ids | set(random.Random(f"1729:{split}:nc_benign").sample(pool, min(80, len(pool))))
    ids = {i["id"] for i in items if i["kind"] == "vuln_intro"}
    for kind in ("benign", "fix"):
        pool = sorted(i["id"] for i in items if i["kind"] == kind)
        ids |= set(random.Random(f"1729:{split}:{kind}").sample(pool, min(80, len(pool))))
    return ids


def bench_sha(split: str) -> str:
    return hashlib.sha256((BENCH / f"{split}.jsonl").read_bytes()).hexdigest()


def check_frozen(split: str) -> None:
    """Refuse to run if the bench file no longer matches BENCH.sha256."""
    want = {}
    for line in (ROOT / "BENCH.sha256").read_text().splitlines():
        h, p = line.split(maxsplit=1)
        want[p.strip()] = h
    key = f"data/bench/{split}.jsonl"
    if want.get(key) != bench_sha(split):
        sys.exit(f"{key} does not match BENCH.sha256; refusing to run")


def repo_dir(repo: str) -> pathlib.Path:
    """Bench repos are bare clones under data/repos/<owner>__<name>; `vulnscan review` passes an absolute path."""
    return pathlib.Path(repo) if repo.startswith("/") else REPOS / repo.replace("/", "__")


def file_at(repo: str, sha: str, path: str) -> str | None:
    d = repo_dir(repo)
    r = subprocess.run(["git", "-C", str(d), "show", f"{sha}:{path}"], capture_output=True, timeout=300)
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", errors="replace")


INFRA_ERRORS = ("URLError", "HTTPError: HTTP Error 5", "TimeoutExpired", "TimeoutError", "ConnectionError",
                "RemoteDisconnected", "claude rc=1", "codex rc=", "rate limit", "usage limit", "overloaded")


def is_infra_error(err: str | None) -> bool:
    """Infrastructure failures are retried on resume; model failures (max_tokens, unparseable output) are
    final and count as misses (DATA.md run policy)."""
    return bool(err) and any(k in err for k in INFRA_ERRORS)


def run_arm(arm_name: str, split: str, review_fn, config: dict, *, final: bool, workers: int,
            limit: int = 0, kinds: list[str] | None = None, run_id: str | None = None, sample: str | None = None,
            db_path: str | pathlib.Path = ROOT / "results" / "vulnscan.sqlite") -> str:
    """review_fn(item) -> (findings, meta) where meta may hold tokens_in/out and raw."""
    if split.startswith("test") and not final:
        sys.exit("the test split only runs with --final (once per frozen arm); iterate on dev")
    check_frozen(split)
    items = load_items(split)
    if kinds:
        items = [i for i in items if i["kind"] in kinds]
    if sample:
        keep = sample_ids(split, sample)
        items = [i for i in items if i["id"] in keep]
        config = {**config, "sample": sample}
    if limit:
        items = items[:limit]
    cfg_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:10]
    run_id = run_id or f"{arm_name}:{split}:{cfg_hash}" + (f":n{limit}" if limit else "")
    db = store.connect(db_path)
    if final:
        prior = db.execute("SELECT run_id FROM runs WHERE arm=? AND split=? AND final=1 AND run_id!=?",
                           (arm_name, split, run_id)).fetchall()
        if prior:
            sys.exit(f"arm {arm_name} already has a final test run {prior[0][0]}; a second one needs a new arm name")
    store.start_run(db, run_id, arm_name, split, bench_sha(split), config, final=final)
    done = store.done_items(db, run_id) | {
        iid for iid, err in db.execute("SELECT item_id, error FROM items WHERE run_id=? AND ok=0", (run_id,))
        if not is_infra_error(err)}
    todo = [i for i in items if i["id"] not in done]
    print(f"run {run_id}: {len(items)} items, {len(done)} final (ok or model failure), {len(todo)} to go", flush=True)

    def one(item):
        t0 = time.time()
        try:
            findings, meta = review_fn(item)
            return item, findings, meta, None, time.time() - t0
        except Exception as e:  # noqa: BLE001
            return item, None, {}, f"{type(e).__name__}: {e}"[:500] + "\n" + traceback.format_exc()[-800:], time.time() - t0

    n = 0
    with cf.ThreadPoolExecutor(workers) as ex:
        for item, findings, meta, err, dt in ex.map(one, todo):
            store.record_item(db, run_id, item["id"], findings, error=err, latency_s=dt,
                              tokens_in=meta.get("tokens_in"), tokens_out=meta.get("tokens_out"), raw=meta.get("raw"))
            n += 1
            if n % 10 == 0 or err:
                print(f"  {n}/{len(todo)} {item['id']} {'ERR ' + err.splitlines()[0] if err else len(findings or [])}", flush=True)
    store.finish_run(db, run_id)
    return run_id
