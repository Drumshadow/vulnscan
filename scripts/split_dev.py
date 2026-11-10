"""Repo-level tune/check split of the dev_nc frontier sample (60/40 by repo, seed 1729). Writes
data/bench/dev_nc_{tune,check}_ids.json. Iterate harness v2 on tune; adopt a change only if check agrees."""
from __future__ import annotations

import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import BENCH, load_items, sample_ids  # noqa: E402

items = [i for i in load_items("dev_nc") if i["id"] in sample_ids("dev_nc", "frontier")]
repos = sorted({i["repo"] for i in items})
random.Random(1729).shuffle(repos)
tune_repos = set(repos[: int(0.6 * len(repos))])
for name, keep in (("tune", lambda r: r in tune_repos), ("check", lambda r: r not in tune_repos)):
    ids = sorted(i["id"] for i in items if keep(i["repo"]))
    (BENCH / f"dev_nc_{name}_ids.json").write_text(json.dumps(ids) + "\n")
    kinds = {k: sum(1 for i in items if i["id"] in set(ids) and i["kind"] == k) for k in ("nc_vuln", "nc_fixed", "nc_benign")}
    print(name, len(ids), kinds)
