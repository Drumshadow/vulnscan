"""CPU-only: how much context v1 vs v2 builds per item (no model calls). H1 acceptance: >=85% of items get
caller or callee context under v2.   context_coverage.py [--sample frontier] [--limit N]"""
from __future__ import annotations

import argparse
import pathlib
import statistics as S
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import load_items, sample_ids  # noqa: E402
from vs.harness import call_sites, changed_symbols  # noqa: E402
from vs.harness_v2 import context_v2  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--split", default="dev_nc")
ap.add_argument("--sample", default="frontier")
ap.add_argument("--limit", type=int, default=0)
a = ap.parse_args()
items = [i for i in load_items(a.split) if i["id"] in sample_ids(a.split, a.sample)][: a.limit or None]
v1, v2c, v2e, v2any = [], [], [], []
for n, it in enumerate(items, 1):
    v1.append(len(call_sites(it, changed_symbols(it))))
    _, ctx = context_v2(it)
    v2c.append(ctx["n_call_site_chars"]); v2e.append(ctx["n_callee_chars"])
    v2any.append(ctx["n_call_site_chars"] + ctx["n_callee_chars"])
    if n % 50 == 0:
        print(f"  {n}/{len(items)}", flush=True)
pct = lambda xs: 100 * sum(x > 0 for x in xs) / len(xs)  # noqa: E731
print(f"items {len(items)}")
print(f"v1 call sites non-empty: {pct(v1):.0f}%  (median chars {S.median(v1):.0f})")
print(f"v2 call sites non-empty: {pct(v2c):.0f}%  callee defs non-empty: {pct(v2e):.0f}%  either: {pct(v2any):.0f}%")
