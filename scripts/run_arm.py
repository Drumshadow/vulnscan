"""Run one eval arm. Dev by default; the test split requires --final and runs once per arm.

  run_arm.py semgrep [--limit N] [--kinds vuln_intro]
  run_arm.py qwen35b --workers 4
  run_arm.py qwen35b --split test --final
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import run_arm  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("arm", choices=["semgrep", "qwen35b", "deephat", "qwen35b_abl", "claude", "codex", "harness", "harness_nohints", "harness_inv", "harness_v2"])
    ap.add_argument("--split", default="dev", help="bench split name (dev, test, dev_nc, test_nc, dev_w2, test_w2_nc, ...)")
    ap.add_argument("--final", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--kinds", nargs="+")
    ap.add_argument("--sample", choices=["frontier", "tune", "check"])
    ap.add_argument("--run-id", help="reuse an existing run id (its completed items are kept)")
    ap.add_argument("--v2-opts", default='{"context": "v2"}', help="harness_v2 options as JSON")
    args = ap.parse_args()
    if args.arm == "semgrep":
        from vs.arms import semgrep_arm as m
        fn, cfg = m.review, m.CONFIG
    elif args.arm in ("harness", "harness_nohints", "harness_inv"):
        from vs import harness as m
        from vs.arms import semgrep_arm
        hints = None if args.arm == "harness_nohints" else semgrep_arm.review
        refute = None if args.arm == "harness_inv" else "v1"
        fn = m.make_review(semgrep_review=hints, refute=refute)
        cfg = {**m.CONFIG, "hints": "semgrep diff-aware" if hints else "none", "refute": refute or "offline"}
    elif args.arm == "harness_v2":
        import json as _json
        from vs import harness_v2 as m
        from vs.arms import semgrep_arm
        opts = _json.loads(args.v2_opts)
        fn, cfg = m.make_review(opts, semgrep_review=semgrep_arm.review), m.config(opts)
    elif args.arm in ("claude", "codex"):
        from vs.arms import cli_arm as m
        fn, cfg = m.REVIEW[args.arm], m.CONFIGS[args.arm]
    else:
        from vs.arms import llm_arm as m
        fn, cfg = m.make_review(args.arm), m.config(args.arm)
    rid = run_arm(args.arm, args.split, fn, cfg, final=args.final, workers=args.workers,
                  limit=args.limit, kinds=args.kinds, sample=args.sample, run_id=args.run_id)
    print(f"done: {rid}")


if __name__ == "__main__":
    main()
