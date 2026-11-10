# vulnscan

A benchmark for AI security review of pull requests, isolated by repository and limited to recent vulnerabilities,
plus a fully local reviewer measured against it.

**Findings** (frozen test set, Python + JS/TS). The headline is the 97 vulnerable/patched pairs whose fix was committed
on or after 2026-07-01. That subset was chosen after the test runs (see the writeup); all 163 are shown too:

1. **Reversed-fix benchmarks have a deletion cue.** Building "vulnerable PRs" by reversing fix commits produces diffs
   that are mostly deletions. A logistic regression on 8 surface statistics separates them from ordinary commits and fixes
   (AUC 0.95, 0.94 against ordinary commits alone; Go/Rust 0.946; C/C++ 0.923), and frontier models reach 73–74% line-window recall there.
2. **Without that cue, recall falls sharply.** Each vulnerable file is paired with its patched twin, both shown as added
   code (same probe: AUC 0.54). On the same advisories, line-window recall falls to 20–24% for frontier models. The
   framings differ in more than the cue, so not all of the gap is the shortcut.
3. **Semantic pair accuracy** (find the bug, don't flag the fix; 95% CI; the judge has only a non-specialist hand check): Codex gpt-6-astra
   **33%** (24–43), Claude Opus 5.5 **24%** (16–33), our local Qwen3.6-35B-A3B harness **13%** (7–21), semgrep **5%**
   (1–10). On all 163 pairs: 40%, 32%, 20%, 7%.
4. **What didn't help a local reviewer** on the tune set: lenses, self-consistency, attack-surface maps, invariant
   extraction, a second local model, ReDoS/CodeQL hints, and a sandboxed proof-of-concept verifier in its first form.
   Finding more bugs came with proportionally more flags on ordinary code. The freeze rule selected one candidate on tune, a
   cross-file context fix (+1 point, interval crossing zero), and it lost to v1 on the repo-disjoint check set. An
   abliterated 35B scored below the stock model. A 1.5B fine-tuned classifier stayed near chance on held-out pairs. A 7B
   generative fine-tune improved on its base model at region level (10.5% vs 4.5%) but was not run as a reviewer. Details: [`writeup/draft.md`](writeup/draft.md), evidence in
   [`evidence/`](evidence/).

Every reviewer ran on the same sample: all 163 test pairs plus 80 ordinary commits (406 items).

## What's here

| Path | What |
|---|---|
| `scripts/fetch_ghsa.py`, `extract_fixes.py`, `fetch_nvd_cc.py` | sources: GitHub Security Advisories (pip/npm/go/rust), NVD fix commits for C/C++ |
| `scripts/build_dataset.py` | repo-level splits with a hard leak check (aborts on any repo/commit/advisory overlap or cutoff violation) |
| `scripts/materialize.py`, `sanitize_bench.py`, `build_newcode.py` | PR-shaped items, answer-leak scrubbing, the paired new-code framing |
| `scripts/shortcut_probe.py` | the surface-statistics probe |
| `vs/score.py`, `scripts/judge.py` | line-window scorer (pair accuracy, recall, precision, false-alarm rates) and the semantic judge |
| `vs/harness.py` | the frozen reviewer (harness v1) |
| `vs/harness_v2.py`, `vs/analyzers.py`, `vs/poc.py`, `sandbox/` | every v2 lever we tried, including the Landlock/seccomp PoC sandbox |
| `scripts/vulnscan.py review <repo> <base>..<head>` / `--all` | run the reviewer on a real repository; markdown + JSON report |
| `scripts/stage_release.py`, `rebuild_from_release.py` | code-free dataset release, and rebuild of the reversed-fix diffs from commit SHAs |
| `DATA.md` | sources, licenses, cutoff, split rules, leakage handling, label noise, run policy |

## Reproducing

The released dataset ([Hugging Face](https://huggingface.co/datasets/drumshadow/vulnscan-pr-security)) holds metadata only: advisory ids, repos, commit SHAs, file
lists, view windows and truth lines. No third-party code is redistributed.
`scripts/rebuild_from_release.py <release_dir> --verify` re-clones the repositories and regenerates the reversed-fix
diffs; on our copy all 1,259 rebuild byte-identical. New-code items are pointers read from git at review time.

Running reviewers needs an OpenAI-compatible endpoint. Ours: vLLM serving Qwen3.6-35B-A3B NVFP4 on an NVIDIA
DGX Spark.

## Roadmap (in progress, each ships when done)

Go/Rust wave (built, frozen, running), C/C++ wave (building), PoC verification v2 (coverage-gated
confirmation), a GLM-5.3-Flash reference arm.

## License

Code: Apache-2.0. Dataset metadata: CC-BY-4.0 (derived from the GitHub Advisory Database and NVD).
