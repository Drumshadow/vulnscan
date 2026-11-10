# Evidence

Numbers-only outputs behind the claims in `README.md`, `DATASET_CARD.md` and `writeup/draft.md`. Run ids refer to
`results/vulnscan.sqlite`. No third-party source code is included here.

| Claim | File | Produced by |
|---|---|---|
| Headline tables, fix-after-cutoff subset, like-for-like framing recall | `headline-wave1.md` | `scripts/headline.py` |
| The 97 fix-after-cutoff pairs | `test_nc_fix_after_cutoff_pairs.json` | `scripts/headline.py --out-pairs` |
| Commit overlap, fix dates, prompt visibility, subsets, sensitivity | `release-checks-wave1.md` | `scripts/release_checks.py` |
| Lever ablation on tune; the freeze candidate on check | `tune-ablation.md` | `scripts/combine_harness.py` |
| Nemotron ensemble | `ensemble-tune.md` | `scripts/evidence_extra.py ensemble` |
| Reviewers' shared misses on dev | `miss-taxonomy-dev.md` | `scripts/evidence_extra.py misses` |
| Abliterated vs stock 35B, tune | `abliterated-vs-stock.md` | `scripts/summarize.py` |
| PoC verification v1 outcomes | `poc-verification-v1.md` | `scripts/verify_run.py --report` |
| 1.5B classifier validation curve | `triage-1.5b-val.jsonl` | `scripts/train_triage.py` |
| 7B generative SFT validation curve (step 0 = base model) | `sft-7b-val.jsonl` | `scripts/train_sft.py` |
| Sandbox safety tests | `sandbox-safety-tests.txt` | `sandbox/test_sandbox.sh` |
| PoC outcome by candidate type (2/31, 8/41) | `poc-by-candidate-type.md` | `scripts/evidence_extra.py poc` |
| PoC known-answer smoke test (two runs, disagreeing on the real bug) | `poc-smoke-known-answers.md` | `scripts/poc_smoke.py` |
| Exact evaluated ids, terminal errors | `evaluated-ids-*.json`, `evaluated-manifests.md` | `scripts/manifests.py` |
| Probe on rendered prompts | `probe-rendered.md` | `scripts/shortcut_probe.py --rendered=90000` |
| Non-specialist hand check of the judge | `judge-hand-check.md` | `audit_semantic_test.csv` labels (not published: quotes third-party code) |

The semantic judge has only a non-specialist hand check (`judge-hand-check.md`), not an expert validation.
