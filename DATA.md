# Data

PR-diff security review benchmark built from reviewed GitHub Security Advisories (GHSA). Wave 1 covers
Python (pip) and JavaScript/TypeScript (npm); Go and Rust advisories are fetched but not split yet; C/C++
comes later from PrimeVul/MegaVul.

## Sources and licenses

| Source | What we use | License |
|---|---|---|
| GHSA via `api.github.com/advisories` (`type=reviewed`) | advisory metadata, CWE, fix-commit links | CC-BY-4.0 (github/advisory-database) |
| The affected GitHub repositories | diffs and file contents at the fix commit and its parent | each repo's own license; **code is never redistributed**, only advisory ids, repo names and commit shas |

Fetch: `scripts/fetch_ghsa.py` (2026-11-02): pip 6,809, npm 8,073, go 5,068, rust 1,625 advisories.

## Cutoff and splits

* **Cutoff 2026-07-01.** Test and dev hold only advisories published on/after it. An advisory date does not bound
  when the fix became public: 66 of 163 test fixes were committed before the cutoff (`evidence/release-checks-wave1.md`).
  Headline results therefore use the 97 pairs with a fix committed on/after the cutoff
  (`evidence/test_nc_fix_after_cutoff_pairs.json`). No claim is made about any model's training data.
* **The split unit is the repository.** A repo picked for test or dev contributes nothing to any other split,
  including its older advisories. At most 2 advisories are sampled per repo.
* Train = pre-cutoff advisories from the remaining repos. Post-cutoff advisories from train repos are dropped.
* Test and dev items use single-commit fixes with at least one CWE.
* `scripts/build_dataset.py` aborts before writing if any repo, commit or GHSA id appears in two splits, or
  if a split violates the cutoff.

| Split | Advisories | Repos |
|---|---|---|
| test | 200 | 134 |
| dev | 200 | 142 |
| train | 5,021 | 2,108 |

## Bench items (`scripts/materialize.py`)

| Kind | Diff shown | Checkout | Expected |
|---|---|---|---|
| `vuln_intro` | fix → fix^ (the reverse of the fix: a PR that introduces the bug) | fix^ | a finding at the truth lines with a matching CWE family |
| `fix` | fix^ → fix (the fix itself) | fix | no finding |
| `benign` | parent → commit, for ordinary commits on/after the cutoff in the same repos (no advisory link, no security words in the subject) | commit | no finding |

* Diffs keep source files only (`.py .js .mjs .cjs .ts .tsx .jsx .mts .cts`). Tests, fixtures, examples,
  docs, changelogs and lockfiles are stripped so the PR does not include the fix's regression test.
* Skipped: more than 400 changed lines, more than 10 files, no source change, or a merge commit.
* **Truth** = head-side lines the fix removed. A fix that only adds code is anchored at the head line where
  it inserts.

Final counts (after sanitizing):

| Split | pip intro / fix / benign | npm intro / fix / benign |
|---|---|---|
| test | 77 / 77 / 146 | 86 / 86 / 159 |
| dev | 85 / 85 / 163 | 80 / 80 / 135 |

Of 200 test advisories, 37 were skipped (11 no source change, 10 too large, 8 too many files, 8 merge commits).
13 test repos have fewer than 2 benign commits after the cutoff.

## Answer leakage and sanitizing (`scripts/sanitize_bench.py`)

Reversing a fix also deletes the fix's comments, which often name the bug ("prevents CVE-…"). Before
sanitizing, 28% of test `vuln_intro` diffs had such deleted text (24% in comments, 13% in code, 12% citing
an advisory id).

* For **every** item kind, deleted comment-only lines and deleted lines containing a CVE/GHSA id are removed
  from the shown diff, and hunk headers are rewritten. Applying it to all kinds keeps "no deleted comments"
  from becoming a tell. Deleted lines are base-side only, so the head checkout and the truth lines are
  unchanged.
* Remaining deleted code that names the bug (e.g. a removed `sanitize()` call) is kept, because a real
  reviewer would see it too. Each `vuln_intro` item carries a `leak` flag: 19 test items are flagged. Every
  report gives scores **on all items and on unflagged items**.
* The original diffs are in `<split>.orig_diffs.jsonl`. Eval arms never read that file.

## Known label noise

* `benign` commits are not audited and may contain real vulnerabilities, so a flag on one is counted as a
  false positive.
* `fix` diffs can leave related issues unfixed (a partial fix). Flags on fixes are reported separately as the
  fix-flag and fix-site rates. Item-level `precision` does count flagged fix items in its denominator.
* GHSA CWE labels are coarse or loose (often CWE-20). Scoring uses CWE families (`vs/cwe.py`). Strict mode
  never treats CWE-20 as a wildcard; loose mode does.

## Freezing

`BENCH.sha256` pins `data/bench/{test,dev}.jsonl` and `data/splits/*.jsonl`. **The test set is run once per
frozen arm, with `--final`.** Iterate on dev only.

## The deletion shortcut and the paired new-code framing (headline)

`scripts/shortcut_probe.py` trains a logistic regression on surface statistics of what the reviewer is
shown, with no semantics: share of removed lines, line counts, and guard-statement and security-word
rates in added and removed lines. It uses repo-grouped 5-fold CV.

| Framing (dev) | intro vs benign+fix | intro vs benign | intro vs fix |
|---|---|---|---|
| regression (reversed fix) | AUC 0.953 | 0.939 | 0.976 |
| **new code (paired)** | **AUC 0.538** | 0.548 | 0.539 |

Reversed fixes are mostly deletions: removed lines are 77% of changed lines for vuln_intro items, against
28% for benign and 20% for fix items. A reviewer can score well on the regression framing by noticing that a
PR deletes a check. So the **headline framing is paired new code** (`scripts/build_newcode.py`,
`data/bench/{dev,test}_nc.jsonl`):

* `nc_vuln`: the changed files at fix^, presented as code the PR adds. Expected: a finding at the truth lines.
* `nc_fixed`: the same files at the fix commit. Expected: nothing at the fix site (the lines the fix added).
* `nc_benign`: the files of a benign commit. Expected: nothing.
* Files of 600 lines or fewer are shown whole. Larger files are shown as ±150-line windows around that
  version's own hunks, with true line numbers. Both versions of a pair get identical treatment.
* **Pair accuracy** = strict hit on `nc_vuln` AND no finding within ±5 lines of the fix site on `nc_fixed`.
  It is the headline metric, together with recall and the benign flag rate.

Counts: dev_nc 164 pairs + 298 benign (one advisory had no viewable file); test_nc 163 pairs + 305 benign.

**Advisory-id redaction (prompt v2).** In new-code views and harness call-site context, a comment line that
cites a CVE/GHSA id is replaced by its comment marker plus `[comment redacted]`, and an id inside code is
replaced by `<advisory-id>`. This applies to every item kind alike. Before redaction, ids appeared in 11–13%
of `nc_fixed` views against 4–6% of `nc_vuln` views. Generic security comments ("prevent path traversal")
are kept because real code has them. They are mildly skewed: 37–40% of fixed views, 30% of vulnerable views,
20% of benign views. The regression framing keeps prompt v1, so its arms stay comparable.

## Evaluated sample and denominators

Exact evaluated ids: `evidence/evaluated-ids-test_nc.json`, `evidence/evaluated-ids-test.json`. Terminal errors per
reviewer: `evidence/evaluated-manifests.md`.

All reviewers ran on one deterministic sample (`vs/bench.py` `sample_ids(..., "frontier")`, seed 1729).

* New-code test: all 163 `nc_vuln` + all 163 `nc_fixed` + 80 of 305 `nc_benign` = 406 items.
* Reversed-fix test: all 163 `vuln_intro` + 80 `fix` + 80 `benign` = 323 items. Pair accuracy is not reported on this
  framing, because only 80 of the 163 positives have their fix item in the sample.
* semgrep also ran on the full splits; the published tables use the same sample as everyone else.
* `precision` is item-level: positive items with a strict hit, divided by all flagged items (positive, fix, benign).
  It ignores extra wrong findings on a correct item.

Measured on the test sample (`evidence/release-checks-wave1.md`): 0 resolved SHAs shared across any two splits or waves;
visibility of the vulnerable code in the prompt; sensitivity to the line window and CWE rule; results excluding
leak-flagged items.

## Probe on rendered prompts, redaction scope, judge provenance

* The shortcut probe was rerun on the exact text placed in each prompt (budgeted, redacted), at 90k characters:
  new-code AUC 0.543 (dev) / 0.508 (test), reversed-fix 0.953 (dev) (`evidence/probe-rendered.md`).
* Advisory-id redaction applies to new-code views and harness call-site context. In the reversed-fix framing, deleted
  lines citing an id are removed, but unchanged head-file context is rendered without redaction.
* New-code leak flags are inherited from the reversed-fix diffs of the same advisory.
* Semantic judgments (`j1`) were produced before strict boolean parsing was added. A strict re-judge of 100 random
  stored matches gave 96 matches, 4 no-match and 0 non-boolean answers. Historical judgments were not regenerated.
  Cached judgments are keyed by run, item, finding index and judge name; the rubric text is pinned by hash.

## Run policy

* **Infrastructure errors are retried** for every arm: subscription rate limits, HTTP 5xx, timeouts. The
  runner resumes failed items with the same command and run id. **Model failures count as misses:** running
  out of tokens before answering, or unparseable output even after the bare-backslash repair. They are never
  dropped. Each summary reports its error count.
* A configuration bug invalidates the whole run, never only the affected items. DeepHat's first runs used a
  36k-character context budget that overflowed its 16k-token window on about 80% of items. They were
  discarded and rerun at 20k characters (`deephat:*:18befcd58a`).
* `--limit` smoke runs (`:n<N>` run ids) are excluded from summaries.
* **CodeRabbit is not run.** Its 86.7% figure is cited only as CodeRabbit's own internal claim.
* **Abliterated 35B confound.** `qwen3.6-35b-a3b-uncensored-nvfp4` has no documented provenance, and its
  NVFP4 recipe keeps attention in FP8, unlike the stock model. A score gap between the two mixes
  abliteration with quantization.
