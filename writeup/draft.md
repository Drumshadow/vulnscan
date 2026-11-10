# How good is AI security review of pull requests, really?

*Stephen Damrel · draft · semantic-judge numbers have only a non-specialist hand check*

## The claim that started this

A code-review vendor reports that its security agent detects 86.7% of vulnerabilities. That figure comes from
the vendor's own internal "comparative development slice". It counts detections only, gives no false-positive
rate, and has not been independently reproduced. I wanted a number I could defend. So I built a public
benchmark isolated by repository and limited to recently fixed bugs, scored precision as well as recall, and ran frontier models, static
analysis and a fully local reviewer against it on equal terms.

## The benchmark

* **Source.** Reviewed GitHub Security Advisories for Python (pip) and JavaScript/TypeScript (npm) that link a
  fix commit.
* **Limiting contamination.** Every evaluation advisory was published on or after 2026-07-01. An advisory date
  does not bound when the fix became public: 66 of the 163 test fixes were committed *before* that date. So the
  headline below uses only the 97 pairs whose fix was committed on or after 2026-07-01. I can't verify any model's
  training data, so this reduces the risk of contamination and does not prove its absence.
* **Isolation.** The split unit is the repository: no test repo contributes anything to training or dev, and
  the build aborts on any overlap.
* **Leakage.** Deleted comment lines and advisory ids are scrubbed from what the reviewer sees, on every item kind
  alike. Ordinary security comments in the code stay, as they do in real code. They are mildly more common in
  patched code (`DATA.md`).
* **Reproducible without redistributing code.** The release is metadata only: advisory ids, repos, commit
  shas, line ranges. A script rebuilds the reversed-fix diffs from the shas; on our copy all 1,259 rebuilt
  byte-identical. New-code items are pointers (sha + line window) read from git at review time.

### The trap: reversed fixes

The common way to build "vulnerability-introducing PRs" is to reverse the fix commit. I did that first, and
frontier models scored 70–80% recall. Then I checked a shortcut. A logistic regression on surface
statistics alone (share of deleted lines, deleted `if`/`raise` lines, words like "check" and "sanitize")
separates those PRs from ordinary commits and fixes at **AUC 0.95** (0.94 against ordinary commits alone), without reading the code for meaning. Reversed
fixes are mostly deletions: 77% of their changed lines, against 28% for ordinary commits. A reviewer can do
well just by noticing that a PR removes a check.

### The fix: paired new code

The headline framing shows each advisory twice, as a PR that *adds* code:

* once with the vulnerable version, where the right answer is a finding at the vulnerable lines;
* once with the patched version, where the right answer is no finding at the fix site.

Both versions are pure additions with nearly identical text, and the same surface-statistics probe scores
**AUC 0.54** there, close to chance. The headline metric is **pair accuracy**: catch the vulnerable version
without flagging the patched one. Ordinary commits from the same repos measure false alarms.

## Results (frozen test set, run once per reviewer)

**How the headline was chosen.** Every reviewer ran exactly once on the frozen test set. The 97-pair headline came
*after* those runs. A date check showed that 66 of the 163 fixes were committed before the cutoff. I computed scores on
that subset and on all 163, saw them, and only then chose to lead with the clean subset. That reason is about
contamination, not about the scores, but the choice was not made in advance. Both populations are reported throughout.

**What was scored.** The test split has 163 vulnerable/patched pairs (Python + JS/TS) and 305 ordinary commits. Every
reviewer ran on the same sample: all 163 pairs plus 80 ordinary commits (406 items). **The headline is the 97 pairs
whose fix was committed on or after the cutoff.** All 163 are shown beside it.

Two scores:
* *Line window:* right file, within ±5 lines of what the fix changed, right CWE family.
* *Semantic:* a fixed-rubric judge (our local 35B) decides whether a finding is the advisory's vulnerability: same
  root cause and component, any line. The same judge scores every reviewer. A non-specialist hand check (the author, blind to reviewer and verdict) agreed with the judge on 20 of 28 decided rows (Cohen's κ 0.41); in 7 of the 8 disagreements the judge was the stricter one (`evidence/judge-hand-check.md`). That is not an expert validation.

*Pair accuracy* means the reviewer found the bug in the vulnerable version and did not flag the same spot in the
patched one.

| Reviewer | Pair acc., semantic (97 pairs, 95% CI) | Pair acc., line window (97) | Semantic, all 163 | Line window, all 163 | Ordinary commits flagged | Median s/review |
|---|---|---|---|---|---|---|
| Codex gpt-6-astra | **33%** (24–43) | 20% | 40% | 21% | 18% | 22 |
| Claude Opus 5.5 | **24%** (16–33) | 19% | 32% | 22% | 9% | 10 |
| Local 35B + harness (ours, frozen) | **13%** (7–21) | 11% | 20% | 15% | 24% | 282 |
| Local 35B, single prompt | 10% (5–17) | 8% | 17% | 11% | 15% | 260 |
| DeepHat-7B (security-tuned) | 9% (4–15) | 2% | 12% | 2% | 92% | 11 |
| semgrep (OSS rules) | 5% (1–10) | 2% | 7% | 4% | 54% | 17 |

The ordinary-commit column uses the same 80 commits in both views. Each interval is repository-clustered.

**Same 97 advisories under both framings (line-window recall):** Codex 74% reversed-fix vs 24% new-code (3.1×), Claude
73% vs 20% (3.7×), our 35B single prompt 46% vs 8% (5.6×). The framings also differ in the context and instructions
shown, so the whole gap can't be attributed to the deletion shortcut.

What this says:
* **Frontier models lead our local reviewer.** Under the semantic judge, Codex is about 2.5× our harness and Claude
  about 1.8×. With 97 pairs the intervals are wide: Claude's overlaps ours. The order frontier > our harness > our
  single prompt held under every line-window and CWE rule I tried (`evidence/release-checks-wave1.md`).
* **Claude vs Codex is not settled.** Codex leads under the judge, they tie on the line window, and the order flips
  with the window size.
* **The two scores diverge.** The judge credits more findings than the line window does for every reviewer, most of all
  Codex. Whether those extra credits are real detections is only as good as the judge (see above).
* **Scores drop on clean fixes.** Every reviewer scores lower on the 97 pairs whose fix came after the cutoff than on
  all 163. That fits some contamination in the other 66, but those items could also just be easier.
* **Our dev estimate was optimistic.** Harness v1 scored 27–28% semantic pair accuracy on dev, 20% on all test pairs
  and 13% on the clean ones. That is why it was frozen before the test run.
* **A local reviewer still beats static analysis on this task:** 13% vs semgrep's 5% on the headline, and the gap
  stays at 3× on all pairs. The intervals overlap on 97 pairs. The harness adds about 3 points over a single prompt.
* **Even the best reviewer finds well under half of these vulnerabilities**, against the 87% figure that started
  this. The two numbers aren't comparable: that figure comes from a different, unpublished test.

## Our local reviewer, and what did and did not help

The reviewer is fully local: Qwen3.6-35B-A3B (about 3B parameters active per token) on one DGX Spark. The
harness gives it:
* the changed code, plus call sites and the definitions of the functions it calls (from `git grep`);
* semgrep hints.

It then asks for findings with a CWE and a line. Every lever below was measured on the same 96 vulnerable/patched
dev pairs ("tune"), paired against harness v1, with a repository-clustered bootstrap. The freeze rule was fixed in
advance: best pair accuracy with at most 30% of ordinary commits flagged, then confirmation on a separate repo-disjoint
"check" set. Only the rule's single pick went to check.

| Lever | Pair acc. | Δ vs v1 (95% CI) | Recall | Benign flagged |
|---|---|---|---|---|
| v1 harness | 17% | – | 26% | 24% |
| Fixed cross-file context (callers + callees) | 18% | +1.0 (−6.4…+9.2) | 21% | 28% |
| Location/CWE prompt | 16% | −1.0 | 18% | 24% |
| DoS + auth "lenses" | 15% | −2.1 | 20% | 44% |
| 3 samples, union | 23% | +6.2 (−2.2…+14.9) | 29% | 42% |
| Attack-surface map, then check | 17% | 0.0 | 26% | 56% |
| Security-invariants pass (reads SECURITY.md/README) | 20% | +3.1 (−5.3…+11.3) | 26% | 40% |
| ReDoS/recursion/CodeQL hints + recall prompt | 16% | −1.0 | 23% | 34% |
| All of the above, unioned | 20% | +3.1 | 33% | 62% |
| Second local model (Nemotron 30B) unioned | 16% | −1.0 | 29% | 66% |

**Every lever that finds more bugs also flags proportionally more ordinary code. Pair accuracy, which rewards
telling a vulnerable function from its patched twin, does not clearly move.**

One hypothesis for this comes from the misses. Of 164 dev vulnerabilities, 84 were missed by *every* reviewer: ours,
Codex and Claude (`evidence/miss-taxonomy-dev.md`):
* 34 got total silence from all three. The largest family among all 84 is denial of service (23). Reading a sample of
  them, many look like bugs of omission (a missing limit or Origin check), but that is my impression, not a measured
  label;
* in 13, at least two reviewers flagged the advisory's file with the right CWE family at a different line. That is
  consistent with the line window missing real detections, but nobody adjudicated these 13.

If that impression holds, more reading can't help much, because the missing ingredient is information the code
doesn't contain. This is a hypothesis, not a measured result.

**Fine-tuning.**
* A 1.5B classifier trained on 10k vulnerable/patched region pairs: best validation checkpoint 0.56 held-out pairwise
  accuracy, final 0.54 (chance is 0.50; `evidence/triage-1.5b-val.jsonl`).
* A *generative* 7B fine-tune (answer: line + CWE, or nothing): held-out region pair accuracy 4.5% for the base model,
  best validation checkpoint 10.5% (step 100), final 6.5% (`evidence/sft-7b-val.jsonl`). This is a region-level
  validation, not the benchmark protocol, so it isn't comparable to the harness numbers.

**Abliteration.** The abliterated 35B (also a different quantization recipe) did worse than stock: 8% vs 12%
single-prompt pair accuracy, and it flagged 40% of benign commits.

**Proof-of-concept verification.** We built a sandbox on the gateway's Landlock/seccomp confinement (no network,
workspace-only writes, cgroup caps). The model writes a PoC that must call the project's real code, run in attack
and benign-control modes; a finding counts as confirmed only if the attack triggers and the control doesn't. It
confirmed a real known bug in a hand-audited MCP server in one of two runs (the other run could not verify it), and
rejected a false SQL-injection claim in both, after two rounds of protocol fixes made on those same two cases (`evidence/poc-smoke-known-answers.md`). On the tune set it did not discriminate (`evidence/poc-by-candidate-type.md`,
`evidence/poc-verification-v1.md`):
* it confirmed 2 of 31 real bugs, but 8 of 41 wrong candidates and 30% of candidates on patched code;
* about 60% of PoCs never reached a verdict. v1 didn't record stderr, so the causes aren't measured; v2 records them.

Execution-based verification looks like the right direction. Making it reliable for arbitrary projects is its own
project.

No v2 lever survived the repo-disjoint check set: the one tune "winner" (fixed context) scored 12% vs 13%
(line window) and 19% vs 26% (semantic) on check. The frozen reviewer is therefore harness v1, and that is what
ran on test. (v1 contains a context-scoping bug; fixing it did not help, so it stayed, and it is documented.)

## Limits

* Ordinary commits are not audited: a few may hold real bugs and count as false alarms.
* GHSA CWE labels are coarse, so scoring uses CWE families.
* Location scoring uses a ±5-line window around the lines the fix touched. A reviewer pointing at the sink
  far from the fix site is scored as a miss on strict recall but counts under recall@file+CWE.
* 66 of 163 test fixes were committed before the cutoff; the headline excludes them. Even the 97 clean pairs can't
  prove no model saw similar code.
* The semantic judge is our own local model. Its only human check is the non-specialist one above. Judgments were
  produced before strict boolean parsing; a strict re-judge of 100 stored matches flipped 4 and found no non-boolean
  answers, and the historical judgments were not regenerated.
* Prompt budgets drop some files: the vulnerable code was fully visible in 149–150 of 163 pairs for the 35B, Claude
  and Codex, and only 70 of 163 for DeepHat (16k context), so DeepHat's score is partly a context limit.
* "Precision" in our tables is item-level: items with a correct finding divided by all flagged items, including
  flagged patched items. Extra wrong findings on a correct item don't lower it.
* The new-code framing removes the deletion cue. The 8-feature probe scores AUC 0.51 (test) and 0.54 (dev) on the
  prompts actually rendered for the reviewers (`evidence/probe-rendered.md`), but no probe can rule out every surface
  signal. Leak flags on new-code items are inherited from the reversed-fix diffs, not measured on new-code prompts.
* Python and JS/TS only in this release. Go/Rust and C/C++ waves are built; their results will follow.
