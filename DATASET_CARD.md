---
license: cc-by-4.0
task_categories:
- text-classification
language:
- en
tags:
- security
- vulnerability-detection
- code-review
- benchmark
pretty_name: vulnscan PR security review benchmark
---

# vulnscan: PR security review benchmark (v1: Python + JS/TS)

A benchmark for **AI security review of code changes**. Every advisory was published on or after **2026-07-01**.
An advisory date does not bound when the fix became public: in the test split, 66 of 163 fixes were committed before
that date. Use `evidence/test_nc_fix_after_cutoff_pairs.json` for the 97 pairs whose fix came after it. No claim is
made about any model's training data. The split unit is the repository, and a build-time leak check aborts on any
repository, commit or advisory overlap between splits (0 shared resolved SHAs across all splits).

**This release contains metadata only:** advisory ids, repository names, commit SHAs, file lists, view windows,
truth lines and boolean leak flags, enforced by a field-level allow-list at staging. No third-party source code is
redistributed. `rebuild_from_release.py` (in the [repo](https://github.com/Drumshadow/vulnscan)) regenerates the reversed-fix diffs from the SHAs
(all 1,259 byte-identical on our copy). New-code items are pointers read from git.

## Two framings

* **`newcode/` (headline).** Each vulnerability appears as a pair: the vulnerable version and the patched version
  of the same files, both presented as added code. Ordinary commits from the same repositories are included as
  negatives. An 8-feature surface-statistics probe scores AUC 0.51 (test) / 0.54 (dev) on the rendered prompts, so the deletion cue
  is gone. That does not rule out
  every other surface signal. Metric: **pair accuracy**, meaning find
  the vulnerability in the vulnerable version and don't flag the fix site in the patched one.
* **`regression/` (secondary, shortcut warning).** The reverse of each fix commit, presented as a PR. These diffs
  are mostly deletions, and the same probe scores **AUC 0.95** on them (vs ordinary commits and fixes; 0.94 vs ordinary
  commits alone). On the same advisories, frontier models' line-window recall is
  3–4× higher here than on the new-code framing (the framings also differ in context and instructions). It is
  included to make that measurable.

| Split | Pairs (new-code) | Ordinary commits | Repos |
|---|---|---|---|
| dev | 164 | 298 | 142 |
| test | 163 | 305 | 134 |

## Fields (per item)

`id, kind (nc_vuln | nc_fixed | nc_benign | vuln_intro | fix | benign), framing, repo, ecosystem, ghsa_id, cve_id,
cwes, published_at, base, head, files, views, truth, fix_site, pair, leak, changed_lines, shown_lines`.

* `truth`: lines (in `head`) the fix changed.
* `fix_site`: lines (in the patched version) the fix added.
* `leak`: residual answer-leak flags (deleted code naming the bug). Report results with and without flagged items.

## Scoring

* **Line window:** right file, within ±5 lines of a truth line, right CWE family (`vs/cwe.py`).
* **Semantic judge:** a fixed rubric decides whether a finding is the advisory's vulnerability (same root cause and
  component, any line). A non-specialist hand check (the author, blind to reviewer and verdict) agreed with the judge on 20 of 28 decided rows (Cohen's κ 0.41); in 7 of the 8 disagreements the judge was the stricter one (`evidence/judge-hand-check.md`). That is not an expert validation.

Reference results used one sample: all 163 test pairs plus 80 ordinary commits (406 items). Semantic pair accuracy on
the 97 fix-after-cutoff pairs: Codex gpt-6-astra 33% (24–43), Claude Opus 5.5 24% (16–33), local Qwen3.6-35B-A3B
harness 13% (7–21), semgrep 5% (1–10). On all 163 pairs: 40%, 32%, 20%, 7%.

## Known limitations

* Ordinary commits are not audited. A few may contain real vulnerabilities and count as false alarms.
* GHSA CWE labels are coarse, so scoring uses CWE families.
* The new-code framing presents whole files (or ±150-line windows) as added code. It is a controlled proxy for
  PR review, not a replay of real PRs.

## Sources and license

Advisory metadata from the [GitHub Advisory Database](https://github.com/github/advisory-database) (CC-BY-4.0)
and [NVD](https://nvd.nist.gov/). Repositories are referenced by commit SHA under their own licenses; no code is
included. This metadata: CC-BY-4.0.
