# Non-specialist hand check of the semantic judge (test set)

Labeller: the author (Stephen Damrel), who is not a specialist security reviewer. Blind to the reviewer and to the
judge's verdict. Rows were sampled from the stored test judgments of three reviewers (`scripts/audit_sheet.py`, seed 1729).
This is not an expert validation of the judge. After the first 4 answers the labeller was told those agreed with the
judge; the remaining 36 were answered without seeing any verdict.

Judge rows: 30 ({'claude': 4, 'harness_inv': 14, 'codex': 12}). Firm labels: 28; unsure: 2.

| human \ judge | match | no match |
|---|---|---|
| same bug | 14 | 7 |
| different bug | 1 | 6 |

Agreement 20/28; Cohen's kappa 0.41. In 7 of 8 disagreements the
human credited a finding the judge did not, so this check gives no sign that the judge over-credits; it cannot
establish the judge's accuracy.

False-alarm rows (findings on patched code, not the advisory's bug): 10; labelled a real other bug: 9, not a bug: 1.
