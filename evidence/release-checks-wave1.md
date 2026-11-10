# Release checks: test_nc, sample frontier, 406 items, {'nc_fixed': 163, 'nc_vuln': 163, 'nc_benign': 80}

## 1. Commit overlap across splits (resolved SHAs)


Splits checked: dev (899), test (907), test_w2 (1147), test_w3 (1367), train (8068). Total shared: 0.

## 2. Fix-commit dates vs the advisory cutoff

163 advisories: fix committed before 2026-07-01: 66 (40%); authored before it: 69 (42%); date unknown: 0.

## 3. Is the vulnerable / patched code actually in the prompt?

- harness_inv (budget 80000): 149/163 pairs with every original anchor line shown
- qwen35b (budget 90000): 150/163 pairs with every original anchor line shown
- claude (budget 90000): 150/163 pairs with every original anchor line shown
- codex (budget 90000): 150/163 pairs with every original anchor line shown
- deephat (budget 20000): 70/163 pairs with every original anchor line shown
- semgrep (budget whole file, findings limited to views): 163/163 pairs with every original anchor line shown

## 4. Scores on subsets (pair accuracy: line window / semantic)

| reviewer | all | no leak flag | fix committed after cutoff | fully visible to that reviewer |
|---|---|---|---|---|
| harness_inv | 15% / 20% (n=163) | 15% / 19% (n=144) | 11% / 13% (n=97) | 14% / 19% (n=149) |
| qwen35b | 11% / 17% (n=163) | 11% / 17% (n=144) | 8% / 10% (n=97) | 12% / 18% (n=150) |
| claude | 22% / 32% (n=163) | 21% / 31% (n=144) | 19% / 24% (n=97) | 23% / 33% (n=150) |
| codex | 21% / 40% (n=163) | 22% / 44% (n=144) | 20% / 33% (n=97) | 21% / 41% (n=150) |
| deephat | 2% / 12% (n=163) | 1% / 10% (n=144) | 2% / 9% (n=97) | 0% / 16% (n=70) |
| semgrep | 4% / 7% (n=163) | 3% / 7% (n=144) | 2% / 5% (n=97) | 4% / 7% (n=163) |

## 5. Sensitivity of line-window pair accuracy

| variant | harness_inv | qwen35b | claude | codex | deephat | semgrep | order |
|---|---|---|---|---|---|---|---|
| window 5, family (reported) | 15% | 11% | 22% | 21% | 2% | 4% | claude > codex > harness_inv > qwen35b > semgrep > deephat |
| window 3 | 15% | 11% | 21% | 20% | 2% | 3% | claude > codex > harness_inv > qwen35b > semgrep > deephat |
| window 10 | 15% | 12% | 23% | 22% | 2% | 4% | claude > codex > harness_inv > qwen35b > semgrep > deephat |
| window 25 | 15% | 12% | 23% | 24% | 2% | 2% | codex > claude > harness_inv > qwen35b > deephat > semgrep |
| exact CWE | 12% | 9% | 21% | 17% | 1% | 3% | claude > codex > harness_inv > qwen35b > semgrep > deephat |
| no CWE requirement | 17% | 13% | 25% | 25% | 9% | 4% | claude > codex > harness_inv > qwen35b > deephat > semgrep |
| fix-site flag needs CWE family | 18% | 13% | 23% | 23% | 3% | 4% | claude > codex > harness_inv > qwen35b > semgrep > deephat |
