# Headline tables: test_nc

97 of 163 pairs have a fix committed on/after 2026-07-01. Ordinary commits in the sample: 80.

## Fix committed after 2026-07-01 (headline)

| reviewer | pairs | pair acc, semantic (95% CI) | pair acc, line window (95% CI) | recall, semantic | recall, line window | patched still flagged, semantic | ordinary commits flagged |
|---|---|---|---|---|---|---|---|
| harness_inv | 97 | 13% (7%-21%) | 11% (5%-18%) | 15% | 14% | 6% | 24% |
| qwen35b | 97 | 10% (5%-17%) | 8% (3%-14%) | 10% | 8% | 4% | 15% |
| claude | 97 | 24% (16%-33%) | 19% (11%-27%) | 24% | 20% | 4% | 9% |
| codex | 97 | 33% (24%-43%) | 20% (12%-28%) | 33% | 24% | 4% | 18% |
| deephat | 97 | 9% (4%-15%) | 2% (0%-5%) | 11% | 2% | 8% | 92% |
| semgrep | 97 | 5% (1%-10%) | 2% (0%-5%) | 8% | 7% | 5% | 54% |

## All pairs

| reviewer | pairs | pair acc, semantic (95% CI) | pair acc, line window (95% CI) | recall, semantic | recall, line window | patched still flagged, semantic | ordinary commits flagged |
|---|---|---|---|---|---|---|---|
| harness_inv | 163 | 20% (14%-26%) | 15% (10%-20%) | 25% | 20% | 9% | 24% |
| qwen35b | 163 | 17% (12%-23%) | 11% (7%-16%) | 19% | 15% | 6% | 15% |
| claude | 163 | 32% (25%-39%) | 22% (16%-29%) | 35% | 26% | 6% | 9% |
| codex | 163 | 40% (32%-48%) | 21% (15%-28%) | 43% | 28% | 7% | 18% |
| deephat | 163 | 12% (7%-18%) | 2% (1%-5%) | 18% | 8% | 13% | 92% |
| semgrep | 163 | 7% (4%-12%) | 4% (1%-7%) | 10% | 7% | 4% | 54% |

## Same advisories, two framings (line-window recall)

| reviewer | reversed-fix | new-code | ratio |
|---|---|---|---|
| harness_inv | not run | | |
| qwen35b | 46% (n=97) | 8% (n=97) | 5.6x |
| claude | 73% (n=97) | 20% (n=97) | 3.7x |
| codex | 74% (n=97) | 24% (n=97) | 3.1x |
| deephat | 31% (n=97) | 2% (n=97) | 15.0x |
| semgrep | 5% (n=97) | 7% (n=97) | 0.7x |
