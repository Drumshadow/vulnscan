# Evaluated populations and terminal errors

## test_nc: 406 items {'nc_fixed': 163, 'nc_vuln': 163, 'nc_benign': 80} (evidence/evaluated-ids-test_nc.json)

| reviewer | stored results | ok | terminal errors (counted as misses / unflagged) |
|---|---|---|---|
| harness_inv | 406 | 394 | 12 |
| qwen35b | 406 | 377 | 29 |
| claude | 406 | 406 | 0 |
| codex | 406 | 406 | 0 |
| deephat | 406 | 387 | 19 |
| semgrep | 406 | 404 | 2 |

## test: 323 items {'vuln_intro': 163, 'fix': 80, 'benign': 80} (evidence/evaluated-ids-test.json)

| reviewer | stored results | ok | terminal errors (counted as misses / unflagged) |
|---|---|---|---|
| harness_inv | not run | | |
| qwen35b | 323 | 317 | 6 |
| claude | 323 | 323 | 0 |
| codex | 323 | 323 | 0 |
| deephat | 323 | 300 | 23 |
| semgrep | 323 | 322 | 1 |

