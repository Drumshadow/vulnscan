# PoC smoke test on two known answers (privately audited MCP server)

The project is not named, and the finding titles are generalised, because its findings have not yet been disclosed
to the maintainer. Run with `scripts/poc_smoke.py`, after two rounds of protocol fixes made on these same two cases.

The final protocol was run twice. The first run's output was overwritten by the second (same log file); the first
run's result is recorded here from the session transcript, the second from the surviving log.

| case | ground truth (from a manual audit) | run 1 | run 2 |
|---|---|---|---|
| finding A: path traversal in a file-write parameter | real, high severity | confirmed (attempt 3) | unverifiable (3 attempts) |
| finding B: SQL injection claimed on interpolated constants | false positive | not_reproduced | not_reproduced |

So the verifier is not reliable on finding A: one confirmation in two runs.
