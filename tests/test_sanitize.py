import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from sanitize_bench import sanitize  # noqa: E402
from materialize import HUNK_RE, head_truth  # noqa: E402

DIFF = """diff --git a/lib/x.js b/lib/x.js
index 1..2 100644
--- a/lib/x.js
+++ b/lib/x.js
@@ -10,6 +10,3 @@ ctx
 var a = 1;
-// Upper bound (CVE-2026-1). Prevents DoS.
-var MAX = 1e7;
 var b = 2;
 var c = 3;
-  // only a comment here
@@ -40,3 +37,3 @@ fn
 if (x) {
-  check(x); // keep: code with trailing comment
+  use(x);
 }
diff --git a/lib/y.js b/lib/y.js
--- a/lib/y.js
+++ b/lib/y.js
@@ -1,2 +1,1 @@
 a
-# comment only file change
"""


def _counts_ok(diff: str) -> bool:
    lines = diff.splitlines()
    for i, l in enumerate(lines):
        m = HUNK_RE.match(l)
        if not m:
            continue
        old_n, new_n = int(m.group(2)), int(m.group(4))
        body = []
        for b in lines[i + 1:]:
            if HUNK_RE.match(b) or b.startswith("diff --git "):
                break
            body.append(b)
        if sum(1 for b in body if b[:1] in " -") != old_n or sum(1 for b in body if b[:1] in " +") != new_n:
            return False
    return True


def test_strips_comment_lines_only():
    out = sanitize(DIFF)
    assert "CVE-2026-1" not in out and "only a comment" not in out
    assert "-var MAX = 1e7;" in out                    # code line kept
    assert "-  check(x); // keep" in out               # code with trailing comment kept
    assert "lib/y.js" not in out                       # file left with no change dropped
    assert _counts_ok(out)


def test_truth_unchanged_by_sanitize():
    # head-side lines do not depend on removed lines
    assert head_truth(sanitize(DIFF))["lib/x.js"] == [10, 38]
    assert head_truth(DIFF)["lib/x.js"] == [10, 38]


def test_strips_advisory_id_lines_in_docstrings():
    d = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,4 +1,2 @@
 def f():
-    closes the root file read reported in GHSA-rh9c-rqvg-f7pr.
-    safe_join(root, p)
     return 1
"""
    out = sanitize(d)
    assert "GHSA" not in out and "-    safe_join(root, p)" in out
