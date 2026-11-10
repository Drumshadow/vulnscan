"""Unified-diff helpers shared by the bench builders, the prompt builder and the scorer."""
from __future__ import annotations

import collections
import re

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def head_truth(diff: str) -> dict[str, list[int]]:
    """Head-side (new-side) lines that are added in this diff; pure-deletion hunks anchor one line."""
    truth: dict[str, set[int]] = collections.defaultdict(set)
    cur = None
    new_ln = 0
    hunk_added = False
    hunk_anchor = None

    def close():
        if cur and not hunk_added and hunk_anchor is not None:
            truth[cur].add(max(1, hunk_anchor))

    for line in diff.splitlines():
        if line.startswith("+++ "):
            close(); hunk_anchor = None
            cur = line[6:] if line.startswith("+++ b/") else None
            continue
        m = HUNK_RE.match(line)
        if m:
            close()
            new_ln = int(m.group(3)); hunk_added = False; hunk_anchor = None
            continue
        if cur is None or line.startswith(("--- ", "diff ", "index ")):
            continue
        if line.startswith("+"):
            truth[cur].add(new_ln); hunk_added = True; new_ln += 1
        elif line.startswith("-"):
            if hunk_anchor is None:
                hunk_anchor = new_ln - 1 if new_ln > 1 else 1
        elif line.startswith("\\"):
            pass
        else:
            new_ln += 1
    close()
    return {k: sorted(v) for k, v in truth.items()}


def hunk_ranges(diff: str) -> dict[str, list[tuple[int, int]]]:
    """New-side line range of every hunk, per file."""
    out: dict[str, list[tuple[int, int]]] = {}
    cur = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            cur = line[6:] if line.startswith("+++ b/") else None
            continue
        m = HUNK_RE.match(line)
        if m and cur:
            s = int(m.group(3)); n = int(m.group(4) or 1)
            out.setdefault(cur, []).append((s, s + max(n, 1) - 1))
    return out


def merge_windows(ranges: list[tuple[int, int]], pad: int, n_lines: int) -> list[tuple[int, int]]:
    """Pad each range by +-pad, clip to [1, n_lines], merge overlaps."""
    spans = sorted((max(1, s - pad), min(n_lines, e + pad)) for s, e in ranges)
    out: list[tuple[int, int]] = []
    for s, e in spans:
        if out and s <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out
