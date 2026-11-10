"""The single-shot review prompt shared by every LLM arm (local and frontier), so arms differ only by model."""
from __future__ import annotations

import json
import re

from .bench import file_at
from .diffutil import hunk_ranges

SYSTEM = """You are an expert application security reviewer. You review one pull request at a time.

Report only security vulnerabilities that this change introduces or makes exploitable: an attacker-reachable \
input must be able to reach a dangerous operation without an effective defense. Do not report style issues, \
missing tests, generic hardening advice, or vulnerabilities that existed unchanged before this PR. \
If the change is not security-relevant, return no findings. False positives are costly.

For each finding give:
- file: the path exactly as it appears in the diff
- line: the line number in the NEW version of the file (use the numbered file contents)
- cwe: the single best CWE id, e.g. "CWE-22"
- title: one short line
- explanation: how an attacker reaches it and what they gain, and why existing defenses do not stop it

Respond with JSON only, no prose and no code fences:
{"findings": [{"file": "...", "line": 123, "cwe": "CWE-...", "title": "...", "explanation": "..."}]}"""


ADVISORY_ID_RE = re.compile(r"CVE-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3}", re.I)
COMMENT_RE = re.compile(r"^(\s*)(#|//|/\*|\*|\"\"\"|\'\'\')")


def redact(line: str) -> str:
    """Advisory ids are an answer key: a comment line citing one is blanked to its marker; an id inside
    code (e.g. an error string) is replaced by a placeholder. Applied to every item kind alike."""
    if not ADVISORY_ID_RE.search(line):
        return line
    m = COMMENT_RE.match(line)
    if m:
        return f"{m.group(1)}{m.group(2)} [comment redacted]"
    return ADVISORY_ID_RE.sub("<advisory-id>", line)


def _numbered(text: str, lo: int = 1, hi: int | None = None, redact_ids: bool = False) -> str:
    lines = text.splitlines()
    hi = min(hi or len(lines), len(lines))
    fx = redact if redact_ids else (lambda x: x)
    return "\n".join(f"{i:5d}  {fx(lines[i - 1])}" for i in range(max(lo, 1), hi + 1))


def build_newcode(item: dict, budget_chars: int) -> str:
    """New-code framing: the PR adds these files (whole, or excerpts with true line numbers). No diff."""
    parts = [f"Repository: {item['repo']}\n\nThis pull request adds the following new code. "
             "Line numbers are the real line numbers in each file.\n"]
    used = len(parts[0])
    for f, wins in item["views"].items():
        content = file_at(item["repo"], item["head"], f) or ""
        whole = len(wins) == 1 and wins[0][0] == 1 and wins[0][1] >= len(content.splitlines())
        block = f"\n### {f} (new file{'' if whole else ', excerpts'})\n" + "".join(
            f"```\n{_numbered(content, s, e, redact_ids=True)}\n```\n" for s, e in wins)
        if used + len(block) > budget_chars:
            parts.append(f"\n### {f}\n(omitted: context budget)\n"); continue
        parts.append(block); used += len(block)
    return "".join(parts)


def build_user(item: dict, budget_chars: int) -> str:
    if item.get("framing") == "newcode":
        return build_newcode(item, budget_chars)
    return _build_regression(item, budget_chars)


def _build_regression(item: dict, budget_chars: int) -> str:
    """Diff first (always whole), then head file contents with line numbers until the budget is spent.
    Files that do not fit whole get +-60 line windows around each hunk."""
    parts = [f"Repository: {item['repo']}\n\n## Pull request diff\n```diff\n{item['diff']}\n```\n"]
    used = len(parts[0])
    ranges = hunk_ranges(item["diff"])
    parts.append("## Changed files after this PR (line-numbered)\n")
    for f in item["files"]:
        content = file_at(item["repo"], item["head"], f)
        if content is None:
            parts.append(f"\n### {f}\n(deleted in this PR)\n"); continue
        whole = f"\n### {f}\n```\n{_numbered(content)}\n```\n"
        if used + len(whole) <= budget_chars:
            parts.append(whole); used += len(whole); continue
        chunks = [f"\n### {f} (excerpts around the changes)\n"]
        for s, e in ranges.get(f, []):
            chunks.append(f"```\n{_numbered(content, s - 60, e + 60)}\n```\n")
        ex = "".join(chunks)
        if used + len(ex) <= budget_chars:
            parts.append(ex); used += len(ex)
        else:
            parts.append(f"\n### {f}\n(omitted: context budget)\n")
    return "".join(parts)


def parse_findings(text: str) -> list[dict]:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in response")
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError:
        # models often emit regexes/paths with bare backslashes; double the ones JSON does not allow
        fixed = re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", text[start:])
        obj, _ = json.JSONDecoder().raw_decode(fixed)
    fs = obj.get("findings", []) if isinstance(obj, dict) else []
    out = []
    for f in fs:
        if not isinstance(f, dict):
            continue
        out.append({k: f.get(k) for k in ("file", "line", "cwe", "title", "explanation")})
    return out
