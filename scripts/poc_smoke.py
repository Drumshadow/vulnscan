"""Known-answer smoke test for PoC verification on a privately audited project.

The project is not named in this repository: its findings are not yet disclosed to the maintainer.
  poc_smoke.py <findings.json from `vulnscan review`> <file the target code lives in> "<title substring>" ["<title substring>" ...]
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.poc import verify  # noqa: E402

findings_path, src_file, *needles = sys.argv[1:]
d = json.load(open(findings_path))
item = {"repo": d["meta"]["repo"], "head": d["meta"]["head"], "files": [src_file]}
for needle in needles:
    f = next(f for f in d["findings"] if needle in (f.get("title") or ""))
    r = verify(item, f)
    print(json.dumps({"finding": f.get("title"), "outcome": r["outcome"], "attempts": r.get("attempts"),
                      "stdout": (r.get("stdout") or "")[-400:], "stderr": (r.get("stderr") or "")[-400:]}, indent=1))
