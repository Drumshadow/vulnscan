"""Coarse CWE families for scoring. A finding's CWE matches the truth if they share a family.

Families are deliberately coarse: reviewers (human or model) routinely label the same bug CWE-22 vs
CWE-73, or CWE-400 vs CWE-770. Unmapped CWEs match only themselves. CWE-20 (improper input
validation) is a catch-all that GHSA uses loosely, so a CWE-20 truth matches any family in --loose
mode only (see score.py), never in strict mode.
"""
from __future__ import annotations

import re

FAMILIES: dict[str, set[int]] = {
    "path": {22, 23, 24, 25, 35, 36, 41, 59, 61, 73, 434, 641},
    "injection": {74, 75, 77, 78, 88, 89, 90, 91, 94, 95, 96, 97, 98, 113, 117, 134, 643, 652, 917, 943, 1336, 1426, 1427},
    "xss": {79, 80, 81, 83, 84, 85, 86, 87, 116, 838},
    "ssrf": {918, 441},
    "proto_pollution": {1321, 915, 471},
    "authz": {284, 285, 639, 862, 863, 266, 269, 732, 276, 280, 552, 425, 1220},
    "authn": {287, 288, 290, 294, 295, 297, 304, 305, 306, 307, 384, 521, 522, 613, 620, 640, 798, 1390, 1391},
    "csrf": {352, 346, 1385},
    "dos": {400, 401, 404, 405, 407, 409, 674, 770, 772, 789, 834, 835, 1050, 1284, 1333, 606},
    "info": {200, 201, 203, 208, 209, 212, 215, 312, 315, 319, 359, 497, 532, 538, 540, 548, 598},
    "deser": {502, 1395},
    "redirect": {601},
    "crypto": {261, 310, 311, 326, 327, 328, 329, 330, 331, 335, 338, 340, 347, 354, 916, 1204, 1240},
    "xxe": {611, 776, 827},
    "race": {362, 363, 364, 366, 367},
    "memory": {119, 120, 121, 122, 125, 126, 127, 131, 190, 191, 401, 415, 416, 476, 787, 805, 824},
    "sandbox": {693, 1188, 265, 653, 749},
    "header": {113, 644, 1021, 942, 1004, 614},
}
_BY_ID = {}
for fam, ids in FAMILIES.items():
    for i in ids:
        _BY_ID.setdefault(i, fam)

CWE_RE = re.compile(r"CWE-?(\d+)", re.I)


def cwe_num(x: str | int | None) -> int | None:
    if x is None:
        return None
    if isinstance(x, int):
        return x
    m = CWE_RE.search(str(x))
    return int(m.group(1)) if m else None


def family(x: str | int | None) -> str | None:
    n = cwe_num(x)
    if n is None:
        return None
    return _BY_ID.get(n, f"cwe-{n}")


def matches(finding_cwe: str | None, truth_cwes: list[str], loose: bool = False) -> bool:
    truth_nums = [cwe_num(c) for c in truth_cwes]
    if loose and 20 in truth_nums:
        return True
    fam = family(finding_cwe)
    if fam is None:
        return False
    return any(fam == family(c) for c in truth_cwes)
