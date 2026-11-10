"""Shortcut probe: can surface statistics of the diff (no semantics) separate vuln_intro items from
benign/fix items? If yes, the reversed-fix framing leaks a "this PR deletes a guard" signal and model
recall on it is optimistic. Repo-grouped cross-validation, logistic regression, AUC.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vs.bench import file_at  # noqa: E402

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

GUARD = re.compile(r"^\s*(if|elif|else|unless|raise|throw|return|assert|try|except|catch)\b|\b(raise|throw)\b")
WORDS = re.compile(r"check|valid|saniti|escape|allow|deny|limit|max|min|safe|forbid|reject|permission|auth|"
                   r"resolve|normali|realpath|startswith|length|size|depth|timeout", re.I)


def feats(diff: str) -> list[float]:
    add = [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    rem = [l[1:] for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    n = max(len(add) + len(rem), 1)
    return [len(rem) / n, np.log1p(len(add)), np.log1p(len(rem)),
            sum(bool(GUARD.search(l)) for l in rem) / max(len(rem), 1),
            sum(bool(WORDS.search(l)) for l in rem) / max(len(rem), 1),
            sum(bool(GUARD.search(l)) for l in add) / max(len(add), 1),
            sum(bool(WORDS.search(l)) for l in add) / max(len(add), 1),
            float(len(add) == 0)]


RENDER_BUDGET = 0  # >0: probe the text actually rendered into the reviewer prompt (redacted, budgeted)


def shown_diff(item: dict) -> str:
    if RENDER_BUDGET:
        from vs.prompt import build_user
        text = build_user(item, RENDER_BUDGET)
        if item.get("framing") != "newcode":
            return text  # diff block first, then numbered head files; +/- lines inside the diff keep their meaning
        import re as _re
        return "\n".join("+" + _re.sub(r"^\s*\d+  ", "", l) for l in text.splitlines() if _re.match(r"^\s*\d+  ", l))
    if item.get("framing") != "newcode":
        return item["diff"]
    out = []
    for f, wins in item["views"].items():
        lines = (file_at(item["repo"], item["head"], f) or "").splitlines()
        for a, b in wins:
            out += ["+" + l for l in lines[a - 1:b]]
    return "\n".join(out)


POS = ("vuln_intro", "nc_vuln")


def main(path: str) -> None:
    items = [json.loads(l) for l in open(path)]
    for it in items:  # normalise new-code kinds onto the regression names for the masks below
        it["kind"] = {"nc_vuln": "vuln_intro", "nc_fixed": "fix", "nc_benign": "benign"}.get(it["kind"], it["kind"])
    X = np.array([feats(shown_diff(i)) for i in items])
    y = np.array([i["kind"] in POS for i in items], dtype=int)
    g = np.array([i["repo"] for i in items])
    for label, mask in (("intro vs benign+fix", np.ones(len(items), bool)),
                        ("intro vs benign", np.array([i["kind"] != "fix" for i in items])),
                        ("intro vs fix", np.array([i["kind"] != "benign" for i in items]))):
        Xm, ym, gm = X[mask], y[mask], g[mask]
        p = np.zeros(len(ym))
        for tr, te in GroupKFold(5).split(Xm, ym, gm):
            m = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xm[tr], ym[tr])
            p[te] = m.predict_proba(Xm[te])[:, 1]
        print(f"{label:22} AUC {roc_auc_score(ym, p):.3f}  (n={len(ym)})")
    print("mean removed-line share: intro %.2f  benign %.2f  fix %.2f" % tuple(
        X[[i['kind'] == k for i in items], 0].mean() for k in ("vuln_intro", "benign", "fix")))
    print("pure-deletion diffs:     intro %.0f%%  benign %.0f%%  fix %.0f%%" % tuple(
        100 * X[[i['kind'] == k for i in items], 7].mean() for k in ("vuln_intro", "benign", "fix")))


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0].startswith("--rendered="):
        RENDER_BUDGET = int(args.pop(0).split("=", 1)[1])
    main(args[0])
