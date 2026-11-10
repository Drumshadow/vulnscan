from vs import cwe
from vs.score import judge_item, metrics, norm_path, score_run

INTRO = {"id": "G1:intro", "kind": "vuln_intro", "repo": "o/r", "cwes": ["CWE-22"],
         "truth": {"src/app.py": [40, 41]}}
FIX = {"id": "G1:fix", "kind": "fix", "repo": "o/r", "cwes": ["CWE-22"], "truth": {}}
BEN = {"id": "o/r@abc:benign", "kind": "benign", "repo": "o/r", "cwes": [], "truth": {}}


def test_family_match():
    assert cwe.matches("CWE-73", ["CWE-22"])          # same family (path)
    assert cwe.matches("cwe-770", ["CWE-400"])        # dos
    assert not cwe.matches("CWE-79", ["CWE-22"])
    assert not cwe.matches(None, ["CWE-22"])
    assert cwe.matches("CWE-1234", ["CWE-1234"])      # unmapped matches itself
    assert not cwe.matches("CWE-79", ["CWE-20"])      # CWE-20 truth is not a wildcard in strict
    assert cwe.matches("CWE-79", ["CWE-20"], loose=True)


def test_hit_strict_and_window():
    f = [{"file": "b/src/app.py", "line": 45, "cwe": "CWE-22"}]
    j = judge_item(INTRO, f)
    assert j["hit_strict"] and j["hit_loc"]
    j = judge_item(INTRO, [{"file": "src/app.py", "line": 47, "cwe": "CWE-22"}])  # 6 away from 41
    assert not j["hit_loc"]


def test_loc_without_cwe():
    j = judge_item(INTRO, [{"file": "./src/app.py", "line": 40, "cwe": "CWE-79"}])
    assert j["hit_loc"] and not j["hit_strict"]


def test_wrong_file_and_null_line():
    assert not judge_item(INTRO, [{"file": "src/other.py", "line": 40, "cwe": "CWE-22"}])["hit_loc"]
    assert not judge_item(INTRO, [{"file": "src/app.py", "line": None, "cwe": "CWE-22"}])["hit_loc"]


def test_metrics_and_errors_count_as_misses():
    items = [INTRO, FIX, BEN]
    findings = {"G1:intro": [], "G1:fix": [{"file": "src/app.py", "line": 1, "cwe": "CWE-22"}],
                "o/r@abc:benign": []}
    r = score_run(items, findings, errored={"G1:intro"}, iters=50)
    m = r["metrics"]
    assert m["recall_strict"] == 0.0 and m["fix_flag_rate"] == 1.0 and m["benign_flag_rate"] == 0.0
    assert m["precision_strict"] == 0.0 and r["n_errored"] == 1


def test_missing_item_reported():
    r = score_run([INTRO, BEN], {"G1:intro": []}, errored=set(), iters=10)
    assert r["n_missing"] == 1


def test_norm_path():
    assert norm_path("a/x.py") == norm_path("./x.py") == "x.py"


def test_precision():
    rows = [(INTRO, judge_item(INTRO, [{"file": "src/app.py", "line": 41, "cwe": "CWE-22"}])),
            (BEN, judge_item(BEN, [{"file": "x", "line": 1, "cwe": "CWE-79"}]))]
    assert metrics(rows)["precision_strict"] == 0.5


def test_hit_file_any_line():
    j = judge_item(INTRO, [{"file": "src/app.py", "line": 300, "cwe": "CWE-22"}])
    assert j["hit_file"] and not j["hit_strict"]
    assert not judge_item(INTRO, [{"file": "src/app.py", "line": 300, "cwe": "CWE-79"}])["hit_file"]


def test_pair_accuracy_newcode():
    v = {"id": "G2:nc_vuln", "kind": "nc_vuln", "repo": "o/r", "pair": "G2", "cwes": ["CWE-22"],
         "truth": {"src/app.py": [40]}}
    fx = {"id": "G2:nc_fixed", "kind": "nc_fixed", "repo": "o/r", "pair": "G2", "cwes": ["CWE-22"],
          "truth": {}, "fix_site": {"src/app.py": [41, 42]}}
    hit = [{"file": "src/app.py", "line": 40, "cwe": "CWE-22"}]
    # flags both versions at the same spot: recall 1, pair accuracy 0
    r = metrics([(v, judge_item(v, hit)), (fx, judge_item(fx, hit))])
    assert r["recall_strict"] == 1.0 and r["pair_acc"] == 0.0 and r["fix_site_flag_rate"] == 1.0
    # flags only the vulnerable version: pair accuracy 1
    r = metrics([(v, judge_item(v, hit)), (fx, judge_item(fx, []))])
    assert r["pair_acc"] == 1.0
    # a finding far from the fix site on the fixed version is not a site flag
    far = [{"file": "src/app.py", "line": 300, "cwe": "CWE-79"}]
    assert not judge_item(fx, far)["site_flag"] and judge_item(fx, far)["flagged"]


def test_regression_fix_site_from_diff():
    fx = {"id": "G1:fix", "kind": "fix", "repo": "o/r", "cwes": ["CWE-22"], "truth": {},
          "diff": "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -10,2 +10,3 @@\n a\n+check()\n b\n"}
    assert judge_item(fx, [{"file": "m.py", "line": 12, "cwe": "CWE-22"}])["site_flag"]


def test_harness_keep_and_symbols():
    from vs.harness import DEF_RE, keep
    assert keep({}, {"verdict": "confirmed", "confidence": 0.7}, 0.5)
    assert not keep({}, {"verdict": "confirmed", "confidence": 0.4}, 0.5)
    assert not keep({}, {"verdict": "refuted", "confidence": 0.9}, 0.5)
    assert not keep({}, {"verdict": "error", "confidence": 0.0}, 0.0)
    assert DEF_RE["py"].match("    async def handle_upload(self, req):").group(1) == "handle_upload"
    m = DEF_RE["js"].match("export const resolvePath = async (p) => {")
    assert next(g for g in m.groups() if g) == "resolvePath"
    m = DEF_RE["js"].match("  async readFile(name) {")
    assert next(g for g in m.groups() if g) == "readFile"


def test_redact_advisory_ids():
    from vs.prompt import redact
    assert redact("    // GHSA-rh9c-rqvg-f7pr: reject absolute paths") == "    // [comment redacted]"
    assert redact("  # see CVE-2026-1234") == "  # [comment redacted]"
    assert redact('raise ValueError("blocked (CVE-2026-1234)")') == 'raise ValueError("blocked (<advisory-id>)")'
    assert redact("x = resolve(p)  # plain") == "x = resolve(p)  # plain"


def test_parse_findings_repairs_bare_backslashes():
    from vs.prompt import parse_findings
    out = parse_findings('{"findings": [{"file": "a.py", "line": 3, "cwe": "CWE-1333", "title": "regex \\d+ \\w", "explanation": "x"}]}'.replace("\\\\", "\\"))
    assert out[0]["line"] == 3


def test_harness_scope():
    from vs.harness import _scope, CODE_GLOBS
    assert _scope(["packages/kit/src/a.js"]) == [f"packages/kit/**/{g}" for g in CODE_GLOBS]
    assert _scope(["setup.py"]) == CODE_GLOBS


def test_infra_error_classification():
    from vs.bench import is_infra_error
    assert is_infra_error("URLError: <urlopen error [Errno 111] Connection refused>")
    assert is_infra_error("HTTPError: HTTP Error 500: Internal Server Error")
    assert is_infra_error('RuntimeError: claude rc=1: {"is_error":true}')
    assert not is_infra_error("RuntimeError: hit max_tokens before answering")
    assert not is_infra_error("JSONDecodeError: Invalid \\escape")
    assert not is_infra_error(None)


def test_v2_scope_glob_and_dedupe():
    from vs.harness_v2 import scope_v2, dedupe, CALL_RE
    s = scope_v2(["asyncssh/scp.py"])
    assert s[0].startswith(":(glob)asyncssh/**/")
    d = dedupe([{"file": "a.py", "line": 10, "cwe": "CWE-22", "confidence": 0.9},
                {"file": "a.py", "line": 13, "cwe": "CWE-23", "confidence": 0.5},
                {"file": "a.py", "line": 40, "cwe": "CWE-22", "confidence": 0.7},
                {"file": "a.py", "line": 11, "cwe": "CWE-79", "confidence": 0.6}])
    assert len(d) == 3 and d[0]["votes"] == 2 and d[0]["confidence"] == 0.9
    assert CALL_RE.findall("x = safe_join(root, path)") == ["safe_join"]


def test_regex_extraction_patterns():
    from vs.analyzers import JS_NEW_RE, JS_RE_LIT, PY_RE_CALL
    assert PY_RE_CALL.search('m = re.match(r"^(a+)+$", s)').group("pat") == "^(a+)+$"
    assert JS_RE_LIT.search("const ok = /^(\\w+\\s?)*$/.test(x)").group("pat") == "^(\\w+\\s?)*$"
    assert JS_NEW_RE.search('new RegExp("(a|aa)+")').group("pat") == "(a|aa)+"


def test_train_truth_lines_in_region():
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
    from vs.diffutil import head_truth
    rdiff = "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -10,3 +10,2 @@\n a\n-check(x)\n b\n"
    # reverse of a fix that added check(x): vulnerable side anchors at line 10
    assert [ln for ln in head_truth(rdiff)["m.py"] if 1 <= ln <= 50] == [10]


def test_combiner_extra_passes():
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
    from combine_harness import combos
    raw = {"passes": [{"name": "main", "seed": 1729, "candidates": [{"file": "a.py", "line": 5, "cwe": "CWE-22"}]},
                      {"name": "twostep", "candidates": [{"file": "a.py", "line": 6, "cwe": "CWE-23"},
                                                         {"file": "a.py", "line": 40, "cwe": "CWE-1333"}]}]}
    c = combos(raw)
    assert len(c["main1"]) == 1 and len(c["twostep"]) == 2 and len(c["main1+twostep"]) == 2


def test_prompt_v3_contains_v2_and_recall():
    from vs.harness_v2 import _investigator, PROMPT_V2_ADDENDUM, PROMPT_V3_ADDENDUM
    s = _investigator("v3", None)
    assert PROMPT_V2_ADDENDUM in s and PROMPT_V3_ADDENDUM in s
    assert PROMPT_V3_ADDENDUM not in _investigator("v2", None)


def test_poc_static_guards():
    from vs.poc import reads_source, uses_project
    assert reads_source("import inspect\nsrc = inspect.getsource(m)")
    assert reads_source("txt = open('pkg/mod.py').read()")
    assert not reads_source("import pkg.mod\npkg.mod.f('../../etc')")
    meta = {"lang": "python", "src": "/x/src"}
    assert uses_project("from acme_server.application import reads\n", meta, "acme_server/application/reads.py")
    assert not uses_project("import os\n", meta, "acme_server/application/reads.py")


def test_poc_path_tokens():
    from vs.poc import _tokens
    src = _tokens("acme_server/application/reads.py")
    assert "read" in src and "application" in src
    assert len(src & _tokens("tests/test_read_application.py")) == 2
    assert "attachment" in _tokens("tests/test_email_attachments.py")


def test_py_tracer_records_target_lines(tmp_path):
    import json, os, subprocess, sys
    from vs.poc import PY_TRACER
    mod = tmp_path / "pkg_mod.py"
    mod.write_text("def a():\n    return 1\n\ndef b():\n    x = 2\n    return x\n")
    (tmp_path / "poc.py").write_text("import pkg_mod\npkg_mod.b()\n")
    (tmp_path / "_vs_tracer.py").write_text(PY_TRACER)
    env = {**os.environ, "PYTHONPATH": str(tmp_path), "VS_COV_FILE": str(mod), "VS_COV_OUT": str(tmp_path / "cov.json")}
    subprocess.run([sys.executable, "-B", "_vs_tracer.py", "poc.py"], cwd=tmp_path, env=env, check=True)
    hits = set(json.loads((tmp_path / "cov.json").read_text()))
    assert {5, 6} <= hits and 2 not in hits  # b() ran, a() did not


def test_bootstrap_keeps_resampled_pair_multiplicity():
    from vs.score import resample_rows
    def pair(repo, name, ok):
        v = {"id": f"{name}:nc_vuln", "kind": "nc_vuln", "repo": repo, "pair": name, "cwes": ["CWE-22"], "truth": {"a.py": [1]}}
        f = {"id": f"{name}:nc_fixed", "kind": "nc_fixed", "repo": repo, "pair": name, "cwes": ["CWE-22"], "truth": {}, "fix_site": {"a.py": [1]}}
        hit = [{"file": "a.py", "line": 1, "cwe": "CWE-22"}] if ok else []
        return [(v, judge_item(v, hit)), (f, judge_item(f, []))]
    by_repo = {"o/a": pair("o/a", "A", True), "o/b": pair("o/b", "B", False)}
    m = metrics(resample_rows(by_repo, ["o/a", "o/a", "o/b"]))
    assert m["n_pairs"] == 3 and abs(m["pair_acc"] - 2 / 3) < 1e-9  # the collapsing bug gave 1/2


def test_stage_release_rejects_code_in_metadata():
    import sys, pathlib, pytest
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
    from stage_release import assert_metadata_only
    ok = {"id": "GHSA-1:nc_vuln", "repo": "o/r", "files": ["src/a.py"], "truth": {"src/a.py": [3]}, "leak": {"code": False}, "cwes": ["CWE-22"]}
    assert_metadata_only(ok)
    for bad in ({**ok, "leak": {"code": "x = eval(input())"}}, {**ok, "summary": "text"}, {**ok, "repo": "os.system('x')\nmore"},
                {**ok, "leak": {"def copied_function():\n    return 123": True}}):
        with pytest.raises(AssertionError):
            assert_metadata_only(bad)
