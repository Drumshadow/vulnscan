"""Evaluated-ID manifests and per-arm terminal error counts for the published test results.
  manifests.py > evidence/evaluated-manifests.md   (also writes evidence/evaluated-ids-<split>.json)"""
import collections, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_checks import ARMS  # noqa: E402
from vs import store  # noqa: E402
from vs.bench import load_items, sample_ids  # noqa: E402

db = store.connect()
print("# Evaluated populations and terminal errors\n")
for split in ("test_nc", "test"):
    ids = sorted(sample_ids(split, "frontier"))
    kinds = collections.Counter(i["kind"] for i in load_items(split) if i["id"] in set(ids))
    pathlib.Path(f"evidence/evaluated-ids-{split}.json").write_text(json.dumps(ids, indent=0) + "\n")
    print(f"## {split}: {len(ids)} items {dict(kinds)} (evidence/evaluated-ids-{split}.json)\n")
    print("| reviewer | stored results | ok | terminal errors (counted as misses / unflagged) |\n|---|---|---|---|")
    for k, (h, _) in ARMS.items():
        rid = f"{k}:{split}:{h}"
        rows = db.execute("SELECT ok FROM items WHERE run_id=? AND item_id IN (%s)" % ",".join("?" * len(ids)), (rid, *ids)).fetchall()
        if not rows:
            print(f"| {k} | not run | | |"); continue
        print(f"| {k} | {len(rows)} | {sum(r[0] for r in rows)} | {sum(1 - r[0] for r in rows)} |")
    print()
