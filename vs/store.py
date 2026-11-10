"""results/vulnscan.sqlite: the source of truth for every eval run (pattern from the redteam lab).

Every arm writes through record_item(); findings use one shape:
  {"file": str, "line": int, "cwe": "CWE-22" | None, "title": str, "explanation": str}
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, arm TEXT NOT NULL, split TEXT NOT NULL, bench TEXT NOT NULL,
  config TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, final INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS items (
  run_id TEXT NOT NULL, item_id TEXT NOT NULL, ok INTEGER NOT NULL, error TEXT,
  latency_s REAL, tokens_in INTEGER, tokens_out INTEGER, raw TEXT,
  PRIMARY KEY (run_id, item_id));
CREATE TABLE IF NOT EXISTS findings (
  run_id TEXT NOT NULL, item_id TEXT NOT NULL, idx INTEGER NOT NULL,
  file TEXT, line INTEGER, cwe TEXT, title TEXT, explanation TEXT,
  PRIMARY KEY (run_id, item_id, idx));
"""


def connect(path: str | pathlib.Path = "results/vulnscan.sqlite") -> sqlite3.Connection:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(p)
    db.executescript(SCHEMA)
    return db


def start_run(db, run_id: str, arm: str, split: str, bench: str, config: dict, final: bool = False) -> None:
    db.execute("INSERT OR IGNORE INTO runs VALUES (?,?,?,?,?,?,NULL,?)",
               (run_id, arm, split, bench, json.dumps(config, sort_keys=True),
                dt.datetime.now(dt.timezone.utc).isoformat(), int(final)))
    db.commit()


def done_items(db, run_id: str) -> set[str]:
    return {r[0] for r in db.execute("SELECT item_id FROM items WHERE run_id=? AND ok=1", (run_id,))}


def record_item(db, run_id: str, item_id: str, findings: list[dict] | None, *, error: str | None = None,
                latency_s: float | None = None, tokens_in: int | None = None, tokens_out: int | None = None,
                raw: str | None = None) -> None:
    db.execute("DELETE FROM findings WHERE run_id=? AND item_id=?", (run_id, item_id))
    db.execute("INSERT OR REPLACE INTO items VALUES (?,?,?,?,?,?,?,?)",
               (run_id, item_id, int(error is None), error, latency_s, tokens_in, tokens_out, raw))
    for i, f in enumerate(findings or []):
        line = f.get("line")
        try:
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None
        db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?)",
                   (run_id, item_id, i, f.get("file"), line, f.get("cwe"), f.get("title"), f.get("explanation")))
    db.commit()


def finish_run(db, run_id: str) -> None:
    db.execute("UPDATE runs SET finished_at=? WHERE run_id=?",
               (dt.datetime.now(dt.timezone.utc).isoformat(), run_id))
    db.commit()


def load_findings(db, run_id: str) -> tuple[dict[str, list[dict]], set[str]]:
    """Returns ({item_id: [finding]}, {item_ids that errored})."""
    out: dict[str, list[dict]] = {}
    for item_id, ok in db.execute("SELECT item_id, ok FROM items WHERE run_id=?", (run_id,)):
        out.setdefault(item_id, [])
    errored = {r[0] for r in db.execute("SELECT item_id FROM items WHERE run_id=? AND ok=0", (run_id,))}
    for item_id, file, line, cwe, title, expl in db.execute(
            "SELECT item_id, file, line, cwe, title, explanation FROM findings WHERE run_id=? ORDER BY idx", (run_id,)):
        out.setdefault(item_id, []).append({"file": file, "line": line, "cwe": cwe, "title": title, "explanation": expl})
    return out, errored
