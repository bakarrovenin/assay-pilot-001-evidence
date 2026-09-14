"""Server-side result store, so the leaderboard is real rather than per browser.

One SQLite file. Each row is a scored submission: the tool, the version, the
verdict, the failure class, the four checks as JSON, and a timestamp. The patch
is never stored. The leaderboard is recounted from these rows on every read, the
same discipline as verify_report_math in the pilot: nothing is a stored rate.

SQLite is the right size for this. It is one file, needs no separate process,
survives a restart, and a public benchmark's submission rate does not need
anything larger. If it ever does, this module is the only thing that changes.
"""

import json
import os
import sqlite3
import threading
import time
import uuid

DB_PATH = os.environ.get(
    "ASSAY_BENCHMARK_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.db"),
)

_lock = threading.Lock()


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS results (
                id            TEXT PRIMARY KEY,
                finding       TEXT NOT NULL,
                tool          TEXT NOT NULL,
                version       TEXT NOT NULL,
                verdict       TEXT NOT NULL,
                failure_class TEXT,
                checks_json   TEXT,
                created_at    TEXT NOT NULL
            )
            """
        )


def save(result):
    """Persist one result. Returns the row id. Stores no patch text."""
    rid = uuid.uuid4().hex
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock, _conn() as conn:
        conn.execute(
            "INSERT INTO results (id, finding, tool, version, verdict, "
            "failure_class, checks_json, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                rid,
                result["finding"],
                result["tool"],
                result["version"],
                result["verdict"],
                result.get("failureClass"),
                json.dumps(result.get("checks")),
                created,
            ),
        )
    return rid, created


def get(rid):
    with _conn() as conn:
        row = conn.execute("SELECT * FROM results WHERE id = ?", (rid,)).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "v": 1,
        "set": "submitted",
        "finding": row["finding"],
        "tool": row["tool"],
        "version": row["version"],
        "verdict": row["verdict"],
        "failureClass": row["failure_class"],
        "checks": json.loads(row["checks_json"]) if row["checks_json"] else None,
        "date": row["created_at"][:10],
        "scorer": "pilot-001-harness",
    }


def _tally(rows):
    scored = alert = verified = no_alert = 0
    for r in rows:
        v = r["verdict"]
        if v == "NO ALERT":
            no_alert += 1
            continue
        if v == "INSUFFICIENT EVIDENCE" or not r["checks_json"]:
            continue
        scored += 1
        checks = json.loads(r["checks_json"]) or {}
        if (checks.get("A") or {}).get("pass"):
            alert += 1
        if v == "VERIFIED":
            verified += 1
    pct = lambda n: None if scored == 0 else round(n / scored * 100)
    a, ver = pct(alert), pct(verified)
    return {
        "scored": scored,
        "alertClosed": alert,
        "verified": verified,
        "noAlert": no_alert,
        "alertClosedRate": a,
        "verifiedRate": ver,
        "gapPp": None if a is None or ver is None else a - ver,
    }


def leaderboard():
    """Recount per (tool, version), most-evidenced first. Recomputed, not stored."""
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM results").fetchall()
    groups = {}
    for r in rows:
        groups.setdefault((r["tool"], r["version"]), []).append(r)
    out = [
        {"tool": tool, "version": version, "tally": _tally(rs)}
        for (tool, version), rs in groups.items()
    ]
    out.sort(key=lambda x: (-x["tally"]["scored"], x["tool"].lower()))
    return {"total": len(rows), "rows": out}
