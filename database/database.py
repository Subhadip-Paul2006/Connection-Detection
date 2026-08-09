"""SQLite persistence for Feluda (Phases 14 & 16).

- history: every analyzed scan record (timestamp, pid, process, ips/ports,
  status, risk score/level, signals).
- baseline: learned normal process->remote_port patterns (`name:port`).
"""

import contextlib
import sqlite3
from pathlib import Path

from utils import logger

log = logger.get_logger("database")

DB_PATH = Path(__file__).resolve().parent / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    exe_path TEXT,
    sha256 TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    status TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    signals TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_ts ON history(timestamp);
CREATE INDEX IF NOT EXISTS idx_history_pid ON history(pid);

CREATE TABLE IF NOT EXISTS baseline (
    key TEXT PRIMARY KEY,
    process_name TEXT,
    remote_port INTEGER,
    created_at TEXT NOT NULL
);
"""


def _connect(db_path=None):
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def baseline_key(process_name, remote_port):
    # Mirror the learn-path normalization (`proc.get("name") or "unknown"`) so
    # learn-time and match-time keys agree even for empty/None process names.
    return f"{(process_name or 'unknown').lower()}:{remote_port}"


def save_scan(records, db_path=None):
    """Persist a batch of analyzed records. Returns inserted row count."""
    from utils.formatting import build_connection_payload

    rows = []
    for rec in records:
        p = build_connection_payload(rec)
        rows.append((
            p["timestamp"], p["pid"], p["process_name"], p["exe_path"], p["sha256"],
            p["local_ip"], p["local_port"], p["remote_ip"], p["remote_port"],
            p["status"], p["risk_score"], p["risk_level"], "; ".join(p["reasons"]),
        ))
    inserted = 0
    try:
        # contextlib.closing guarantees close(); a bare `with` on sqlite3 only
        # commits — it never closes the connection, leaking one per call.
        with contextlib.closing(_connect(db_path)) as conn, conn:
            cur = conn.executemany(
                """INSERT INTO history
                   (timestamp, pid, process_name, exe_path, sha256,
                    local_ip, local_port, remote_ip, remote_port,
                    status, risk_score, risk_level, signals)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
            inserted = cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else len(rows)
        log.info("persisted %d history rows", inserted)
    except sqlite3.Error as exc:
        log.error("save_scan failed: %s", exc)
    return inserted


def fetch_history(limit=200, level=None, db_path=None):
    """Fetch most recent history rows, optionally filtered by risk level."""
    sql = "SELECT * FROM history"
    params = []
    if level:
        sql += " WHERE risk_level = ?"
        params.append(level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except sqlite3.Error as exc:
        log.error("fetch_history failed: %s", exc)
        return []


def distinct_history_count(db_path=None):
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            return conn.execute("SELECT COUNT(*) AS c FROM history").fetchone()["c"]
    except sqlite3.Error:
        return 0


def create_baseline(records, db_path=None):
    """Learn normal process->remote_port patterns from a scan's records.

    Only external (public) connections with a real remote port are learned,
    matching how baseline checks are applied during analysis.
    """
    from utils.formatting import utc_now_iso

    now = utc_now_iso()
    added = 0
    entries = {}
    for rec in records:
        if not rec.get("is_external"):
            continue
        proc = rec.get("proc_info") or {}
        name = proc.get("name") or "unknown"
        rport = rec.get("remote_port")
        if rport is None:
            continue
        key = baseline_key(name, rport)
        entries[key] = (key, name, rport, now)
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            for row in entries.values():
                cur = conn.execute(
                    "INSERT OR IGNORE INTO baseline (key, process_name, remote_port, created_at) VALUES (?,?,?,?)",
                    row,
                )
                added += cur.rowcount
        log.info("baseline learned %d new patterns (total known: %d)", added, len(entries))
    except sqlite3.Error as exc:
        log.error("create_baseline failed: %s", exc)
        return 0
    return added


def load_baseline(db_path=None):
    """Return a set of baseline keys like 'chrome.exe:443'."""
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            return {row["key"] for row in conn.execute("SELECT key FROM baseline")}
    except sqlite3.Error as exc:
        log.error("load_baseline failed: %s", exc)
        return set()


def clear_baseline(db_path=None):
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            conn.execute("DELETE FROM baseline")
    except sqlite3.Error as exc:
        log.error("clear_baseline failed: %s", exc)
