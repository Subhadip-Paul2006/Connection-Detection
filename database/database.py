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
    signals TEXT,
    country TEXT DEFAULT '',
    country_code TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_history_ts ON history(timestamp);
CREATE INDEX IF NOT EXISTS idx_history_pid ON history(pid);

CREATE TABLE IF NOT EXISTS baseline (
    key TEXT PRIMARY KEY,
    process_name TEXT,
    remote_port INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS defender_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    threat_name TEXT,
    severity TEXT,
    affected_path TEXT,
    process_name_if_known TEXT,
    detected_at TEXT,
    correlated_history_id INTEGER,
    match_confidence TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(correlated_history_id) REFERENCES history(id)
);
CREATE INDEX IF NOT EXISTS idx_defender_events_ts ON defender_events(detected_at);

CREATE TABLE IF NOT EXISTS telegram_stats (
    chat_id TEXT PRIMARY KEY,
    total_alerts_sent INTEGER DEFAULT 0,
    last_alert_at TEXT,
    last_scan_ended_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS telegram_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id TEXT NOT NULL,
    alert_type TEXT,
    risk_level TEXT,
    risk_score INTEGER,
    details TEXT,
    sent_at TEXT NOT NULL,
    FOREIGN KEY(chat_id) REFERENCES telegram_stats(chat_id)
);
CREATE INDEX IF NOT EXISTS idx_telegram_alerts_chat ON telegram_alerts(chat_id);

CREATE TABLE IF NOT EXISTS telegram_sessions (
    chat_id TEXT PRIMARY KEY,
    session_started_at TEXT NOT NULL,
    session_ended_at TEXT,
    last_known_state TEXT NOT NULL,
    current_severity_focus TEXT,
    total_findings_sent INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS correlated_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_identity TEXT NOT NULL,
    stages_involved TEXT NOT NULL,
    chain_narrative TEXT NOT NULL,
    bonus_points INTEGER NOT NULL,
    final_risk_score INTEGER NOT NULL,
    final_risk_level TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    related_history_ids TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_chains_identity ON correlated_chains(target_identity);
CREATE INDEX IF NOT EXISTS idx_chains_ts ON correlated_chains(detected_at);
"""


def _connect(db_path=None):
    path = Path(db_path) if db_path else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    # Older DBs opened before the geoip columns existed get them on first read.
    for stmt in (
        "ALTER TABLE history ADD COLUMN country TEXT DEFAULT ''",
        "ALTER TABLE history ADD COLUMN country_code TEXT DEFAULT ''",
    ):
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass  # column already exists
    return conn


def baseline_key(process_name, remote_port):
    # Mirror the learn-path normalization (`proc.get("name") or "unknown"`) so
    # learn-time and match-time keys agree even for empty/None process names.
    return f"{(process_name or 'unknown').lower()}:{remote_port}"


def save_scan(records, db_path=None, return_ids=False):
    """Persist a batch of analyzed records. Returns inserted row count.

    When return_ids=True, also returns a list of inserted history row ids (same
    order as `records`) so later phases can attach deeper metadata (e.g.
    process_lineage.connection_id) without inventing a disconnected table.
    """
    from utils.formatting import build_connection_payload

    rows = []
    for rec in records:
        p = build_connection_payload(rec)
        geo = rec.get("geoip") or {}
        rows.append((
            p["timestamp"], p["pid"], p["process_name"], p["exe_path"], p["sha256"],
            p["local_ip"], p["local_port"], p["remote_ip"], p["remote_port"],
            p["status"], p["risk_score"], p["risk_level"], "; ".join(p["reasons"]),
            geo.get("country", ""), geo.get("country_code", ""),
        ))
    inserted = 0
    row_ids = []
    try:
        # contextlib.closing guarantees close(); a bare `with` on sqlite3 only
        # commits — it never closes the connection, leaking one per call.
        with contextlib.closing(_connect(db_path)) as conn, conn:
            for row in rows:
                cur = conn.execute(
                    """INSERT INTO history
                       (timestamp, pid, process_name, exe_path, sha256,
                        local_ip, local_port, remote_ip, remote_port,
                        status, risk_score, risk_level, signals, country, country_code)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    row,
                )
                row_ids.append(cur.lastrowid)
            inserted = len(row_ids)
        log.info("persisted %d history rows", inserted)
    except sqlite3.Error as exc:
        log.error("save_scan failed: %s", exc)
    if return_ids:
        return row_ids
    return inserted


def fetch_history(limit=200, level=None, country=None, db_path=None):
    """Fetch most recent history rows, optionally filtered by risk level
    and/or ISO-3166 country code (geo enrichment)."""
    sql = "SELECT * FROM history"
    params = []
    clauses = []
    if level:
        clauses.append("risk_level = ?")
        params.append(level.upper())
    if country:
        clauses.append("country_code = ?")
        params.append(str(country).upper())
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
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


def save_defender_events(events, db_path=None):
    """Persist Defender correlation / gap event records.
    `events` is a list of dicts matching defender_events schema.
    Returns count of inserted rows.
    """
    from utils.formatting import utc_now_iso

    now = utc_now_iso()
    rows = []
    for evt in events:
        rows.append((
            evt.get("event_id"),
            evt.get("threat_name", ""),
            evt.get("severity", ""),
            evt.get("affected_path", ""),
            evt.get("process_name_if_known", ""),
            evt.get("detected_at", ""),
            evt.get("correlated_history_id"),  # nullable FK
            evt.get("match_confidence", ""),
            evt.get("created_at") or now,
        ))
    inserted = 0
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            for row in rows:
                conn.execute(
                    """INSERT INTO defender_events
                       (event_id, threat_name, severity, affected_path, process_name_if_known,
                        detected_at, correlated_history_id, match_confidence, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    row,
                )
                inserted += 1
        log.info("persisted %d defender event rows", inserted)
    except sqlite3.Error as exc:
        log.error("save_defender_events failed: %s", exc)
    return inserted


def fetch_defender_events(limit=50, db_path=None):
    """Fetch recent Defender events from defender_events table."""
    sql = "SELECT * FROM defender_events ORDER BY id DESC LIMIT ?"
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            return [dict(r) for r in conn.execute(sql, [int(limit)]).fetchall()]
    except sqlite3.Error as exc:
        log.error("fetch_defender_events failed: %s", exc)
        return []


def record_telegram_alert(chat_id, alert_type="connection", risk_level="HIGH", risk_score=0, details="", db_path=None):
    """Log a sent Telegram alert and UPSERT total count in telegram_stats for chat_id."""
    from utils.formatting import utc_now_iso
    now = utc_now_iso()
    chat_id_str = str(chat_id).strip()
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            # 1. Insert alert log entry
            conn.execute(
                """INSERT INTO telegram_alerts (chat_id, alert_type, risk_level, risk_score, details, sent_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (chat_id_str, alert_type, risk_level, int(risk_score), str(details), now),
            )
            # 2. UPSERT into telegram_stats
            conn.execute(
                """INSERT INTO telegram_stats (chat_id, total_alerts_sent, last_alert_at, updated_at)
                   VALUES (?, 1, ?, ?)
                   ON CONFLICT(chat_id) DO UPDATE SET
                       total_alerts_sent = total_alerts_sent + 1,
                       last_alert_at = excluded.last_alert_at,
                       updated_at = excluded.updated_at""",
                (chat_id_str, now, now),
            )
        log.info("recorded telegram alert for chat_id=%s (type=%s)", chat_id_str, alert_type)
        return True
    except sqlite3.Error as exc:
        log.error("record_telegram_alert failed: %s", exc)
        return False


def record_telegram_scan_stop(chat_id, db_path=None):
    """Update last_scan_ended_at timestamp in telegram_stats for chat_id when scan/monitor stops."""
    from utils.formatting import utc_now_iso
    now = utc_now_iso()
    chat_id_str = str(chat_id).strip()
    if not chat_id_str:
        return False
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            conn.execute(
                """INSERT INTO telegram_stats (chat_id, total_alerts_sent, last_scan_ended_at, updated_at)
                   VALUES (?, 0, ?, ?)
                   ON CONFLICT(chat_id) DO UPDATE SET
                       last_scan_ended_at = excluded.last_scan_ended_at,
                       updated_at = excluded.updated_at""",
                (chat_id_str, now, now),
            )
        log.info("recorded telegram scan stop for chat_id=%s", chat_id_str)
        return True
    except sqlite3.Error as exc:
        log.error("record_telegram_scan_stop failed: %s", exc)
        return False


def fetch_telegram_stats(chat_id=None, db_path=None):
    """Fetch telegram recipient stats. Returns dict or list of dicts."""
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            if chat_id:
                row = conn.execute("SELECT * FROM telegram_stats WHERE chat_id = ?", [str(chat_id)]).fetchone()
                return dict(row) if row else {}
            return [dict(r) for r in conn.execute("SELECT * FROM telegram_stats ORDER BY updated_at DESC").fetchall()]
    except sqlite3.Error as exc:
        log.error("fetch_telegram_stats failed: %s", exc)
        return {} if chat_id else []


def fetch_telegram_alerts(chat_id=None, limit=50, db_path=None):
    """Fetch logged telegram alerts."""
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            if chat_id:
                sql = "SELECT * FROM telegram_alerts WHERE chat_id = ? ORDER BY id DESC LIMIT ?"
                return [dict(r) for r in conn.execute(sql, [str(chat_id), int(limit)]).fetchall()]
            sql = "SELECT * FROM telegram_alerts ORDER BY id DESC LIMIT ?"
            return [dict(r) for r in conn.execute(sql, [int(limit)]).fetchall()]
    except sqlite3.Error as exc:
        log.error("fetch_telegram_alerts failed: %s", exc)
        return []


def upsert_telegram_session(chat_id, state="listening", severity_focus=None, db_path=None):
    """Upsert a telegram session record on chat_id PRIMARY KEY.

    Resets session_started_at to now, session_ended_at to NULL, total_findings_sent to 0,
    and updates state and severity focus.
    """
    from utils.formatting import utc_now_iso
    now = utc_now_iso()
    chat_id_str = str(chat_id).strip()
    if not chat_id_str:
        return False
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            conn.execute(
                """INSERT INTO telegram_sessions
                   (chat_id, session_started_at, session_ended_at, last_known_state, current_severity_focus, total_findings_sent, updated_at)
                   VALUES (?, ?, NULL, ?, ?, 0, ?)
                   ON CONFLICT(chat_id) DO UPDATE SET
                       session_started_at = excluded.session_started_at,
                       session_ended_at = NULL,
                       last_known_state = excluded.last_known_state,
                       current_severity_focus = excluded.current_severity_focus,
                       total_findings_sent = 0,
                       updated_at = excluded.updated_at""",
                (chat_id_str, now, state, severity_focus, now),
            )
        log.info("upserted telegram session for chat_id=%s (state=%s)", chat_id_str, state)
        return True
    except sqlite3.Error as exc:
        log.error("upsert_telegram_session failed: %s", exc)
        return False


def update_telegram_session_state(chat_id, state, severity_focus=None, db_path=None):
    """Update live state and severity focus for an active session."""
    from utils.formatting import utc_now_iso
    now = utc_now_iso()
    chat_id_str = str(chat_id).strip()
    if not chat_id_str:
        return False
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            conn.execute(
                """UPDATE telegram_sessions
                   SET last_known_state = ?,
                       current_severity_focus = ?,
                       updated_at = ?
                   WHERE chat_id = ?""",
                (state, severity_focus, now, chat_id_str),
            )
        log.info("updated telegram session state for chat_id=%s to state=%s", chat_id_str, state)
        return True
    except sqlite3.Error as exc:
        log.error("update_telegram_session_state failed: %s", exc)
        return False


def increment_session_findings(chat_id, count=1, db_path=None):
    """Atomically increment total_findings_sent for an active session."""
    from utils.formatting import utc_now_iso
    now = utc_now_iso()
    chat_id_str = str(chat_id).strip()
    if not chat_id_str:
        return False
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            conn.execute(
                """UPDATE telegram_sessions
                   SET total_findings_sent = total_findings_sent + ?,
                       updated_at = ?
                   WHERE chat_id = ?""",
                (int(count), now, chat_id_str),
            )
        return True
    except sqlite3.Error as exc:
        log.error("increment_session_findings failed: %s", exc)
        return False


def close_telegram_session(chat_id, db_path=None):
    """Mark session as ended in telegram_sessions."""
    from utils.formatting import utc_now_iso
    now = utc_now_iso()
    chat_id_str = str(chat_id).strip()
    if not chat_id_str:
        return False
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            conn.execute(
                """UPDATE telegram_sessions
                   SET session_ended_at = ?,
                       last_known_state = 'stopped',
                       current_severity_focus = NULL,
                       updated_at = ?
                   WHERE chat_id = ?""",
                (now, now, chat_id_str),
            )
        log.info("closed telegram session for chat_id=%s", chat_id_str)
        return True
    except sqlite3.Error as exc:
        log.error("close_telegram_session failed: %s", exc)
        return False


def fetch_telegram_sessions(chat_id=None, db_path=None):
    """Fetch telegram session records. Returns dict or list of dicts."""
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            if chat_id:
                row = conn.execute("SELECT * FROM telegram_sessions WHERE chat_id = ?", [str(chat_id)]).fetchone()
                return dict(row) if row else {}
            return [dict(r) for r in conn.execute("SELECT * FROM telegram_sessions ORDER BY updated_at DESC").fetchall()]
    except sqlite3.Error as exc:
        log.error("fetch_telegram_sessions failed: %s", exc)
        return {} if chat_id else []


def save_correlated_chain(chain_dict, db_path=None):
    """Save an attack chain record into correlated_chains table."""
    import json
    from utils.formatting import utc_now_iso
    now = utc_now_iso()
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            cur = conn.execute(
                """INSERT INTO correlated_chains
                   (target_identity, stages_involved, chain_narrative, bonus_points, final_risk_score, final_risk_level, detected_at, related_history_ids)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(chain_dict.get("target_identity", "")),
                    json.dumps(chain_dict.get("stages_involved", [])),
                    str(chain_dict.get("chain_narrative", "")),
                    int(chain_dict.get("bonus_points", 0)),
                    int(chain_dict.get("final_risk_score", 50)),
                    str(chain_dict.get("final_risk_level", "HIGH")),
                    chain_dict.get("detected_at") or now,
                    json.dumps(chain_dict.get("related_history_ids", [])),
                ),
            )
            chain_id = cur.lastrowid
        log.info("saved correlated chain id=%d for target=%s", chain_id, chain_dict.get("target_identity"))
        return chain_id
    except sqlite3.Error as exc:
        log.error("save_correlated_chain failed: %s", exc)
        return None


def fetch_correlated_chains(limit=50, db_path=None):
    """Fetch stored attack chain records."""
    import json
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            rows = conn.execute(
                "SELECT * FROM correlated_chains ORDER BY id DESC LIMIT ?", [int(limit)]
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                try:
                    d["stages_involved"] = json.loads(d.get("stages_involved") or "[]")
                except Exception:
                    pass
                try:
                    d["related_history_ids"] = json.loads(d.get("related_history_ids") or "[]")
                except Exception:
                    pass
                results.append(d)
            return results
    except sqlite3.Error as exc:
        log.error("fetch_correlated_chains failed: %s", exc)
        return []



