"""SQLite persistence for Browser & URL Threat Detection.

Two tables added to the SAME history.db the rest of Feluda uses (per spec —
extend, never a separate DB):

- browser_urls: one row per (browser_name, url). first_seen is set the first
  time that (browser, url) is observed; last_seen bumps on every subsequent
  observation. risk_score/signals are the latest structural-score verdict.
- url_reputation_cache: per-domain VirusTotal results with an expiry, so
  reputation lookups can respect rate limits without re-calling the API.

Reuses utils.formatting.utc_now_iso and database.DB_PATH for consistency.
"""

import contextlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from utils import logger
from utils.formatting import utc_now_iso

log = logger.get_logger("browser.db")

from database.database import DB_PATH  # reuse single DB path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS browser_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    browser_name TEXT NOT NULL,
    pid INTEGER,
    url TEXT NOT NULL,
    domain TEXT,
    title TEXT,
    is_live_tab INTEGER NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    signals TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (browser_name, url)
);
CREATE INDEX IF NOT EXISTS idx_browser_urls_risk ON browser_urls(risk_score);

CREATE TABLE IF NOT EXISTS url_reputation_cache (
    domain TEXT PRIMARY KEY,
    vt_result TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""


def _connect(db_path=None):
    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def domain_from_url(url):
    """Extract the bare domain for storage/key purposes (no port)."""
    from urllib.parse import urlsplit

    try:
        host = urlsplit(url).hostname or ""
    except (ValueError, TypeError):
        host = ""
    return host.lower()


def upsert_browser_url(record, db_path=None):
    """Insert-or-update one URL record. Returns row id (new) or existing id.

    `record` comes from browser_detector + url_risk_engine, carrying:
      browser_name, pid, url, title, is_live_tab, risk_score, signals
    first_seen is preserved across re-observations; last_seen always updates.
    """
    now = utc_now_iso()
    domain = domain_from_url(record.get("url", ""))
    signals = json.dumps(record.get("signals") or [])
    row = (
        record.get("browser_name", "unknown"),
        record.get("pid"),
        record.get("url", ""),
        domain,
        record.get("title", ""),
        1 if record.get("is_live_tab") else 0,
        int(record.get("risk_score", 0)),
        signals,
        now,
        now,
    )
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            cur = conn.execute(
                """INSERT INTO browser_urls
                   (browser_name, pid, url, domain, title, is_live_tab,
                    risk_score, signals, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT (browser_name, url) DO UPDATE SET
                       pid         = excluded.pid,
                       title       = excluded.title,
                       is_live_tab = excluded.is_live_tab,
                       risk_score  = excluded.risk_score,
                       signals     = excluded.signals,
                       last_seen   = excluded.last_seen""",
                row,
            )
            return cur.lastrowid
    except sqlite3.Error as exc:
        log.error("upsert_browser_url failed: %s", exc)
        return None


def fetch_browser_urls(limit=500, min_score=None, db_path=None):
    """Fetch most-recently-seen URL rows (desc last_seen), newest first."""
    sql = "SELECT * FROM browser_urls"
    params = []
    if min_score is not None:
        sql += " WHERE risk_score >= ?"
        params.append(int(min_score))
    sql += " ORDER BY last_seen DESC LIMIT ?"
    params.append(int(limit))
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except sqlite3.Error as exc:
        log.error("fetch_browser_urls failed: %s", exc)
        return []


def browser_url_count(db_path=None):
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            return conn.execute("SELECT COUNT(*) AS c FROM browser_urls").fetchone()["c"]
    except sqlite3.Error:
        return 0


def cache_get(domain, db_path=None):
    """Return (vt_result_dict, expires_at) for a domain, or None if missing/expired."""
    now = utc_now_iso()
    try:
        with contextlib.closing(_connect(db_path)) as conn:
            row = conn.execute(
                "SELECT vt_result, expires_at FROM url_reputation_cache WHERE domain = ?",
                (domain,),
            ).fetchone()
    except sqlite3.Error as exc:
        log.error("cache_get failed: %s", exc)
        return None
    if not row or not row["expires_at"] or row["expires_at"] <= now:
        return None
    try:
        return json.loads(row["vt_result"] or "{}"), row["expires_at"]
    except json.JSONDecodeError:
        return None


def cache_set(domain, vt_result, ttl_days=7, db_path=None):
    """Store a VirusTotal result for a domain with an expiry."""
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(days=int(ttl_days))).isoformat()
    try:
        with contextlib.closing(_connect(db_path)) as conn, conn:
            conn.execute(
                """INSERT INTO url_reputation_cache (domain, vt_result, checked_at, expires_at)
                   VALUES (?,?,?,?)
                   ON CONFLICT (domain) DO UPDATE SET
                       vt_result = excluded.vt_result,
                       checked_at = excluded.checked_at,
                       expires_at = excluded.expires_at""",
                (domain, json.dumps(vt_result), now.isoformat(), expires),
            )
    except sqlite3.Error as exc:
        log.error("cache_set failed: %s", exc)
