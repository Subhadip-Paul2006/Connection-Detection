"""Browser process detection + open-tab/recent-URL extraction (Phase 1).

Local-only, read-only: uses psutil.process_iter() to find running browser
processes and reads each browser's own on-disk History (Chromium) /
places.sqlite (Firefox) via a temp copy, so a locked browser file never
blocks us and we never mutate a live profile.

Output record shape (matches spec §2):
    {browser_name, pid, tab_url, tab_title, is_live_tab, detected_at}

Phase 1 delivers `is_live_tab=False` (recent-history) for every engine — the
records are real, current URLs, labeled "recent" so they aren't mistaken for
live tabs. CDP-live and Firefox recovery.jsonlz4 are the Phase-2 upgrades and
are stubbed at clearly-marked seams below so they drop in cleanly later.
"""

import json
import shutil
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

import psutil

from utils import logger
from utils.config_loader import settings
from utils.formatting import utc_now_iso

log = logger.get_logger("browser.detector")

# Chromium History SQL: newest-first, bounded, skips internal chrome:// *and*
# devtools/blob pages that carry no security signal for URL scoring.
_CHROMIUM_HISTORY_SQL = """
SELECT url, title FROM urls
WHERE url NOT LIKE 'chrome://%'
  AND url NOT LIKE 'chrome-extension://%'
  AND url NOT LIKE 'edge://%'
  AND url NOT LIKE 'brave://%'
  AND url NOT LIKE 'devtools://%'
  AND url NOT LIKE 'about:%'
ORDER BY last_visit_time DESC
LIMIT ?
"""

# Firefox places.sqlite: joins moz_places -> title, newest-first.
_FIREFOX_HISTORY_SQL = """
SELECT url, title FROM moz_places
WHERE url NOT LIKE 'about:%'
  AND url NOT LIKE 'chrome://%'
  AND url NOT LIKE 'resource://%'
  AND url NOT LIKE 'view-source:%'
  AND url NOT LIKE 'moz-extension://%'
ORDER BY last_visit_date DESC
LIMIT ?
"""


def known_browsers():
    """Config-driven map: process-name -> (display_name, engine, profile_roots).

    profile_roots is a LIST of candidate path fragments tried in order so the
    same browser works whether it's a classic installed app (e.g.
    C:\\Users\\<u>\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data) or a
    Store/UWP-packaged app (e.g. %LOCALAPPDATA%\\Packages\\<family>\\LocalCache\\
    Local\\Arc\\User Data)."""
    raw = settings().get("browser", {}).get("known_browsers", {})
    out = {}
    for proc_name, spec in raw.items():
        try:
            name, engine, roots = spec
        except (TypeError, ValueError):
            log.debug("bad browser config entry for %r: %r", proc_name, spec)
            continue
        if isinstance(roots, str):
            roots = [roots]  # tolerate older single-string form
        out[proc_name.lower()] = (name, engine, roots or [])
    return out


def detect_running_browsers():
    """Return one dict per distinct browser-kind currently running at least one
    process.

    A browser like Chrome/Edge spawns many helper PIDs that share one exe and
    one user data-dir; the History DB is shared, so we keep just the
    LOWEST pid per browser-kind as the representative. That still satisfies
    'map each browser process to PID and executable path' and avoids scanning
    the same profile once per helper.

    Record: {browser_name, engine, pid, exe, proc_name}
    """
    known = known_browsers()
    best = {}  # display_name -> record kept so far
    try:
        procs = psutil.process_iter(["pid", "name", "exe"])
    except Exception as exc:
        log.error("process_iter failed: %s", exc)
        return []
    for proc in procs:
        try:
            info = proc.info
            pname = (info.get("name") or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if pname not in known:
            continue
        display, engine, root = known[pname]
        rec = {
            "browser_name": display,
            "engine": engine,
            "pid": info.get("pid"),
            "exe": info.get("exe") or "",
            "proc_name": pname,
        }
        kept = best.get(display)
        if kept is None or (rec["pid"] or 10**9) < (kept["pid"] or 10**9):
            best[display] = rec
    log.info("detected %d running browser kinds", len(best))
    return list(best.values())


# ---------------------------------------------------------------------------
# Profile location & tab extraction
# ---------------------------------------------------------------------------

def _localappdata():
    import os
    return os.environ.get("LOCALAPPDATA", "")


def _appdata():
    import os
    return os.environ.get("APPDATA", "")


def _firefox_profile_root():
    """Firefox lives under %APPDATA%/Mozilla/Firefox/Profiles/<profile>."""
    root = Path(_appdata()) / "Mozilla" / "Firefox" / "Profiles"
    return root if root.is_dir() else None


def _chromium_history_db(browser):
    """Yield every Chromium profile's History file for the given browser record.

    Each browser holds a config LIST of candidate profile roots (classic vs.
    Store/UWP install); the first root that exists wins, and missing ones are
    silently skipped. Never raises.
    """
    _name, _engine, rel_roots = known_browsers().get(browser.get("proc_name", ""), ("", "", []))
    if not rel_roots:
        return
    for rel_root in rel_roots:
        base = Path(_localappdata()) / rel_root
        if not base.is_dir():
            continue
        try:
            children = sorted(base.iterdir())
        except OSError as exc:
            log.debug("iterating %s failed: %s", base, exc)
            continue
        for candidate in children:
            try:
                h = candidate / "History"
                if h.is_file():
                    yield candidate.name, h
            except OSError:
                continue
        # Stop after scanning the first existing candidate root.
        break


def _firefox_history_db(firefox_record):
    """Yield every Firefox profile's places.sqlite."""
    root = _firefox_profile_root()
    if root is None:
        return
    try:
        for profile in sorted(root.iterdir()):
            if profile.is_dir():
                db = profile / "places.sqlite"
                if db.is_file():
                    yield profile.name, db
    except OSError as exc:
        log.debug("firefox profile walk failed: %s", exc)


def _copy_locked(path):
    """Copy a possibly-locked SQLite file to a temp location; return Path or None."""
    try:
        tmpdir = Path(tempfile.mkdtemp(prefix="feluda_browser_"))
        tmp = tmpdir / path.name
        shutil.copy2(path, tmp)
        return tmp
    except (OSError, shutil.Error) as exc:
        log.debug("copy of %s failed: %s", path, exc)
        return None


def _read_history_db(path, sql, max_rows):
    """Run a one-shot read against a (temp) copy of a browser SQLite DB."""
    tmp = _copy_locked(path)
    if tmp is None:
        return []
    try:
        with closing(sqlite3.connect(str(tmp))) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, (int(max_rows),)).fetchall()]
    except sqlite3.Error as exc:
        log.debug("read of %s failed: %s", path, exc)
        return []
    finally:
        try:
            shutil.rmtree(tmp.parent, ignore_errors=True)
        except OSError:
            pass


def extract_tabs(browser, max_rows=None):
    """Return recent-URL records for one browser record from detect_running_browsers.

    Phase 1: every record is marked is_live_tab=False (recent history).
    Never raises — any per-browser failure is logged and yields [].
    """
    if max_rows is None:
        max_rows = settings().get("browser", {}).get("max_history_rows_per_profile", 500)

    engine = browser.get("engine")
    out = []
    try:
        if engine == "chromium":
            for _profile_name, hist_db in _chromium_history_db(browser) or []:
                rows = _read_history_db(hist_db, _CHROMIUM_HISTORY_SQL, max_rows)
                for r in rows:
                    out.append({
                        "browser_name": browser["browser_name"],
                        "pid": browser["pid"],
                        "tab_url": r.get("url", ""),
                        "tab_title": r.get("title", "") or "",
                        "is_live_tab": False,
                        "detected_at": utc_now_iso(),
                    })
        elif engine == "gecko":
            for _profile_name, db in _firefox_history_db(browser) or []:
                rows = _read_history_db(db, _FIREFOX_HISTORY_SQL, max_rows)
                for r in rows:
                    out.append({
                        "browser_name": browser["browser_name"],
                        "pid": browser["pid"],
                        "tab_url": r.get("url", ""),
                        "tab_title": r.get("title", "") or "",
                        "is_live_tab": False,
                        "detected_at": utc_now_iso(),
                    })
        else:
            log.debug("no extractor for engine %r", engine)
    except Exception as exc:  # one browser must never stop the others
        log.error("extract_tabs(%s) failed: %s", browser.get("browser_name"), exc)
        return []
    return out


def extract_all_tabs(browsers=None, max_rows=None):
    """Return URL records for every running browser (or the given list)."""
    if browsers is None:
        browsers = detect_running_browsers()
    all_records = []
    for b in browsers:
        all_records.extend(extract_tabs(b, max_rows=max_rows))
    log.info("extracted %d url records from %d browsers", len(all_records), len(browsers))
    return all_records


# ---------------------------------------------------------------------------
# Phase-2 seams (intentionally stubbed for the follow-up cert/VT phase)
# ---------------------------------------------------------------------------

def _chromium_live_tabs(browser):  # pragma: no cover - Phase 2
    """Try CDP live-tab extraction for Chromium browsers started with
    --remote-debugging-port. Requires the `pychrome` or `pyppeteer` extra and
    must gracefully no-op when the port isn't open or the dep is missing.
    """
    return []


def _firefox_live_tabs(browser):  # pragma: no cover - Phase 2
    """Try recovery.jsonlz4 under sessionstore-backups (needs the `lz4` extra)
    to fetch genuinely-open tabs; must gracefully no-op without the dep.
    """
    return []
