"""Browser process detection + open-tab/recent-URL extraction (Phase 2).

Local-only, read-only: uses psutil.process_iter() to find running browser
processes and reads each browser's on-disk data via a temp copy, so locked
profile files never crash the polling loop and no browser state is mutated.

Output record shape (browser-agnostic — every extractor returns the same keys):
    {browser_name, pid, tab_url, tab_title, is_live_tab, detected_at}

Dispatch is config-driven: `extract_tabs()` looks up the browser's `method`
in _METHOD_DISPATCH and calls the registered extractor, so adding browser #N
is a config-only change (add to rules.json; add the extractor only if a new
method is actually required).

Methods implemented in Phase 2:
  chromium_history_fallback  — reads copies of the Chromium History SQLite DB
  firefox_session            — reading sessionstore-backups/recovery.jsonlz4
                               (mozLz4: 8-byte magic header + LZ4-compressed JSON),
                               falling back to places.sqlite if that session
                               file is missing or corrupt.
"""

import configparser
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

# Firefox places.sqlite: join moz_places with moz_historyvisits for recency,
# bounded; skip internal about:/chrome: pages that carry no security signal.
_FIREFOX_HISTORY_SQL = """
SELECT DISTINCT p.url, p.title, MAX(h.visit_date) AS last_visit
FROM moz_places p
JOIN moz_historyvisits h ON h.place_id = p.id
WHERE p.url NOT LIKE 'about:%'
  AND p.url NOT LIKE 'chrome://%'
  AND p.url NOT LIKE 'resource://%'
  AND p.url NOT LIKE 'view-source:%'
  AND p.url NOT LIKE 'moz-extension://%'
GROUP BY p.url
ORDER BY last_visit DESC
LIMIT ?
"""

# Session record shape must match detect_running_browsers's record exactly.
_BROWSER_REC_KEYS = ("browser_name", "engine", "method", "pid", "exe", "proc_name")


def known_browsers():
    """Config-driven map: process-name -> (display, engine, method, roots).

    Each root is a candidate path fragment resolved under an env var base
    (%LOCALAPPDATA% for Chromium classic installs AND Store/UWP packages,
    %APPDATA% for Firefox's Profiles tree — Mozilla's path convention).
    First existing candidate root wins for a given browser.
    """
    raw = settings().get("browser", {}).get("known_browsers", {})
    out = {}
    for proc_name, spec in raw.items():
        try:
            name, engine, method, roots = spec
        except (TypeError, ValueError) as exc:
            log.debug("bad browser config entry for %r: %r (%s)", proc_name, spec, exc)
            continue
            # tolerate older 3-tuple (display, engine, roots) shape from Phase 1
        if isinstance(roots, str):
            roots = [roots]
        # map the legacy engine to the new method vocabulary if `method` arrived empty
        if not method:
            method = "firefox_session" if engine == "gecko" else "chromium_history_fallback"
        out[proc_name.lower()] = (name, engine, method, roots or [])
    return out


# Keep this for any legacy Phase-1 callers; they're few and cheap to retain.
def detect_running_browsers():
    """Return one dict per distinct browser-kind currently running at least one
    process.

    Chrome/Edge/Arc/Brave each spawn many helper processes sharing one exe and
    one profile dir; we keep the LOWEST pid per display name as representative
    (still satisfies 'map each browser process to PID and exe path').
    """
    known = known_browsers()
    best = {}
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
        display, engine, method, _roots = known[pname]
        rec = {
            "browser_name": display,
            "engine": engine,
            "method": method,
            "proc_name": pname,
            "pid": info.get("pid"),
            "exe": info.get("exe") or "",
        }
        kept = best.get(display)
        if kept is None or (rec["pid"] or 10**9) < (kept["pid"] or 10**9):
            best[display] = rec
    log.info("detected %d running browser kinds", len(best))
    return list(best.values())


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _appdata():
    import os
    return os.environ.get("APPDATA", "")


def _localappdata():
    import os
    return os.environ.get("LOCALAPPDATA", "")


def _copy_locked(path):
    """Copy a possibly-locked file into a temp dir; return the temp Path or None.

    Both Chromium's History DB and Firefox's places.sqlite lock hard while the
    browser is running, so every read goes through this indirection.
    """
    try:
        tmpdir = Path(tempfile.mkdtemp(prefix="feluda_browser_"))
        tmp = tmpdir / path.name
        shutil.copy2(path, tmp)
        return tmp
    except (OSError, shutil.Error) as exc:
        log.debug("copy of %s failed: %s", path, exc)
        return None


def _read_history_db(path, sql, max_rows):
    """Read a one-shot SELECT off a temp copy of a browser profile SQLite DB."""
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


def _profile_base_env(browser):
    """Firefox's profile lives under %APPDATA%; everything else under %LOCALAPPDATA%."""
    engine = (browser.get("engine") or "").lower()
    return _appdata() if engine == "gecko" else _localappdata()


# ---------------------------------------------------------------------------
# Chromium extraction (method = chromium_history_fallback)
# ---------------------------------------------------------------------------

def _chromium_profile_history_db(browser):
    """Iterate (profile_name, History_path) for a chromium browser record."""
    _name, _engine, _method, rel_roots = known_browsers().get(
        browser.get("proc_name", ""), ("", "", "", [])
    )
    if not rel_roots:
        return
    base_root = Path(_profile_base_env(browser))
    for rel_root in rel_roots:
        base = base_root / rel_root
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
        break  # scan only the first existing candidate root (most preferred)


def _extract_chromium_history_fallback(browser, max_rows):
    """Pull recent URLs from each Chromium profile's History DB."""
    out = []
    for _profile_name, hist_db in _chromium_profile_history_db(browser) or []:
        rows = _read_history_db(hist_db, _CHROMIUM_HISTORY_SQL, max_rows)
        for r in rows:
            out.append({
                "browser_name": browser["browser_name"],
                "pid": browser["pid"],
                "tab_url": r.get("url", ""),
                "tab_title": r.get("title", "") or "",
                "is_live_tab": False,   # History entries are "recent", not live tabs
                "detected_at": utc_now_iso(),
            })
    return out


# ---------------------------------------------------------------------------
# Firefox extraction (method = firefox_session)
# ---------------------------------------------------------------------------

def _resolve_firefox_profiles(browser):
    """Return the list of Firefox profile dirs to inspect, active profile first.

    Resolution order:
      1. profiles.ini [Install*] Default=N entry (the profile Firefox is actually using)
      2. fall back to every subdirectory under Profiles/ in deterministic order

    Never raises — on any failure returns an empty list so the poll loop just skips.
    """
    _name, _engine, _method, rel_roots = known_browsers().get(
        browser.get("proc_name", ""), ("", "", "", [])
    )
    if not rel_roots:
        return []
    root = Path(_appdata()) / rel_roots[0]
    profiles_ini = root / "profiles.ini"
    installs = root / "installs.ini"

    if not root.is_dir():
        return []
    try:
        cp = configparser.ConfigParser()
        # Both files exist on modern Firefox; installs.ini is the newer split
        # from profiles.ini, but Default=N inside an [Install*] section in
        # profiles.ini is still authoritative.
        cp.read(profiles_ini, encoding="utf-8")
    except Exception as exc:
        log.warning("profiles.ini unreadable (%s): %s", profiles_ini, exc)
        cp = None

    if cp is not None:
        for section in cp.sections():
            if not section.startswith("Install"):
                continue
            default = cp.get(section, "Default", fallback=None)
            if not default:
                continue
            prof = root / "Profiles" / default
            if prof.is_dir():
                return [prof]
        # No [Install*] section with a Default — use the first real profile.
        for section in cp.sections():
            if section.startswith("Profile"):
                path_str = cp.get(section, "Path", fallback=None)
                if not path_str:
                    continue
                prof = root / path_str
                if prof.is_dir():
                    return [prof]

    # profiles.ini missing/empty/malformed — fall back to scanning the tree.
    profiles_dir = root / "Profiles"
    if not profiles_dir.is_dir():
        return []
    try:
        return [p for p in sorted(profiles_dir.iterdir())
                if p.is_dir() and p.name not in (".", "..")]
    except OSError as exc:
        log.warning("profiles dir unreadable (%s): %s", profiles_dir, exc)
        return []


def _read_firefox_live_tabs(profile_path):
    """Read genuinely open tabs from sessionstore-backups/recovery.jsonlz4.

    Mozilla prepends an 8-byte magic header ("mozLz40\\0") and writes raw LZ4
    block-compressed JSON after it. The sequence is:
        strip 8 bytes -> lz4.block.decompress -> json.loads
    Any failure returns [] so the caller falls back to the history method.
    """
    session_dir = profile_path / "sessionstore-backups"
    candidate = session_dir / "recovery.jsonlz4"
    if not candidate.is_file():
        # recovery.baklz4 is an older snapshot; still worth a try before
        # dropping to places.sqlite.
        candidate = session_dir / "recovery.baklz4"
        if not candidate.is_file():
            return []
    try:
        payload = candidate.read_bytes()
        if payload[:8] == b"mozLz40\x00":
            payload = payload[8:]
        else:
            # Unexpected magic — don't risk corrupt data; treat as unavailable.
            log.warning("unexpected magic in %s; refusing to parse", candidate)
            return []
        import lz4.block  # local import: keeps Phase 1 fully working without it
        decompressed = lz4.block.decompress(payload)
        import json
        session = json.loads(decompressed.decode("utf-8"))
    except Exception as exc:
        log.warning("recovery.jsonlz4 decode failed (%s): %s", candidate, exc)
        return []

    tabs = []
    for window in session.get("windows", []):
        for tab in window.get("tabs", []):
            entries = tab.get("entries", [])
            if not entries:
                continue
            current = entries[-1]  # final entry is the current URL per tab
            url = current.get("url", "")
            title = current.get("title", "") or ""
            if not url or url.startswith(("about:", "chrome:", "resource:", "view-source:")):
                continue
            tabs.append({"url": url, "title": title})
    return tabs


def _extract_firefox_session(browser, max_rows):
    """Primary Firefox path — live tabs, falling back to history if needed.

    Never raises: a browser crashing, a missing profile folder, or a corrupt
    session file all yield an empty list from the corresponding helper, and
    history-fallback still runs.
    """
    profiles = _resolve_firefox_profiles(browser)
    if not profiles:
        log.info("no firefox profile found for pid %s — browser not installed or never run", browser.get("pid"))
        return []

    out = []
    for prof in profiles:
        live = _read_firefox_live_tabs(prof)
        if live:
            for t in live:
                out.append({
                    "browser_name": browser["browser_name"],
                    "pid": browser["pid"],
                    "tab_url": t["url"],
                    "tab_title": t["title"],
                    "is_live_tab": True,
                    "detected_at": utc_now_iso(),
                })
            continue  # this profile was live-extracted; don't double-dip history
        # Fallback: places.sqlite history for this profile, same as Chromium fallback.
        db = prof / "places.sqlite"
        if not db.is_file():
            log.debug("no places.sqlite in %s", prof)
            continue
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
    return out


_METHOD_DISPATCH = {
    "chromium_history_fallback": _extract_chromium_history_fallback,
    "firefox_session": _extract_firefox_session,
}


def extract_tabs(browser, max_rows=None):
    """Dispatch to the extractor registered for the browser's configured method.

    Phase 2 refactor: NO per-browser branching here — the method string in
    rules.json decides which extractor runs. One unknown method logs and
    no-ops, never crash.
    """
    if max_rows is None:
        max_rows = settings().get("browser", {}).get("max_history_rows_per_profile", 500)

    method = browser.get("method") or known_browsers().get(
        browser.get("proc_name", ""), (None, None, "", [])
    )[2]
    extractor = _METHOD_DISPATCH.get(method)
    if extractor is None:
        log.warning("no extractor for method %r (browser %r)", method, browser.get("proc_name"))
        return []
    try:
        return extractor(browser, max_rows)
    except Exception as exc:
        log.error("extract_tabs(%s via %s) failed: %s", browser.get("browser_name"), method, exc)
        return []


def extract_all_tabs(browsers=None, max_rows=None):
    """Return URL records for every running browser (or the given list).

    A browser failing never blocks the others — user-visible tab extraction
    continues even if one browser's profile files are corrupt.
    """
    if browsers is None:
        browsers = detect_running_browsers()
    all_records = []
    for b in browsers:
        all_records.extend(extract_tabs(b, max_rows=max_rows))
    log.info("extracted %d url records from %d browsers", len(all_records), len(browsers))
    return all_records
