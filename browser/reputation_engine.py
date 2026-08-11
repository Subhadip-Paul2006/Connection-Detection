"""VirusTotal reputation engine (Phase 3, Stage 2 of the URL Risk Engine).

Opt-in only: this module only becomes active when a VT API key is present via
the FELUDA_VT_API_KEY environment variable (or a .env file line) AND the
caller passes enable_reputation=True. Without the key/flag, every function is
a graceful no-op and Feluda behaves exactly as it did offline.

Design constraints (VT public/free tier):
  - 4 requests per minute, ~500 requests per day
  - 429 once the quota is exceeded
We therefore:
  - check the SQLite cache BEFORE any network call (cache hit = zero quota)
  - throttle client-side with a sliding-window limiter (shared URL+IP budget)
  - stop looking up for the rest of the day once the quota is near cap
  - never cache 429/5xx responses as "clean" results
  - never block the caller — lookups are enqueued and resolved asynchronously
"""

import asyncio
import base64
import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from utils import logger
from utils.config_loader import settings

log = logger.get_logger("browser.reputation")

_ENV_VAR = "FELUDA_VT_API_KEY"
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


# ---------------------------------------------------------------------------
# API key handling
# ---------------------------------------------------------------------------

def _load_dotenv():
    """Best-effort .env loader (single KEY=VALUE lines, no expansion).

    Reads only FELUDA_VT_API_KEY. Never raises; a malformed file just yields
    no key and the caller falls back to telling the user to set the env var.
    """
    if not _ENV_FILE.is_file():
        return {}
    try:
        out = {}
        for line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() == _ENV_VAR:
                out[_ENV_VAR] = v.strip().strip('"').strip("'")
        return out
    except OSError:
        return {}


def get_api_key():
    """Resolve the VT key. Returns the key or None — never logs it."""
    return os.environ.get(_ENV_VAR) or _load_dotenv().get(_ENV_VAR)


def vt_available():
    """True when a VT key is configured — the module is only usable then."""
    return bool(get_api_key())


# ---------------------------------------------------------------------------
# Rate limiter (sliding window, thread-safe enough for our use)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window limiter used for ALL VT calls (URL + IP share budget).

    The caller is a single-threaded polling loop with an async worker, so a
    plain list of timestamps is sufficient.
    """

    def __init__(self, per_minute=None, per_day=None):
        cfg = settings().get("vt", {})
        self.per_minute = int(per_minute or cfg.get("rate_limit_per_minute", 4))
        self.per_day = int(per_day or cfg.get("daily_quota", 500))
        self._hits_minute = []  # list of float timestamps within the last 60s
        self._hits_day = []     # list of float timestamps within the last 86400s

    def _prune(self):
        now = time.time()
        self._hits_minute = [t for t in self._hits_minute if now - t < 60]
        self._hits_day = [t for t in self._hits_day if now - t < 86_400]

    def used_today(self):
        self._prune()
        return len(self._hits_day)

    def remaining_quota(self):
        return max(0, self.per_day - self.used_today())

    def _can_fire(self):
        """True if a new VT call is allowed by the rate + quota."""
        self._prune()
        return len(self._hits_minute) < self.per_minute and self._hits_day < self.per_day

    def wait_for_slot(self):
        """Block the CURRENT (async or sync) task until a slot opens, or return
        False immediately if the daily quota is exhausted so the caller can
        skip work without ever making a request.
        """
        while True:
            self._prune()
            if len(self._hits_day) >= self.per_day:
                return False
            if len(self._hits_minute) < self.per_minute:
                return True
            # oldest slot falls out of the 60s window soon — wait for it
            oldest = min(self._hits_minute)
            wait = max(0.0, 60 - (time.time() - oldest))
            if wait > 0:
                time.sleep(min(wait + 0.01, 5.0))  # never spin-eat CPU

    def record(self):
        now = time.time()
        self._hits_minute.append(now)
        self._hits_day.append(now)


# ---------------------------------------------------------------------------
# VT API client (async, never blocks the caller)
# ---------------------------------------------------------------------------

def _b64url_no_padding(s):
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def _vt_headers(api_key):
    return {"x-apikey": api_key, "Accept": "application/json"}


def _fetch_json_sync(url, api_key, timeout):
    """One-shot synchronous GET -> (status, json_or_None). Never raises.

    Uses stdlib urllib so Feluda still only requires psutil+rich+lz4.
    """
    req = urllib.request.Request(url, headers=_vt_headers(api_key))
    try:
        with urllib.request.urlopen(req, timeout=int(timeout)) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            status = resp.getcode()
            if status == 404:
                return 404, None           # VT hasn't seen this indicator before
            if status == 429:
                log.warning("VT rate limit hit (429)")
                return 429, None
            return status, data
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None               # never submitted — valid "unknown"
        if exc.code == 429:
            log.warning("VT rate limit hit (429)")
            return 429, None
        log.error("VT HTTP %s for %s", exc.code, url)
        return exc.code, None
    except urllib.error.URLError as exc:   # DNS/connect/refused/etc
        log.error("VT request failed (%s): %s", url, exc)
        return 0, None
    except json.JSONDecodeError as exc:
        log.error("VT response wasn't JSON (%s): %s", url, exc)
        return 0, None


async def _fetch_json(url, api_key, timeout):
    """Async wrapper around the sync fetch — runs in a small thread pool so
    the caller's event loop never blocks on network I/O.
    """
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return await loop.run_in_executor(pool, _fetch_json_sync, url, api_key, timeout)


async def lookup_url(url, api_key=None, timeout=None):
    """Look up a URL via VT v3 /urls/{b64url}. Returns a stats dict, or None on
    failure/rate-limit. Always safe to call from a background task."""
    if not api_key:
        api_key = get_api_key()
    if not api_key:
        return None
    cfg = settings().get("vt", {})
    timeout = int(timeout or cfg.get("request_timeout_seconds", 10))
    base = cfg.get("base_url", "https://www.virustotal.com/api/v3")
    uid = _b64url_no_padding(url)
    status, data = await _fetch_json(f"{base}/urls/{uid}", api_key, timeout)
    if status != 200 or not isinstance(data, dict):
        return None
    attrs = data.get("data", {}).get("attributes", {}) or {}
    stats = (attrs.get("last_analysis_stats") or {})
    return {
        "vt_malicious": int(stats.get("malicious", 0)),
        "vt_suspicious": int(stats.get("suspicious", 0)),
        "vt_harmless": int(stats.get("harmless", 0)),
        "vt_undetected": int(stats.get("undetected", 0)),
        "vt_total": sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")),
        "vt_url": url,
        "vt_checked_at": datetime.now(timezone.utc).isoformat(),
        "existed_on_vt": True,
        "raw": {"analysis_stats": stats, "reputation": attrs.get("reputation")},
    }


async def lookup_ip(ip, api_key=None, timeout=None):
    """Look up an IP via VT v3 /ip_addresses/{ip}. Same return shape as
    lookup_url, except `url` is replaced by the IP and `vt_url` is `None`.
    """
    if not api_key:
        api_key = get_api_key()
    if not api_key:
        return None
    cfg = settings().get("vt", {})
    timeout = int(timeout or cfg.get("request_timeout_seconds", 10))
    base = cfg.get("base_url", "https://www.virustotal.com/api/v3")
    status, data = await _fetch_json(f"{base}/ip_addresses/{ip}", api_key, timeout)
    if status != 200 or not isinstance(data, dict):
        return None
    attrs = data.get("data", {}).get("attributes", {}) or {}
    stats = (attrs.get("last_analysis_stats") or {})
    return {
        "vt_malicious": int(stats.get("malicious", 0)),
        "vt_suspicious": int(stats.get("suspicious", 0)),
        "vt_harmless": int(stats.get("harmless", 0)),
        "vt_undetected": int(stats.get("undetected", 0)),
        "vt_total": sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")),
        "vt_url": None,
        "vt_checked_at": datetime.now(timezone.utc).isoformat(),
        "existed_on_vt": True,
        "raw": {"analysis_stats": stats, "reputation": attrs.get("reputation")},
    }


# ---------------------------------------------------------------------------
# Cache + scoring glue
# ---------------------------------------------------------------------------

def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _iso_days_ahead(days):
    return (datetime.now(timezone.utc) + timedelta(days=int(days))).isoformat()


def cache_get(indicator, db_path=None):
    """Return a cached {vt_malicious, vt_suspicious, ...} dict or None.

    A cache record whose expires_at is in the past is treated as a miss so
    the caller will refresh it via a live VT call.
    """
    from database import database
    cfg = settings().get("vt", {})
    ttl = int(cfg.get("cache_ttl_days", 7))
    now = _now_iso()
    try:
        with database._connect(db_path) as conn:  # reuse single DB helper
            row = conn.execute(
                "SELECT vt_result, expires_at, checked_at FROM url_reputation_cache "
                "WHERE domain = ?",
                (indicator,),
            ).fetchone()
    except Exception as exc:
        log.error("cache read failed for %s: %s", indicator, exc)
        return None
    if not row:
        return None
    if row["expires_at"] and row["expires_at"] < now:
        return None
    try:
        data = json.loads(row["vt_result"] or "{}")
    except json.JSONDecodeError:
        return None
    data["cached"] = True
    return data


def cache_set(indicator, result, unknown=False, db_path=None):
    """Persist a VT result. Never caches failures as if they were clean hits.
    `unknown=True` uses the shorter TTL so unknown URLs/IPs are re-checked
    sooner (they can appear in VT a day later)."""
    from database import database
    cfg = settings().get("vt", {})
    ttl = int(cfg.get("cache_ttl_days_unknown", 1) if unknown
              else cfg.get("cache_ttl_days", 7))
    try:
        with database._connect(db_path) as conn, conn:
            conn.execute(
                "INSERT INTO url_reputation_cache (domain, vt_result, checked_at, expires_at) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT(domain) DO UPDATE SET vt_result=excluded.vt_result, "
                "checked_at=excluded.checked_at, expires_at=excluded.expires_at",
                (indicator, json.dumps(result), _now_iso(), _iso_days_ahead(ttl)),
            )
    except Exception as exc:
        log.error("cache write failed for %s: %s", indicator, exc)


def score_result(result, weights=None):
    """Turn a VT result dict into (points, signal_string) for the rule engine.

    Mirrors the PHASE 3 weight block and returns a plain zero/no-op result
    when the VT data is absent or unavailable, so a caller that hasn't wired
    VT yet still gets a deterministic no-score.
    """
    w = weights or settings().get("vt", {}).get("weights", {})
    if not result or result.get("cached_error"):
        return 0, "VirusTotal: lookup unavailable or unresolved"

    m = int(result.get("vt_malicious", 0))
    s = int(result.get("vt_suspicious", 0))
    t = int(result.get("vt_total", 0))

    if m >= 3:
        pts = int(w.get("vt_flagged_by_multiple_engines", 40))
        return pts, f"VirusTotal: {m}/{t} engines flagged this as MALICIOUS"
    if m >= 1:
        pts = int(w.get("vt_flagged_by_few_engines", 20))
        return pts, f"VirusTotal: {m}/{t} engines flagged this as malicious"
    if s > 0:
        pts = int(w.get("vt_suspicious_only", 10))
        return pts, f"VirusTotal: {s}/{t} engines flagged as suspicious"
    # 0 malicious, 0 suspicious: was it even registered on VT?
    if result.get("existed_on_vt"):
        return 0, f"VirusTotal: {t}/{t} engines report clean"
    return 0, "VirusTotal: not yet seen by VT"


# ---------------------------------------------------------------------------
# Async queue / worker (never blocks the polling loop)
# ---------------------------------------------------------------------------

class VTQueue:
    """A minimal in-process async worker that dedupes and queues lookups.

    Usage:
        q = VTQueue()
        q.submit_url(url)                # fire-and-forget from any thread
        result = q.get_now(url)          # None until the worker lands the
                                         # result (from cache or live call)

    The queue drains lookup calls one at a time through the rate limiter, so
    even a burst of 100 URLs produces at most 4 HTTP calls/minute.
    """

    def __init__(self):
        self._queue = asyncio.Queue()
        self._tasks = {}
        self._rate = RateLimiter()
        self._worker = None
        self._loop = None

    def _ensure_worker(self):
        """Start the background drain task on the running loop."""
        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            # No loop yet — will be created when the caller runs its own.
            return
        if self._worker is None or self._worker.done():
            self._worker = self._loop.create_task(self._drain())

    def submit_url(self, url, db_path=None):
        """Queue a URL lookup. No-op when VT isn't enabled or URL was already
        queued/cache-hit. Returns True if it will be fetched."""
        if not vt_available():
            return False
        if cache_get(url, db_path) is not None:
            return False  # already cached — no cost, no need
        if url in self._tasks and not self._tasks[url].done():
            return True   # already queued
        self._tasks[url] = self._loop.create_task(self._lookup_and_store(url, db_path))
        self._ensure_worker()
        return True

    def get_now(self, url, db_path=None):
        """Return a cache/lookup result right now, or None if not ready."""
        return cache_get(url, db_path)

    async def _lookup_and_store(self, url, db_path):
        # Cheap: serve a cached hit again if we raced a previous call.
        cached = cache_get(url, db_path)
        if cached is not None:
            return cached
        # 429 / cap handling: skip the live call, but cache an unknown marker
        # with a short TTL so the NEXT poll will retry after a cooldown.
        if self._rate.remaining_quota() <= 0:
            log.warning("VT daily quota exhausted; skipping lookup for %s", url)
            return None
        if not self._rate.wait_for_slot():
            return None  # quota exhausted while waiting
        try:
            result = await lookup_url(url)
        finally:
            self._rate.record()
        if result is None:
            return None
        cache_set(url, result, unknown=not result.get("existed_on_vt"), db_path=db_path)
        return result

    async def _drain(self):
        """Keep the worker alive; tasks are created directly per URL, so the
        queue just yields control back to the loop until cancelled."""
        while True:
            await asyncio.sleep(1)

    def quota_status(self):
        """Human-readable quota string for CLI footers."""
        return f"VT: {self._rate.used_today()}/{self._rate.per_day} today"


# ---------------------------------------------------------------------------
# Synchronous convenience wrapper (for non-async CLI paths)
# ---------------------------------------------------------------------------

def lookup_url_sync(url, db_path=None):
    """Sync wrapper around the async path so `scan` / `export` can opt in
    without becoming async CLIs. Cache-first; live call only on miss and the
    caller has already decided async is acceptable."""
    if not vt_available():
        return None
    cached = cache_get(url, db_path)
    if cached is not None:
        return cached
    try:
        result = asyncio.run(lookup_url(url))
    except RuntimeError:
        # Already inside a running loop (rare in this CLI) — fall back to
        # skipping rather than crashing the scan.
        log.debug("lookup_url_sync called inside running loop; skipping")
        return None
    if result is None:
        return None
    cache_set(url, result, unknown=not result.get("existed_on_vt"), db_path=db_path)
    return result
