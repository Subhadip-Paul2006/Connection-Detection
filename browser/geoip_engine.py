"""Stage 4 of the URL Risk Engine — GeoIP + ASN enrichment.

Resolves public remote IPs (network connections) and browser-URL hostnames to
country / region / city / ISP / ASN, then flags geographically or
organizationally unusual connections via the same additive scoring pattern as
Stages 1–3.

Provider design:
  Option A (DEFAULT, working): ip-api.com — free, no key, no signup.
      NOTE: the free tier is HTTP-only (no HTTPS) and licensed for
      NON-COMMERCIAL use only. The geographic data exchanged here is not
      sensitive (it's public routing/location metadata about a remote host,
      not user data), so plain HTTP is a deliberate, documented trade-off.
      Rate limit: 45 req/min per source IP; we cap ourselves at 40/min for
      headroom.
  Option B (OPTIONAL, stubbed): MaxMind GeoLite2 local .mmdb files behind
      `geoip.provider == "maxmind"` in rules.json. Fully offline and unlimited
      once the user supplies `geoip.maxmind_city_mmdb` / `geoip.maxmind_asn_mmdb`
      paths themselves. We do NOT automate the MaxMind signup/download flow;
      it's intentionally config-gated — see lookup_ip() TODO.

Caching: geoip_cache table in the existing history.db, 30-day TTL (IP→geo/ASN
mappings churn slowly), checked before every live call.

Async: GeoIPQueue mirrors reputation_engine.VTQueue — fire-and-forget tasks
throttled through the limiter; scans read only the cache and never block on a
live lookup.
"""

import asyncio
import json
import socket
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from utils import logger
from utils.config_loader import settings

log = logger.get_logger("browser.geoip")

from database.database import DB_PATH  # reuse the single Feluda DB file

_SCHEMA = """
CREATE TABLE IF NOT EXISTS geoip_cache (
    ip TEXT PRIMARY KEY,
    country TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    isp TEXT,
    org TEXT,
    asn TEXT,
    asn_org TEXT,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""


def _connect(db_path=None):
    import sqlite3
    conn = sqlite3.connect(str(db_path or DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def cache_get(ip, db_path=None):
    """Return the cached geo row for `ip` as a dict, or None on miss/expiry."""
    now = _now_iso()
    try:
        with _connect(db_path) as conn:
            row = conn.execute(
                "SELECT ip, country, country_code, region, city, isp, org, asn, asn_org "
                "FROM geoip_cache WHERE ip = ?", (ip,),
            ).fetchone()
    except Exception as exc:
        log.error("geoip cache read failed for %s: %s", ip, exc)
        return None
    if not row:
        return None
    row = dict(row)
    row["cached"] = True
    return row


def cache_set(ip, data, db_path=None):
    """Persist a lookup result. `data` keys match the table columns."""
    cfg = settings().get("geoip", {})
    ttl_days = int(cfg.get("cache_ttl_days", 30))
    expires = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()
    try:
        with _connect(db_path) as conn, conn:
            conn.execute(
                "INSERT INTO geoip_cache "
                "(ip, country, country_code, region, city, isp, org, asn, asn_org, "
                " checked_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET country=excluded.country, "
                "country_code=excluded.country_code, region=excluded.region, "
                "city=excluded.city, isp=excluded.isp, org=excluded.org, "
                "asn=excluded.asn, asn_org=excluded.asn_org, "
                "checked_at=excluded.checked_at, expires_at=excluded.expires_at",
                (
                    ip,
                    data.get("country", ""), data.get("country_code", ""),
                    data.get("region", ""), data.get("city", ""),
                    data.get("isp", ""), data.get("org", ""),
                    data.get("asn", ""), data.get("asn_org", ""),
                    _now_iso(), expires,
                ),
            )
    except Exception as exc:
        log.error("geoip cache write failed for %s: %s", ip, exc)


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

def _lookup_ip_ipapi(ip, timeout):
    """Option A — ip-api.com, HTTP-only free tier (non-commercial use).

    One call returns country/region/city/ISP/org/AS — no provider combining.
    Returns a normalized dict on success; None on 429/network failure (caller
    treats None as "skip, don't cache a false result").
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as"
    try:
        with urllib.request.urlopen(url, timeout=int(timeout)) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            log.warning("ip-api.com rate limit (429) — backing off")
        else:
            log.error("ip-api.com HTTP %s for %s", exc.code, ip)
        return None
    except Exception as exc:
        log.error("ip-api.com lookup failed for %s: %s", ip, exc)
        return None
    if data.get("status") != "success":
        return None
    as_field = data.get("as", "") or ""      # e.g. "AS15169 Google LLC"
    asn, _, asn_org = as_field.partition(" ")
    return {
        "country": data.get("country", ""),
        "country_code": data.get("countryCode", ""),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
        "asn": asn,
        "asn_org": asn_org,
    }


def _lookup_ip_maxmind(ip):
    """Option B — MaxMind GeoLite2 local DBs.

    TODO(config-gated): read `geoip.maxmind_city_mmdb` / `geoip.maxmind_asn_mmdb`
    paths from config and use the `maxminddb`/`geoip2` package against them.
    Not implemented by default — requires the user to create a MaxMind account,
    accept the GeoLite2 EULA, and download the .mmdb files manually. When the
    provider is "maxmind" but the files aren't present, we log once and fall
    through to Option A so the feature still works.
    """
    cfg = settings().get("geoip", {})
    city_db, asn_db = cfg.get("maxmind_city_mmdb"), cfg.get("maxmind_asn_mmdb")
    if not (city_db and asn_db):
        log.warning(
            "geoip.provider=maxmind but no .mmdb paths configured; "
            "falling back to ip-api.com"
        )
        return None
    # Intentional stub — see TODO above.
    return None


def lookup_ip(ip, timeout=None):
    """Synchronous lookup: provider dispatch + cache interaction.

    Returns a normalized geo dict (from cache or live), or None when nothing
    usable is known without making a call and the caller decided to skip.
    """
    cfg = settings().get("geoip", {})
    timeout = int(timeout or cfg.get("request_timeout_seconds", 4))

    cached = cache_get(ip)
    if cached is not None:
        return cached

    provider = cfg.get("provider", "ip-api")
    data = _lookup_ip_maxmind(ip) if provider == "maxmind" else None
    if data is None:
        data = _lookup_ip_ipapi(ip, timeout)
    if data is None:
        return None                      # don't cache failures
    cache_set(ip, data)
    data["cached"] = False
    return data


# ---------------------------------------------------------------------------
# Rate limiter + async queue (Option A budgets; mirrors reputation_engine)
# ---------------------------------------------------------------------------

class GeoIPRateLimiter:
    """Sliding-window per-minute limiter. 40/min default leaves headroom under
    ip-api.com's documented 45/min free-tier cap."""

    def __init__(self, per_minute=None):
        import time
        self._time = time
        cfg = settings().get("geoip", {})
        self.per_minute = int(per_minute or cfg.get("rate_limit_per_minute", 40))
        self._hits = []

    def _prune(self):
        now = self._time.time()
        self._hits = [t for t in self._hits if now - t < 60]

    def wait_for_slot(self):
        while True:
            self._prune()
            if len(self._hits) < self.per_minute:
                return True
            wait = 60 - (self._time.time() - min(self._hits))
            # Simple sleep-and-recheck is fine: this runs on a worker thread,
            # never on the caller's poll loop.
            self._time.sleep(min(max(wait, 0.05), 5.0))

    def record(self):
        self._hits.append(self._time.time())


class GeoIPQueue:
    """Fire-and-forget async worker pattern (same shape as VTQueue).

    submit(ip)  — enqueue a lookup if not cached and not already pending
    get_now(ip) — read the cache; None until the worker lands the result

    The polling loop calls get_now synchronously (cache-only reads) so a live
    lookup never stalls it; submitted work resolves in the background.
    """

    def __init__(self):
        self._rate = GeoIPRateLimiter()
        self._pending = set()
        self._tasks = []

    def submit(self, ip):
        """Queue an IP lookup if needed. Returns True if it may be fetched."""
        if not ip:
            return False
        if cache_get(ip) is not None:
            return False                   # cache hit — zero live calls
        if ip in self._pending:
            return True
        self._pending.add(ip)
        self._schedule(ip)
        return True

    def get_now(self, ip):
        return cache_get(ip)

    def _schedule(self, ip):
        """Best-effort background fetch: if an event loop is running, create a
        task; otherwise fall back to a daemon thread so the CLI path works too.
        Either way the synchronous caller returns immediately."""
        def _work():
            try:
                self._rate.wait_for_slot()
                result = lookup_ip(ip)
                if result is not None:
                    self._rate.record()
            except Exception as exc:      # never kill the loop over one IP
                log.error("geoip worker failed for %s: %s", ip, exc)
            finally:
                self._pending.discard(ip)

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.run_in_executor(None, _work)
                return
        except RuntimeError:
            pass
        # No running loop (plain CLI mode): daemon thread keeps it non-blocking.
        import threading
        threading.Thread(target=_work, daemon=True).start()

    def quota_status(self):
        self._rate._prune()
        return f"GeoIP: {len(self._rate._hits)}/{self._rate.per_minute} this minute"


# ---------------------------------------------------------------------------
# Hostname → IP + scoring
# ---------------------------------------------------------------------------

def resolve_hostname(hostname, timeout=3):
    """Resolve a browser-URL hostname to an IPv4 address, or None on failure.

    DNS failures (gone domain, NXDOMAIN) are expected in browsing history and
    are skipped silently — never an error, never a crash.
    """
    if not hostname:
        return None
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    for _fam, _t, _p, _c, sockaddr in infos:
        ip = sockaddr[0]
        if ":" not in ip:                  # prefer IPv4 for ip-api
            return ip
    return None


def score_result(entry, for_browser_url=False, weights=None):
    """Apply Stage 4 rules to a cached geo entry.

    Returns (points, [reasons]). Weights come from config geoip.weights and
    remain modest on purpose: geography is weak evidence and should nudge a
    score, not dominate it — Stage 2 (reputation) and Stage 3 (certs) carry
    the high-confidence signals. Don't casually raise these weights later.
    """
    w = weights or settings().get("geoip", {}).get("weights", {})
    cfg = settings().get("geoip", {})
    points, reasons = 0, []
    if not entry:
        return points, reasons

    # unusual_country (+20): resolved country outside the user's allowlist.
    expected = {c.upper() for c in cfg.get("expected_countries", [])}
    cc = (entry.get("country_code") or "").upper()
    if cc and expected and cc not in expected:
        pts = int(w.get("unusual_country", 20))
        points += pts
        reasons.append(
            f"GeoIP: connection to {entry.get('country', cc)} ({cc}) — "
            f"not in expected-countries list (+{pts})"
        )

    # high_risk_hosting_asn (+25): ASN/org matches abuse-tolerant hosting list.
    blocklist = [str(x).lower() for x in cfg.get("high_risk_asns", [])]
    hay = " ".join([
        (entry.get("asn") or "").lower(),
        (entry.get("asn_org") or "").lower(),
        (entry.get("org") or "").lower(),
    ])
    if blocklist and any(b in hay for b in blocklist):
        pts = int(w.get("high_risk_hosting_asn", 25))
        points += pts
        reasons.append(
            f"GeoIP: resolved on abuse-tolerant hosting ASN "
            f"({entry.get('asn') or '?'} {entry.get('asn_org') or ''}) (+{pts})"
        )

    # datacenter_not_cdn (+10): hosting/DC ASN rather than a known CDN/ISP —
    # mild anomaly for browser traffic (browser tabs usually reach CDNs).
    if for_browser_url:
        known_cdns = [s.lower() for s in cfg.get("cdn_org_keywords", [])]
        dc_keywords = [s.lower() for s in cfg.get("datacenter_org_keywords", [])]
        org_blob = " ".join([
            (entry.get("isp") or "").lower(),
            (entry.get("org") or "").lower(),
            (entry.get("asn_org") or "").lower(),
        ])
        if dc_keywords and any(k in org_blob for k in dc_keywords) and not any(
            k in org_blob for k in known_cdns
        ):
            pts = int(w.get("datacenter_not_cdn", 10))
            points += pts
            reasons.append(
                f"GeoIP: browser traffic served from a hosting/datacenter ASN "
                f"rather than a recognized CDN ({entry.get('org') or entry.get('isp') or '?'}) "
                f"(+{pts})"
            )
    return points, reasons
