"""Stage 3 of the URL Risk Engine — TLS certificate inspection.

Offline + no-key: the only network activity is a raw TLS handshake on TCP 443
to the site itself, the same bytes any browser sends when you visit it.
Everything is driven by config/rules.json "cert" weights and cached in
database/history.db (cert_checks) so repeat scans of the same hostname within
the TTL never redo the handshake.

Every rule returns (triggered: bool, weight_key: str, reason: str) — the
same contract as Stage 1 structural rules and Stage 2 reputation rules.
Unreachable hosts are cached briefly under the distinct "cert_unreachable"
pseudo-key so a network blip is never reported as a security finding.
"""

import json
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from utils import logger
from utils.config_loader import settings

log = logger.get_logger("browser.cert")

_DB_PATH = Path(__file__).resolve().parent.parent / "database" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cert_checks (
    hostname TEXT PRIMARY KEY,
    cert_flags TEXT NOT NULL DEFAULT '[]',
    risk_points INTEGER NOT NULL DEFAULT 0,
    unreachable INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""

# All rule weights live in config "cert" -> "weights" (spec §3).
_CERT_RULES = [
    "cert_expired",
    "cert_not_yet_valid",
    "cert_self_signed_or_untrusted",
    "cert_hostname_mismatch",
    "cert_short_validity",
    "cert_weak_signature",
    "no_https",
]

_WEAK_SIGALGS = {"sha1", "md5"}          # (openssl signature names, lowercased)
_SHORT_DAYS = 10                          # certs valid for under ~10 days
_UNREACHABLE_FLAG = "cert_unreachable"    # distinct from any real cert signal


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _iso_hours_ahead(hours):
    return (datetime.now(timezone.utc) + timedelta(hours=int(hours))).isoformat()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _connect(db_path=None):
    import sqlite3

    path = db_path or _DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def cache_get(hostname):
    """Return a cached cert analysis dict for `hostname`, or None on miss/expiry."""
    cfg = settings().get("cert", {})
    ttl_h = int(cfg.get("cache_ttl_hours", 24))
    now = datetime.now(timezone.utc)
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT cert_flags, risk_points, unreachable, expires_at "
                "FROM cert_checks WHERE hostname = ?",
                (hostname,),
            ).fetchone()
    except Exception as exc:
        log.error("cert cache read failed for %s: %s", hostname, exc)
        return None
    if not row:
        return None
    if row["expires_at"] and row["expires_at"] < now.isoformat():
        return None
    try:
        flags = json.loads(row["cert_flags"] or "[]")
    except json.JSONDecodeError:
        flags = []
    return {
        "hostname": hostname,
        "cert_flags": flags,
        "risk_points": int(row["risk_points"]),
        "unreachable": bool(row["unreachable"]),
        "cached": True,
    }


def cache_set(hostname, flags, points, unreachable=False, db_path=None):
    """Persist a cert analysis result. Unreachable hosts get the shorter TTL
    so they're re-attempted sooner — a temporary outage shouldn't be cached
    as if it were a trustworthy finding."""
    cfg = settings().get("cert", {})
    ttl_h = int(cfg.get("cache_ttl_hours_unreachable", 1) if unreachable
                else cfg.get("cache_ttl_hours", 24))
    try:
        with _connect(db_path) as conn, conn:
            conn.execute(
                "INSERT INTO cert_checks "
                "(hostname, cert_flags, risk_points, unreachable, checked_at, expires_at) "
                "VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(hostname) DO UPDATE SET "
                "cert_flags=excluded.cert_flags, risk_points=excluded.risk_points, "
                "unreachable=excluded.unreachable, checked_at=excluded.checked_at, "
                "expires_at=excluded.expires_at",
                (hostname, json.dumps(flags), int(points),
                 1 if unreachable else 0, _now_iso(), _iso_hours_ahead(ttl_h)),
            )
    except Exception as exc:
        log.error("cert cache write failed for %s: %s", hostname, exc)


# ---------------------------------------------------------------------------
# TLS handshake (stdlib only, caller-supplied timeout)
# ---------------------------------------------------------------------------

def fetch_certificate(hostname, timeout=None):
    """Connect on 443 + return the peer cert dict, or a structured error dict.

    Never raises; anything that isn't a perfect TLS handshake comes back as
    {"error": "...", "kind": "<classified>"} so rule engines can decide what
    to do with it (unreachable vs. security finding).
    """
    cfg = settings().get("cert", {})
    timeout = int(timeout or cfg.get("connect_timeout_seconds", 3))

    # A plain TCP connect first distinguishes "host is down / port closed"
    # from "TLS handshake worked but the cert is bad".
    try:
        with socket.create_connection((hostname, 443), timeout=timeout):
            pass
    except (OSError, socket.timeout):
        return {"error": f"no TCP connect on 443 for {hostname}",
                "kind": "unreachable"}

    # context without hostname checking (we want to *inspect* even bad certs —
    # Feluda's philosophy is reporting WHY it's risky, not just refusing to
    # look) but with full cert verification enabled so self-signed/untrusted
    # chains surface as a signal instead of crashing the scan.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # report SAN mismatch; don't silently reject

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                return {
                    "cert": cert,
                    "cipher": cipher,
                    "tls_version": tls.version(),
                    "server_hostname": hostname,
                }
    except ssl.SSLCertVerificationError as exc:
        # Untrusted chain / self-signed / expired — caller will translate the
        # exact verify_message into the right signal.
        return {"error": str(exc), "kind": "cert_verify_failed",
                "verify_code": exc.verify_code,
                "verify_message": exc.verify_message}
    except (socket.timeout, ssl.SSLError) as exc:
        return {"error": str(exc), "kind": "tls_failed"}
    except OSError as exc:                                # TCP-level issue
        return {"error": str(exc), "kind": "unreachable"}


# ---------------------------------------------------------------------------
# Rule implementations (spec §2) — pure analysis, no I/O
# ---------------------------------------------------------------------------

def _cert_expired(cert):
    """not_valid_after is in the past."""
    if not cert:
        return False, "", ""
    na = cert.get("notAfter")
    if not na:
        return False, "", ""
    try:
        from datetime import timezone as _tz
        na_dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_tz.utc)
        if na_dt < datetime.now(_tz.utc):
            return True, "cert_expired", f"Certificate expired at {na}"
    except (ValueError, TypeError):
        pass
    return False, "", ""


def _cert_not_yet_valid(cert):
    """not_valid_before is in the future — clock skew or freshly minted rogue cert."""
    if not cert:
        return False, "", ""
    nb = cert.get("notBefore")
    if not nb:
        return False, "", ""
    try:
        from datetime import timezone as _tz
        nb_dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_tz.utc)
        if nb_dt > datetime.now(_tz.utc):
            return True, "cert_not_yet_valid", f"Certificate not valid before {nb}"
    except (ValueError, TypeError):
        pass
    return False, "", ""


def _cert_self_signed_or_untrusted(cert, proto=None):
    """Issuer == subject, or the handshake failed verification.

    Self-signed certs are common on internal tooling; the heuristic is "no
    trusted root was presented", not "this is definitely phishing".
    """
    # Hard case: TLS verify already failed with "self signed"
    if proto and proto.get("kind") == "cert_verify_failed":
        msg = str(proto.get("verify_message", "")).lower()
        if "self-signed" in msg or "self signed" in msg:
            return True, "cert_self_signed_or_untrusted", \
                "Certificate is self-signed (no trusted root)"
        return True, "cert_self_signed_or_untrusted", \
            f"Certificate failed verification: {msg or 'unknown'}"
    # Soft case: handshake succeeded but issuer==subject (possible after
    # bypassing verification elsewhere)
    if cert:
        subj = cert.get("subject", [])
        iss = cert.get("issuer", [])
        subj_cn = _rfc4514_cn(subj)
        iss_cn = _rfc4514_cn(iss)
        if subj_cn and iss_cn and subj_cn == iss_cn:
            return True, "cert_self_signed_or_untrusted", (
                f"Certificate issuer == subject ('{subj_cn}') — likely self-signed"
            )
    return False, "", ""


def _rfc4514_cn(rdn_sequence):
    for rdn in rdn_sequence:
        for k, v in rdn:
            if k == "commonName":
                return v
    return ""


def _cert_hostname_mismatch(cert, hostname):
    """Host is not present in cert's SAN dNSName list."""
    if not cert or not hostname:
        return False, "", ""
    san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    if not san:
        return False, "", ""
    # exact or wildcard match: '*' covers exactly one leftmost label
    def _matches(name, pattern):
        name = name.lower()
        pattern = pattern.lower()
        if not pattern.startswith("*."):
            return name == pattern
        # Extract "*." suffix — the wildcard covers exactly one label, so
        # "*.example.com" matches "test.example.com" but NOT "a.b.example.com".
        wildcard_suffix = pattern[1:]          # ".example.com"
        return (
            name.endswith(wildcard_suffix) and
            name.count(".") == pattern.count(".")
        )
    for name in san:
        if _matches(hostname, name):
            return False, "", ""
    return True, "cert_hostname_mismatch", (
        f"Connected hostname '{hostname}' not in cert SAN list {san[:5]}"
    )


def _cert_short_validity(cert):
    """Total validity window under ~10 days — fast-rotation free ACME phishing pattern."""
    nb, na = (cert or {}).get("notBefore"), (cert or {}).get("notAfter")
    if not nb or not na:
        return False, "", ""
    try:
        from datetime import timezone as _tz
        nb_dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_tz.utc)
        na_dt = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_tz.utc)
        if (na_dt - nb_dt).days < _SHORT_DAYS:
            return True, "cert_short_validity", (
                f"Certificate validity window only {(na_dt - nb_dt).days} days "
                f"(< {_SHORT_DAYS}) — fast-rotation pattern"
            )
    except (ValueError, TypeError):
        pass
    return False, "", ""


def _cert_weak_signature(cert, tls_result):
    """Leaf cert uses a known-weak signature algorithm."""
    # ssl.getpeercert() doesn't include the signature algorithm, so we check
    # the negotiated cipher name for known-weak digests.
    if not tls_result or not tls_result.get("cipher"):
        return False, "", ""
    cipher_name = tls_result["cipher"][0] if tls_result["cipher"] else ""
    lower = cipher_name.lower()
    for weak in _WEAK_SIGALGS:
        if weak in lower:
            return True, "cert_weak_signature", (
                f"Weak signature/digest in negotiated cipher '{cipher_name}' ({weak})"
            )
    return False, "", ""


def _no_https(url):
    """URL scheme is plain HTTP — nothing to inspect, flag it as transparent info."""
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        if parts.scheme == "http":
            return True, "no_https", "URL is plain HTTP — no TLS certificate exists to inspect"
    except (ValueError, TypeError):
        pass
    return False, "", ""


# Map rule keys to their weight entries in config.
_RULE_TO_WEIGHT = {name: name for name in ["cert_expired", "cert_not_yet_valid",
                                            "cert_self_signed_or_untrusted",
                                            "cert_hostname_mismatch",
                                            "cert_short_validity", "cert_weak_signature"]}


def _evaluate(url, cert, proto):
    """Evaluate all cert rules. Returns (flags, points) — no I/O beyond the
    caller's own cert fetch. `proto == None` means http:// (no TLS possible).
    """
    if proto is None:
        # http:// — only the no_https rule can fire here
        t, _, r = _no_https(url)
        return (["no_https"] if t else [], 5 if t else 0), [{"key": "no_https", "reason": r}] if t else []

    checks = [
        _cert_expired(cert),
        _cert_not_yet_valid(cert),
        _cert_self_signed_or_untrusted(cert, proto),
        _cert_hostname_mismatch(cert, proto.get("server_hostname", "")),
        _cert_short_validity(cert),
        _cert_weak_signature(cert, proto),
    ]
    flags = [key for triggered, key, _ in checks if triggered]
    points = sum(_RULE_TO_WEIGHT.get(key, 0) and
                 settings().get("cert", {}).get("weights", {}).get(key, 0)
                 for key in flags)
    reasons = [reason for _, _, reason in checks if reason]
    return (flags, points), [{"key": k, "reason": r} for k, r in zip(
        [key for _, key, _ in checks if key], reasons)]


# ---------------------------------------------------------------------------
# Public API — used by url_risk_engine.score_records via cache_get / enqueue
# ---------------------------------------------------------------------------

def inspect_url(url, connect_now=False):
    """Return a cert analysis dict for a URL.

    Cache-first: a fresh cached row never causes a new TLS handshake.
    If connect_now=True AND the URL is https, we immediately perform a live
    handshake (used by interactive scan flows where the caller has explicitly
    opted in). When merely cached data exists, it's returned as-is.

    Returns None when: the URL is not https AND connect_now=False; or the host
    is unreachable and there is no cached result to report (nothing to say).
    """
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except (ValueError, TypeError):
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not host:
        return None

    if scheme == "http":
        t, _, reason = _no_https(url)
        if t:
            return {
                "hostname": host, "cert_flags": ["no_https"],
                "risk_points": settings().get("cert", {}).get("weights", {}).get("no_https", 5),
                "unreachable": False, "cached": False,
            }
        return None

    if scheme != "https":
        return None

    cached = cache_get(host)
    if cached is not None:
        return cached

    if not connect_now:
        return None

    result = fetch_certificate(host)
    if result.get("kind") == "unreachable":
        # Cache with short TTL so we re-attempt soon — a drop isn't a finding.
        cache_set(host, [], 0, unreachable=True)
        return {
            "hostname": host, "cert_flags": [], "risk_points": 0,
            "unreachable": True, "cached": False,
        }

    # A handshake that fails verification NEVER returns getpeercert() — the
    # cert had to be rejected at the TLS layer. We translate the verify
    # failure message into the highest-confidence signal we can name from it.
    # Successful handshakes are analysed against the returned peer dict.
    if result.get("kind") == "cert_verify_failed":
        msg = str(result.get("verify_message", "")).lower()
        flags, reasons, points = [], [], 0
        _wv = settings().get("cert", {}).get("weights", {})
        if "expired" in msg:
            flags.append("cert_expired")
            points += int(_wv.get("cert_expired", 25))
            reasons.append(f"Certificate failed verification: {msg}")
        if "self signed" in msg or "self-signed" in msg:
            flags.append("cert_self_signed_or_untrusted")
            points += int(_wv.get("cert_self_signed_or_untrusted", 35))
            reasons.append(f"Certificate is self-signed ({msg})")
        if not flags:
            # some other verify failure — surface the raw reason at the
            # generic self_signed_or_untrusted weight, per spec intent
            flags.append("cert_self_signed_or_untrusted")
            points += int(_wv.get("cert_self_signed_or_untrusted", 35))
            reasons.append(f"Certificate failed verification: {msg or 'unknown'}")
        cache_set(host, flags, points, unreachable=False)
        return {
            "hostname": host, "cert_flags": flags, "risk_points": points,
            "unreachable": False, "cached": False,
        }

    cert = result.get("cert")
    (flags, points), _reasons = _evaluate(url, cert, result)
    cache_set(host, flags, points, unreachable=False)
    return {
        "hostname": host, "cert_flags": flags, "risk_points": points,
        "unreachable": False, "cached": False,
    }


def inspect_many(urls, connect_now=True, max_workers=4):
    """Inspect many URLs non-blocking from the caller's perspective.

    Uses a ThreadPoolExecutor so the caller (browsers sweep or export) can
    enqueue handshakes and read whatever cache data already exists without
    blocking on any given host. Returns a dict of hostname -> inspect result.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    jobs = {}
    for u in urls:
        try:
            from urllib.parse import urlsplit
            host = (urlsplit(u).hostname or "").lower()
        except (ValueError, TypeError):
            continue
        if host:
            jobs.setdefault(host, u)   # one host => one handshake total
    results = {}
    with ThreadPoolExecutor(max_workers=int(max_workers)) as pool:
        futs = {pool.submit(inspect_url, u, True): h for h, u in jobs.items()}
        for fut in as_completed(futs, timeout=None):
            host = futs[fut]
            try:
                results[host] = fut.result()
            except Exception as exc:
                log.error("cert inspect failed for %s: %s", host, exc)
    return results
