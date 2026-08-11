"""Browser URL structural risk scoring engine (Phase 1).

Follows Feluda's existing analyzer/rules.py pattern: each check is an
independent, toggleable function returning (triggered, points, reason). The
aggregator sums points, clamps into [0, 100], and collects all reason
strings into a `signals` list.

Everything here is heuristic and fully OFFLINE — no network calls, no TLS
attempts. Certificate checks are Phase 2 (require toggled live network I/O)
and VirusTotal reputation is Phase 3 (async + cached + opt-in); explicit
stubs are kept at the bottom so they plug in without touching these rules.
"""

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from utils import logger
from utils.config_loader import settings

log = logger.get_logger("browser.url_risk")

_PCT_RE = re.compile(r"%(?:[0-9A-Fa-f]{2})")

# Unicode Script_Extensions values we treat as "latin-looking" vs. foreign.
_LATIN_SCRIPT_NAMES = frozenset({"latin", "common", "inherited"})


def _script_name_for_char(ch):
    """Return a coarse script bucket for a character, using Unicode names.

    'A' -> 'LATIN', 'α' -> 'GREEK', 'а' -> 'CYRILLIC'. Combining marks and
    neutral chars (digits, hyphens) map to 'COMMON'/'INHERITED' so they never
    break a purely-Latin domain on their own.
    """
    if ch.isdigit() or ch in "-.":
        return "common"
    try:
        name = unicodedata.name(ch, "")
    except (TypeError, ValueError):
        return "unknown"
    if not name:
        return "common"
    # first token: 'LATIN SMALL LETTER A' -> 'latin'
    return name.split()[0].lower()


def _decode_idn(host):
    """Decode a possibly-punycode host to Unicode for script analysis.

    `urlsplit` keeps 'xn--...' labels as ASCII; the *displayed* domain is the
    Unicode form, and that's what a homograph inherits its deception from, so
    we must judge the decoded version. On any failure, return the input.
    """
    if not host or "xn--" not in host:
        return host
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeEncodeError, UnicodeDecodeError):
        return host


def _registered_domain(host):
    """Cheap registrable-domain guess: last two '.'-separated labels.

    Adequate for typosquat scoring (rule-of-thumb TLD == short alpha label)
    without pulling in a full PSL parser.
    """
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def _levenshtein(a, b):
    """Small runtime DP Levenshtein (URLs are short enough that O(nm) is fine)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,       # deletion
                current[j - 1] + 1,    # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        previous = current
    return previous[-1]


# ---------------------------------------------------------------------------
# Individual structural rules (toggleable; always run first)
# ---------------------------------------------------------------------------

def check_homograph_idn(host):
    """Mixed-script domain — classic homograph/IDN phishing.

    Attackers register `xn--` (punycode) names whose glyphs look like a real
    brand (e.g., Cyrillic 'а' for Latin 'a'). A domain mixing scripts is a
    strong spoofing signal. Pure Latin/ASCII domains never trigger.
    """
    if not host or host.isascii():
        return False, 0, ""
    scripts = set()
    for ch in host:
        if ch in "-.":
            continue
        scripts.add(_script_name_for_char(ch))
    scripts -= {"common", "inherited", "unknown"}
    if len(scripts) > 1:
        return True, "homograph_idn", (
            f"Mixed-script domain '{host}' (scripts: {sorted(scripts)}) — "
            "possible IDN/homograph spoofing"
        )
    # Single foreign script is still a signal if the name tries to look latin.
    if scripts and "latin" not in scripts:
        return True, "homograph_idn", (
            f"Non-ASCII domain '{host}' (scripts: {sorted(scripts)}) — "
            "verify this is the domain you intended"
        )
    return False, 0, ""


def check_excessive_percent_encoding(url):
    """Lots of %XX escapes often hide the true URL from a quick glance."""
    count = len(_PCT_RE.findall(url))
    threshold = settings().get("url_risk", {}).get("percent_encoding_threshold", 6)
    if count >= threshold:
        return True, "excessive_percent_encoding", (
            f"URL contains {count} percent-encoded characters (>= {threshold}), "
            "common obfuscation pattern"
        )
    return False, 0, ""


def check_ip_literal(host):
    """Bare IP literal as host.

    A phishing URL like `http://93.184.1.10/login` skips DNS entirely;
    legitimate sites almost always use names. Private/loopback IPs are
    downgraded to informational since a LAN URL is usually fine.
    """
    if not host:
        return False, 0, ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False, 0, ""
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False, 0, ""
    return True, "ip_literal", (
        f"Host is an IP literal ({host}) instead of a domain name"
    )


def check_suspicious_tld(host):
    """Free / heavily-abused TLDs (config-driven list).

    Many URL-denylist feeds over-report these because they're cheap to
    register in bulk; presented strictly as a signal.
    """
    if not host:
        return False, 0, ""
    tld = host.rsplit(".", 1)[-1].lower()
    suspicious = {t.lower() for t in settings().get("url_risk", {}).get("suspicious_tlds", [])}
    if tld in suspicious:
        return True, "suspicious_tld", f"Domain uses often-abused free TLD '.{tld}'"
    return False, 0, ""


def check_typosquat(host):
    """Edit-distance-2 match against well-known brands on the registered domain.

    `paypa1.com` / `micros0ft-support.com` style lookalikes. Tiny hardcoded
    brand list by design (configurable via url_risk.typosquat_targets); the
    check runs on registrable-domain labels only to keep false positives low.
    Common URL shorteners (youtu.be, t.co, bit.ly…) are allow-listed so a
    shortener isn't flagged as its parent brand's typed-double.
    """
    cfg = settings().get("url_risk", {})
    reg = _registered_domain(host or "")
    shorteners = {s.lower() for s in cfg.get("typosquat_shortener_allowlist", [])}
    if reg.lower() in shorteners:
        return False, 0, ""
    label = reg.split(".", 1)[0].lower()
    if not label:
        return False, 0, ""
    targets = [t.lower() for t in cfg.get("typosquat_targets", [])]
    for target in targets:
        if label == target:
            return False, 0, ""   # exact brand = intended site
        if 0 < _levenshtein(label, target) <= 2:
            return True, "typosquat", (
                f"Domain label '{label}' is edit-distance <= 2 from well-known "
                f"brand '{target}' — possible typosquat"
            )
    return False, 0, ""


def check_url_length(url):
    """Very long URLs are common in phishing/tracking/abuse scenarios.

    Threshold is config-driven; this is a weak signal so it gets a low weight.
    """
    threshold = settings().get("url_risk", {}).get("length_outlier_threshold", 100)
    if len(url) >= threshold:
        return True, "url_length_outlier", (
            f"URL length {len(url)} chars exceeds {threshold} — often padding/obfuscation"
        )
    return False, 0, ""


# Evaluation order (deterministic signals list).
RULES = [
    check_homograph_idn,
    check_excessive_percent_encoding,
    check_ip_literal,
    check_suspicious_tld,
    check_typosquat,
    check_url_length,
]


def score_url(url):
    """Run every structural rule over `url` and return
    {risk_score, signals, rules_applied}.

    Each rule returns (triggered, weight_key_or_0, reason) so the caller can
    fold points additively and never confuse the penalty per rule with the
    weight name. Weights come from config/rules.json url_risk.weights.
    """
    weights = settings().get("url_risk", {}).get("weights", {})
    signals = []
    rules_applied = {}
    try:
        parts = urlsplit(url)
    except (ValueError, TypeError) as exc:
        log.debug("unparseable url %r: %s", url, exc)
        return {"risk_score": 0, "signals": [], "rules_applied": {}}

    host = (parts.hostname or "").lower()
    # Decode punycode once so script/typosquat checks see the real glyphs.
    display_host = _decode_idn(host)

    for rule in RULES:
        # host-based rules get the hostname; url-based rules get the raw url.
        # homograph/typosquat checks want the *decoded* (display) domain.
        if rule in (check_excessive_percent_encoding, check_url_length):
            arg = url
        elif rule in (check_homograph_idn, check_typosquat):
            arg = display_host
        else:
            arg = host
        try:
            triggered, key, reason = rule(arg)
        except Exception as exc:  # a bad rule must never crash the engine
            log.error("url rule %s failed: %s", rule.__name__, exc)
            continue
        if triggered and key:
            pts = int(weights.get(key, 0))
            rules_applied[key] = rules_applied.get(key, 0) + pts
            signals.append(f"{reason} (+{pts})")

    score = max(0, min(100, sum(rules_applied.values())))
    return {
        "risk_score": score,
        "signals": signals,
        "rules_applied": rules_applied,
    }


def check_reputation_vt(url):
    """Stage 2 heuristic: apply VirusTotal cache data as a scoring signal.

    Returns (triggered, key, reason) where key is the empty string when VT is
    disabled or no cached result exists, so callers can't accidentally skip
    structural scoring while waiting on a lookup. The scoring points come from
    vt.weights (separate from url_risk.weights until the response is in hand).
    """
    from browser import reputation_engine
    if not reputation_engine.vt_available():
        return False, "", ""
    cached = reputation_engine.cache_get(url)
    if cached is None:
        return False, "", ""
    pts, reason = reputation_engine.score_result(cached)
    # triggered=False lets the caller decide whether to apply pts without
    # double-counting; pts==0 means "we have a result, no penalty" (clean/unknown).
    return True, "vt_reputation", (reason, pts)


def score_records(records, use_reputation=False):
    """Score every detector record in-place. When use_reputation=True AND a
    cached VirusTotal result exists, fold its points into risk_score and
    append its signal to the existing reason list.

    - Never blocks: only cached results are applied here. Live VT lookups are
      enqueued separately by the caller.
    - Transparent: every record gets a `signals` list either way.
    """
    for rec in records:
        if not rec.get("tab_url"):
            rec.setdefault("risk_score", 0)
            rec.setdefault("signals", [])
            continue
        scored = score_url(rec["tab_url"])                 # structural (Stage 1)
        risk = scored["risk_score"]
        signals = list(scored["signals"])
        applied = dict(scored["rules_applied"])
        if use_reputation:
            from browser import reputation_engine
            cached = reputation_engine.cache_get(rec["tab_url"])
            if cached is not None:
                pts, reason = reputation_engine.score_result(cached)
                applied["vt_reputation"] = applied.get("vt_reputation", 0) + pts
                if reason:
                    signals.append(f"{reason} (+{pts})")
                risk = min(100, risk + pts)
                rec["vt"] = {k: cached.get(k) for k in
                             ("vt_malicious", "vt_suspicious", "vt_total", "cached")}
        rec["risk_score"] = risk
        rec["signals"] = signals
        rec["rules_applied"] = applied
    return records


# ---------------------------------------------------------------------------
# Phase-2 / Phase-3 seams (intentionally stubbed)
# ---------------------------------------------------------------------------

def check_certificate(url):  # pragma: no cover - Phase 2
    """TLS certificate heuristics (self-signed / expired / SAN mismatch).

    Requires consented network I/O against the URL's host, so it's a toggle —
    implemented in Phase 2 alongside the async worker pool.
    """
    return {"risk_score": 0, "signals": [], "rules_applied": {}}


def check_reputation(url):  # pragma: no cover - Phase 3
    """VirusTotal domain/URL lookup, async + SQLite-TTL cached.

    Must never block the polling loop; driven from an async helper with
    results persisted via browser/browser_db.py url_reputation_cache.
    """
    return {"risk_score": 0, "signals": [], "rules_applied": {}}
