"""Rule-based detection engine (Phase 10).

Additive, weighted rules. Every rule that fires contributes points AND a
human-readable reason string. There are no automatic verdicts here: the
output is a set of *signals* with explicit explanations. Weights and
thresholds come from config/rules.json so they can be tuned without code
changes.
"""

from collections import Counter
from urllib.parse import urlsplit

from utils import logger
from utils.config_loader import settings

from analyzer import processes as proc_analyzer
from analyzer.risk_score import apply_score


def _host_from_url(url):
    """Safe helper used by the cert stage: return lowercase hostname or ""."""
    try:
        parts = urlsplit(url)
    except (ValueError, TypeError):
        return ""
    return (parts.hostname or "").lower()

# Deterministic rule evaluation order (for stable reason lists).
RULE_ORDER = [
    "external_unknown_process",
    "unusual_remote_port",
    "suspicious_location",
    "multiple_external_connections",
    "repeated_connection",
    "outside_baseline",
]

log = logger.get_logger("analyzer.rules")


def _add(record, rule_key, weight, reason):
    record["rules_applied"][rule_key] = record["rules_applied"].get(rule_key, 0) + weight
    record["reasons"].append(f"{reason} (+{weight})")


def analyze(records, baseline=None, repeat_keys=None, hash_processes=True,
            use_reputation=False, use_cert=False):
    """Run all rules over enriched, annotated records.

    Args:
        records: connection records already carrying proc_info, ip_class,
                 is_external, port flags (from collector + ips/ports annotate).
        baseline: set of "name:port" strings considered normal, or None to skip.
        repeat_keys: set of connection keys seen in >= N scans, or None.
        hash_processes: if True, SHA-256 notable executables (Phase 9).
        use_reputation: if True AND FELUDA_VT_API_KEY is configured AND a
            cached result exists for this record's remote IP, add a VT-based
            penalty per the vt.weights block (spec §5).

    Returns the same records with risk_score, risk_level, reasons, rules_applied.
    """
    cfg = settings()
    weights = {**cfg.get("rule_weights", {})}
    thresholds = cfg.get("thresholds", {})

    # reputation integration is opt-in per-poll only
    _vt = None
    if use_reputation:
        from browser import reputation_engine as _re
        _vt = _re if _re.vt_available() else None

    # certificate inspection (Stage 3) — opt-in via --cert-check; cached only
    _cert = None
    if use_cert:
        from browser import cert_inspector as _ci
        _cert = _ci

    # Pre-compute external-connection count per pid for the burst signal.
    ext_per_pid = Counter()
    for r in records:
        if r.get("is_external"):
            pid = r.get("pid")
            if pid is not None:
                ext_per_pid[pid] += 1

    repeat_keys = repeat_keys or set()
    min_ext = thresholds.get("multiple_external_connections_min", 3)

    for rec in records:
        # Reset (not setdefault) so re-analyzing the same record list is
        # idempotent and never double-counts weights or reasons.
        rec["rules_applied"] = {}
        rec["reasons"] = []
        rec["baseline_hit"] = False

        pid = rec.get("pid")
        proc = rec.get("proc_info") or {}
        is_ext = bool(rec.get("is_external"))
        unknown_proc = proc_analyzer.is_unknown_process(proc)

        # 1. External connection + unrecognized process
        if is_ext and unknown_proc:
            _add(
                rec, "external_unknown_process", weights.get("external_unknown_process", 30),
                f"External (public) connection from unrecognized process "
                f"'{proc.get('name', 'unknown')}'",
            )

        # 2. Unusual remote port (signal, not proof of malice)
        if rec.get("port_unusual_remote"):
            _add(
                rec, "unusual_remote_port", weights.get("unusual_remote_port", 20),
                f"Unusual remote port {rec.get('remote_port')} "
                f"(service: {rec.get('port_service') or 'unrecognized'})",
            )

        # 3. Suspicious execution location
        exe = proc.get("exe") or ""
        if proc_analyzer.is_suspicious_location(exe):
            _add(
                rec, "suspicious_location", weights.get("suspicious_location", 25),
                f"Executable running from suspicious location: {exe}",
            )

        # 4. Process holds multiple simultaneous external connections
        if is_ext and pid is not None and ext_per_pid.get(pid, 0) >= min_ext:
            _add(
                rec, "multiple_external_connections",
                weights.get("multiple_external_connections", 10),
                f"'{proc.get('name', 'unknown')}' holds {ext_per_pid[pid]} "
                f"external connections (>= {min_ext})",
            )

        # 5. Connection repeatedly reappears across polls (feed from monitor loop)
        key = (pid, rec.get("local_port"), rec.get("remote_ip"), rec.get("remote_port"))
        if key in repeat_keys:
            _add(
                rec, "repeated_connection", weights.get("repeated_connection", 10),
                "Connection repeatedly reappears across polling intervals",
            )

        # 6. Outside learned baseline (only when a baseline is active)
        if baseline is not None:
            # Build the key via the canonical helper so learn and match agree
            # even when a process name is empty/missing (else they diverge and
            # baseline_hit is permanently False -> always flagged).
            from database import database as _db
            bkey = _db.baseline_key(proc.get("name"), rec.get("remote_port"))
            rec["baseline_hit"] = bkey in baseline
            if is_ext and not rec["baseline_hit"]:
                _add(
                    rec, "outside_baseline", weights.get("outside_baseline", 15),
                    f"'{proc.get('name', 'unknown')}:{rec.get('remote_port')}' "
                    f"is outside the learned baseline",
                )

        # 7. VirusTotal IP reputation (cached-only, non-blocking)
        #    Fires only when --reputation-check is on in monitor/scan and
        #    there's a cached result for this remote IP in
        #    url_reputation_cache. A cache miss here just yields nothing —
        #    the scan proceeds with the structural score it already has.
        if _vt is not None and is_ext and rec.get("remote_ip"):
            cached = _vt.cache_get(rec["remote_ip"])
            if cached is not None:
                pts, reason = _vt.score_result(cached)
                if pts:
                    rec["rules_applied"]["vt_reputation"] = rec["rules_applied"].get(
                        "vt_reputation", 0) + pts
                    rec["reasons"].append(f"{reason} (+{pts})")

        # 8. TLS certificate inspection (cached-only, non-blocking)
        #    Fires only when --cert-check is on in monitor/scan and a cached
        #    cert_checks row exists for the record's remote host. The scan
        #    pipeline never blocks on a live handshake; a recent-cache miss
        #    just means Stage 3 hasn't visited this hostname yet.
        if _cert is not None and rec.get("url"):
            cached = _cert.cache_get(_host_from_url(rec["url"]))
            if cached is not None and not cached.get("unreachable"):
                for flag in cached.get("cert_flags", []):
                    pts = settings().get("cert", {}).get("weights", {}).get(flag, 0)
                    if pts:
                        rec["rules_applied"][flag] = rec["rules_applied"].get(flag, 0) + pts
                        rec["reasons"].append(f"TLS: {flag} (+{pts})")
                rec["risk_score"] = min(
                    100, rec.get("risk_score", 0) + cached.get("risk_points", 0))
                rec["cert"] = {k: cached.get(k) for k in
                               ("hostname", "cert_flags", "risk_points")}
        apply_score(rec)

    if hash_processes:
        proc_analyzer.hash_notable_processes(records)

    log.info(
        "analyzed %d records; %d at MEDIUM+",
        len(records),
        sum(1 for r in records if r.get("risk_score", 0) >= thresholds.get("alert_min_risk_score", 25)),
    )
    return records
