"""Single-scan orchestration: collect -> enrich -> annotate -> analyze.

Shared by `scan`, `baseline`, and `monitor` so all modes run identical logic.
"""

from utils import logger

from analyzer import ips, ports, rules
from collector import connections as conn_collector
from collector import processes as proc_collector
from database import database

log = logger.get_logger("pipeline")


def run_scan(use_baseline=True, repeat_keys=None, hash_processes=True,
             use_reputation=False, use_cert=False, use_geoip=False, use_lineage=False,
             use_defender=False, args=None):
    """Run one full scan. Returns analyzed records sorted by risk desc.

    Optional enrichments are opt-in per caller:
      use_reputation — VT Stage 2 (cache-read only, no blocking)
      use_cert     — TLS Stage 3 (cache-read only)
      use_geoip    — GeoIP Stage 4 (cache-read only)
      use_defender — Defender Stage 7 (event log correlation)
    `args` (an argparse.Namespace) is the CLI's preferred way to thread them in;
    explicit kwargs take precedence when both are given.
    """
    # Inline flag resolution so legacy callers keep working untouched.
    if args is not None:
        from main import _reputation_enabled, _cert_enabled, _geoip_enabled, _lineage_enabled, _defender_enabled
        use_reputation = use_reputation or _reputation_enabled(args)
        use_cert = use_cert or _cert_enabled(args)
        use_geoip = use_geoip or _geoip_enabled(args)
        use_lineage = use_lineage or _lineage_enabled(args)
        use_defender = use_defender or _defender_enabled(args)

    store = getattr(run_scan, "_store", None)
    if store is None:
        store = conn_collector.ConnectionStore()
        run_scan._store = store

    records = conn_collector.collect_connections()
    records = proc_collector.enrich_connections(records)
    records = ips.annotate(records)
    records = ports.annotate(records)

    store.observe_scan(records)
    if repeat_keys is None:
        from utils.config_loader import settings
        min_scans = settings().get("thresholds", {}).get("repeated_connection_min_scans", 3)
        repeat_keys = store.repeat_keys(min_scans)

    defender_matches = None
    confirmed_matches = []
    gap_events = []
    if use_defender:
        from analyzer import defender_correlator
        if not defender_correlator.check_elevation():
            from rich.console import Console
            Console().print("[yellow]--defender-check requires an elevated (Admin) terminal. Skipping Defender event correlation.[/yellow]")
        else:
            def_events = defender_correlator.query_defender_events()
            confirmed_matches, gap_events = defender_correlator.correlate_events(records, def_events)
            defender_matches = {id(m["record"]): m for m in confirmed_matches}

    run_scan._last_defender_data = {
        "confirmed": confirmed_matches,
        "gaps": gap_events,
    }

    baseline = database.load_baseline() if use_baseline else None
    records = rules.analyze(
        records, baseline=baseline, repeat_keys=repeat_keys, hash_processes=hash_processes,
        use_reputation=use_reputation, use_cert=use_cert, use_geoip=use_geoip,
        use_lineage=use_lineage, use_defender=use_defender, defender_matches=defender_matches,
    )
    records.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
    return records
