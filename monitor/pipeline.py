"""Single-scan orchestration: collect -> enrich -> annotate -> analyze.

Shared by `scan`, `baseline`, and `monitor` so all modes run identical logic.
"""

from utils import logger

from analyzer import ips, ports, rules
from collector import connections as conn_collector
from collector import processes as proc_collector
from database import database

log = logger.get_logger("pipeline")


def run_scan(use_baseline=True, repeat_keys=None, hash_processes=True):
    """Run one full scan. Returns analyzed records sorted by risk desc."""
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

    baseline = database.load_baseline() if use_baseline else None
    records = rules.analyze(
        records, baseline=baseline, repeat_keys=repeat_keys, hash_processes=hash_processes
    )
    records.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
    return records
