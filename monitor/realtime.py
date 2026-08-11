"""Real-time monitoring loop (Phase 13) + repeated-connection memory (Phase 15).

Loop: collect -> diff against previous scan -> analyze -> persist -> alert on
new/changed MEDIUM+ entries -> sleep on a config-driven interval (no tight
loop). All alerts list explicit signal reasons — never verdicts.
"""

import time

from rich.console import Console

from utils import logger
from utils.config_loader import settings
from utils.formatting import render_alert_panel, render_connections_table

from analyzer import ips, ports, rules
from collector import connections as conn_collector
from collector import processes as proc_collector
from database import database

console = Console()
log = logger.get_logger("monitor.realtime")

ALERT_STATUSES = {"ESTABLISHED", "SYN_SENT", "SYN_RECEIVED", "CLOSE_WAIT"}


def _key(rec):
    return (rec.get("pid"), rec.get("local_port"), rec.get("remote_ip"), rec.get("remote_port"))


def run_monitor(interval=None, alert_min=None, once=False, show_table=True, use_baseline=True,
               use_reputation=False, use_cert=False, use_geoip=False):
    """Start the polling monitor loop. Ctrl+C exits cleanly."""
    cfg = settings()
    if interval is None:
        interval = cfg.get("monitor", {}).get("poll_interval_seconds", 5)
    if alert_min is None:
        alert_min = cfg.get("thresholds", {}).get("alert_min_risk_score", 25)
    min_repeat = cfg.get("thresholds", {}).get("repeated_connection_min_scans", 3)

    store = conn_collector.ConnectionStore()
    previous = set()           # connection keys seen last scan
    prev_below = {}            # key -> bool, was this key below alert_min last scan?
    scan_num = 0

    console.print(
        f"[bold cyan]Feluda monitor[/bold cyan] — polling every {interval}s "
        f"(alert threshold: score >= {alert_min}). Ctrl+C to stop."
    )

    try:
        while True:
            scan_num += 1
            records = conn_collector.collect_connections()
            records = proc_collector.enrich_connections(records)
            records = ips.annotate(records)
            records = ports.annotate(records)

            store.observe_scan(records)
            repeat_keys = store.repeat_keys(min_repeat)

            baseline = database.load_baseline() if use_baseline else None
            records = rules.analyze(
                records, baseline=baseline, repeat_keys=repeat_keys,
                use_reputation=use_reputation, use_cert=use_cert, use_geoip=use_geoip,
            )
            records.sort(key=lambda r: r.get("risk_score", 0), reverse=True)

            current = {_key(r) for r in records}
            database.save_scan(records)

            new_records = [r for r in records if _key(r) not in previous]
            # Alert on (a) brand-new keys, and (b) existing keys whose score
            # has just CROSSED the alert threshold since the previous scan —
            # otherwise `repeated_connection` (+10) pushing a key from 20 to
            # 30 would never surface.
            hits = [
                r for r in records
                if r.get("risk_score", 0) >= alert_min
                and (_key(r) not in previous or prev_below.get(_key(r)))
            ]

            console.print(
                f"\\[scan {scan_num}] {len(records)} connections, "
                f"{len(new_records)} new, "
                f"[yellow]{sum(1 for r in records if r.get('risk_score', 0) >= alert_min)}[/yellow] "
                f"at/above alert threshold"
            )

            for rec in hits:
                # High-scoring new LISTENers are logged even though they aren't
                # popups — otherwise a fresh listener (a classic backdoor
                # indicator) would vanish silently from interactive monitoring.
                logger.log_detection(rec)
                if rec.get("status") in ALERT_STATUSES:
                    console.print(render_alert_panel(rec))

            if show_table and once:
                console.print(render_connections_table(records[:50], title=f"Scan {scan_num} snapshot"))

            prev_below = {_key(r): r.get("risk_score", 0) < alert_min for r in records}
            previous = current
            if once:
                break
            time.sleep(max(1, int(interval)))
    except KeyboardInterrupt:
        console.line()
        console.print("[bold]Monitor stopped by user.[/bold]")
    log.info("monitor exited after %d scans", scan_num)
