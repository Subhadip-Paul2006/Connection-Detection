"""Real-time monitoring loop (Phase 13) + repeated-connection memory (Phase 15).

Loop: collect -> diff against previous scan -> analyze -> persist -> alert on
new/changed MEDIUM+ entries -> sleep on a config-driven interval (no tight
loop). All alerts list explicit signal reasons -- never verdicts.

Phase 7 addition: optional ``--alert-telegram`` push notifications routed
through ``telegram_alerter.TelegramAlerter``.  The alerter runs in a daemon
thread and is fully non-blocking from the poll loop's perspective.
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
               use_reputation=False, use_cert=False, use_geoip=False, use_lineage=False,
               persistence_check=False, alert_telegram=False, test_alert=False):
    """Start the polling monitor loop. Ctrl+C exits cleanly.

    Parameters
    ----------
    alert_telegram : bool
        If True, load and start the Telegram alerter (requires env vars
        FELUDA_BOT_TELEGRAM_TOKEN and FELUDA_TELEGRAM_CHAT_ID).  Missing env
        vars print a one-line error and continue without alerting -- monitor
        itself never crashes over a bad Telegram config.
    test_alert : bool
        If True, send a single sample Telegram message and return immediately.
        Does not start the polling loop.
    """
    cfg = settings()
    if interval is None:
        interval = cfg.get("monitor", {}).get("poll_interval_seconds", 5)
    if alert_min is None:
        alert_min = cfg.get("thresholds", {}).get("alert_min_risk_score", 25)
    min_repeat = cfg.get("thresholds", {}).get("repeated_connection_min_scans", 3)
    persistence_interval = int(cfg.get("persistence", {}).get("persistence_check_polls", 12))

    tg_cfg = cfg.get("telegram", {})
    tg_threshold  = int(tg_cfg.get("alert_threshold", 50))
    tg_cooldown   = int(tg_cfg.get("cooldown_seconds", 1800))

    # ------------------------------------------------------------------ Telegram setup
    alerter = None
    if alert_telegram or test_alert:
        from telegram_alerter import TelegramAlerter, send_test_alert_sync
        if test_alert:
            ok = send_test_alert_sync()
            if ok:
                console.print("[green]Test alert sent successfully. Check your Telegram.[/green]")
            else:
                console.print("[red]Test alert failed. Check credentials and logs.[/red]")
            return  # don't start the polling loop for --test-alert

        alerter = TelegramAlerter(
            cooldown_seconds=tg_cooldown,
            alert_threshold=tg_threshold,
        )
        if alerter.configure():
            alerter.start()
            console.print(
                f"[bold cyan]Telegram alerts enabled[/bold cyan] "
                f"(threshold={tg_threshold}, cooldown={tg_cooldown}s)"
            )
        else:
            # configure() already printed the per-missing-var error; continue without alerting
            alerter = None

    # ------------------------------------------------------------------ polling loop
    store = conn_collector.ConnectionStore()
    previous = set()           # connection keys seen last scan
    prev_below = {}            # key -> bool, was this key below alert_min last scan?
    scan_num = 0
    last_persist_scan_num = -1

    console.print(
        f"[bold cyan]Feluda monitor[/bold cyan] -- polling every {interval}s "
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
                use_lineage=use_lineage,
            )
            records.sort(key=lambda r: r.get("risk_score", 0), reverse=True)

            current = {_key(r) for r in records}
            ids = database.save_scan(records, return_ids=True)
            if use_lineage:
                from analyzer import lineage_analyzer
                tuples = [(i, r) for i, r in zip(ids, records) if r.get("lineage")]
                for i, r in tuples:
                    lineage_analyzer.save_lineage(connection_id=i,
                                                  lineage=r["lineage"],
                                                  fires={},
                                                  db_path=None)

            new_records = [r for r in records if _key(r) not in previous]
            # Alert on (a) brand-new keys, and (b) existing keys whose score
            # has just CROSSED the alert threshold since the previous scan --
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
                # popups -- otherwise a fresh listener (a classic backdoor
                # indicator) would vanish silently from interactive monitoring.
                logger.log_detection(rec)
                if rec.get("status") in ALERT_STATUSES:
                    console.print(render_alert_panel(rec))
                # Phase 7: Telegram push -- fire-and-forget, never blocks loop
                if alerter is not None:
                    alerter.enqueue_connection_alert(rec)

            if show_table and once:
                console.print(render_connections_table(records[:50], title=f"Scan {scan_num} snapshot"))

            # --persistence-check: re-scan autorun locations every N poll cycles,
            # cross-referenced against the currently-active (this-run) connection exes.
            if persistence_check and (scan_num - last_persist_scan_num) >= max(1, persistence_interval):
                import persistence_scanner as _ps
                active_exes = sorted({
                    r.get("exe_path", "").lower()
                    for r in records
                    if r.get("is_external") and r.get("risk_score", 0) > 0 and r.get("exe_path")
                })
                p_entries, p_errors = _ps.scan(include_services=False, active_exes=active_exes, save=True)
                flagged = [e for e in p_entries if e.get("matched_connection_id") or e.get("risk_points", 0) > 0]
                if flagged:
                    from utils.formatting import render_persistence_table
                    console.print(f"[bold yellow]Persistence check[scan {scan_num}][/bold yellow] "
                                  f"flagged {len(flagged)} persistence entries")
                    console.print(render_persistence_table(flagged[:20], errors=p_errors,
                                                           title=f"Persistence matches (@scan {scan_num})"))
                    # Phase 7: Telegram alerts for persistence cross-reference matches
                    if alerter is not None:
                        for entry in flagged:
                            alerter.enqueue_persistence_alert(entry)
                else:
                    console.print(f"[dim]persistence check @{scan_num}: no new matches[/dim]")
                last_persist_scan_num = scan_num

            prev_below = {_key(r): r.get("risk_score", 0) < alert_min for r in records}
            previous = current
            if once:
                break
            time.sleep(max(1, int(interval)))
    except KeyboardInterrupt:
        console.line()
        console.print("[bold]Monitor stopped by user.[/bold]")
    finally:
        # Clean shutdown of the background sender thread
        if alerter is not None:
            alerter.stop()
    log.info("monitor exited after %d scans", scan_num)
