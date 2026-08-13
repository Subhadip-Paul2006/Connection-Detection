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


class MonitorController:
    """Controls the background monitor scan loop state for Telegram remote control."""

    def __init__(self, alerter=None):
        self.mode = "STOPPED"
        self.alert_min_score = 50
        self.mode_started_at = None
        self.scans_count = 0
        self.alerts_count = 0
        self.alerter = alerter

    def set_mode(self, mode: str, min_score: int) -> str:
        self.mode = mode.upper()
        self.alert_min_score = min_score
        self.mode_started_at = time.time()
        if self.alerter:
            self.alerter.set_alert_threshold(min_score)
        log.info("MonitorController mode set to %s (score >= %d)", self.mode, min_score)
        return f"Mode set to {self.mode} (alerting on score >= {min_score})"

    def stop_scan(self) -> str:
        self.mode = "STOPPED"
        self.mode_started_at = None
        log.info("MonitorController scan stopped")
        return "Active scan loop paused. Listener remains active."

    def get_status_markdown(self) -> str:
        from telegram_alerter import _esc
        if self.mode == "STOPPED" or not self.mode_started_at:
            uptime_str = "N/A (Stopped)"
        else:
            elapsed = int(time.time() - self.mode_started_at)
            mins, secs = divmod(elapsed, 60)
            hrs, mins = divmod(mins, 60)
            uptime_str = f"{hrs}h {mins}m {secs}s" if hrs else (f"{mins}m {secs}s" if mins else f"{secs}s")

        lines = [
            "\U0001f4ca *Feluda Monitor Status*",
            f"*Active Mode:* `{_esc(self.mode)}` \\(score \\>\\= {_esc(str(self.alert_min_score))}\\)",
            f"*Mode Uptime:* `{_esc(uptime_str)}`",
            f"*Scans Conducted:* `{_esc(str(self.scans_count))}`",
            f"*Alerts Triggered:* `{_esc(str(self.alerts_count))}`",
        ]
        return "\n".join(lines)


def run_monitor(interval=None, alert_min=None, once=False, show_table=True, use_baseline=True,
               use_reputation=False, use_cert=False, use_geoip=False, use_lineage=False,
               use_defender=False, persistence_check=False, alert_telegram=False, test_alert=False,
               telegram_control=False, args=None):
    """Start the polling monitor loop. Ctrl+C exits cleanly."""
    if telegram_control:
        return run_monitor_control(args or locals())


def run_monitor_control(args_or_dict):
    """Run two-way Telegram remote control monitor (long-polling listener + controllable scan task)."""
    import asyncio
    from telegram_alerter import TelegramAlerter, credentials_available, check_credentials
    from telegram_listener import TelegramListener, TelegramConflictError

    token, chat_id = credentials_available()
    if not token or not chat_id:
        check_credentials(quiet=False)
        return 1

    cfg = settings()
    interval = getattr(args_or_dict, "interval", None) or cfg.get("monitor", {}).get("poll_interval_seconds", 5)
    tg_cooldown = int(cfg.get("telegram", {}).get("cooldown_seconds", 1800))

    alerter = TelegramAlerter(cooldown_seconds=tg_cooldown, alert_threshold=50)
    if not alerter.configure():
        return 1
    alerter.start()

    controller = MonitorController(alerter=alerter)
    listener = TelegramListener(token=token, allowed_chat_id=chat_id, controller=controller)

    console.print(
        "\n[bold cyan]Telegram Remote Control Active[/bold cyan] -- Listening for commands (/high, /medium, /low, /stop, /status).\n"
        "Scan is currently [yellow]STOPPED[/yellow]. Select a mode in Telegram or tap a button to begin.\n"
    )

    async def _scan_worker():
        store = conn_collector.ConnectionStore()
        previous = set()
        prev_below = {}

        while True:
            await asyncio.sleep(max(1, int(interval)))
            if controller.mode == "STOPPED":
                continue

            controller.scans_count += 1
            loop = asyncio.get_running_loop()

            def _do_scan():
                recs = conn_collector.collect_connections()
                recs = proc_collector.enrich_connections(recs)
                recs = ips.annotate(recs)
                recs = ports.annotate(recs)
                store.observe_scan(recs)
                repeat_keys = store.repeat_keys(cfg.get("thresholds", {}).get("repeated_connection_min_scans", 3))
                
                use_base = getattr(args_or_dict, "no_baseline", False) is False if hasattr(args_or_dict, "no_baseline") else True
                baseline = database.load_baseline() if use_base else None
                
                recs = rules.analyze(
                    recs, baseline=baseline, repeat_keys=repeat_keys,
                    use_reputation=getattr(args_or_dict, "reputation_check", False),
                    use_cert=getattr(args_or_dict, "cert_check", False),
                    use_geoip=getattr(args_or_dict, "geo_check", False),
                    use_lineage=getattr(args_or_dict, "lineage_check", False),
                    use_defender=getattr(args_or_dict, "defender_check", False),
                )
                recs.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
                return recs

            records = await loop.run_in_executor(None, _do_scan)
            current = {_key(r) for r in records}
            database.save_scan(records)

            hits = [
                r for r in records
                if r.get("risk_score", 0) >= controller.alert_min_score
                and (_key(r) not in previous or prev_below.get(_key(r)))
            ]

            if hits:
                controller.alerts_count += len(hits)
                for rec in hits:
                    logger.log_detection(rec)
                    if rec.get("status") in ALERT_STATUSES:
                        console.print(render_alert_panel(rec))
                    alerter.enqueue_connection_alert(rec)

            prev_below = {_key(r): r.get("risk_score", 0) < controller.alert_min_score for r in records}
            previous = current

    async def _main_async():
        try:
            await asyncio.gather(listener.poll_loop(), _scan_worker())
        except TelegramConflictError:
            console.print("[bold red]ERROR: Telegram 409 Conflict.[/bold red] Another process is already long-polling this bot token.")
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(_main_async())
    except KeyboardInterrupt:
        console.line()
        console.print("[bold]Remote control monitor stopped by user.[/bold]")
    finally:
        listener.stop()
        alerter.stop()
    return 0
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

    # ------------------------------------------------------------------ Defender check elevation
    defender_admin = False
    if use_defender:
        from analyzer import defender_correlator
        defender_admin = defender_correlator.check_elevation()
        if not defender_admin:
            console.print("[yellow]--defender-check requires an elevated (Admin) terminal. Skipping Defender event correlation.[/yellow]")
            use_defender = False

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

            defender_matches = None
            confirmed_matches = []
            gap_events = []
            if use_defender and defender_admin:
                from analyzer import defender_correlator
                def_events = defender_correlator.query_defender_events(lookback_minutes=max(15, (interval * 3) // 60 + 1))
                confirmed_matches, gap_events = defender_correlator.correlate_events(records, def_events)
                defender_matches = {id(m["record"]): m for m in confirmed_matches}

            baseline = database.load_baseline() if use_baseline else None
            records = rules.analyze(
                records, baseline=baseline, repeat_keys=repeat_keys,
                use_reputation=use_reputation, use_cert=use_cert, use_geoip=use_geoip,
                use_lineage=use_lineage, use_defender=use_defender, defender_matches=defender_matches,
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

            if use_defender and defender_admin and (confirmed_matches or gap_events):
                rec_id_map = {id(r): i for i, r in zip(ids, records)}
                def_db_rows = []
                for m in confirmed_matches:
                    r_id = rec_id_map.get(id(m["record"]))
                    evt = m["event"]
                    def_db_rows.append({
                        **evt,
                        "correlated_history_id": r_id,
                        "match_confidence": m["match_confidence"],
                    })
                for g in gap_events:
                    def_db_rows.append({
                        **g,
                        "correlated_history_id": None,
                        "match_confidence": "gap",
                    })
                database.save_defender_events(def_db_rows)

                from utils.formatting import render_defender_panel
                console.print(render_defender_panel(confirmed_matches, gap_events))

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
