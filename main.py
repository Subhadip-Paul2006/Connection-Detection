"""Feluda â€” defensive network connection monitor & triage CLI.

A monitoring/triage tool, not an antivirus. Every flag is a *signal* with an
explicit reason list â€” never a definitive threat determination.

Usage:
    python main.py scan                          # one-shot scan, rich table
    python main.py monitor                       # real-time polling loop
    python main.py baseline                      # learn normal process->port
    python main.py history [--limit N] [--level HIGH]
    python main.py export [--format csv|json|html|all]
"""

import argparse
import json
import sys
from pathlib import Path

# Ensure project root on path so `analyzer`, `collector`, etc. import cleanly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from utils import logger
from utils.config_loader import settings
from utils.formatting import (
    print_banner, render_connections_table, render_browser_activity_panel,
    render_persistence_table, render_defender_panel, render_defender_events_table,
)

console = Console()
log = logger.get_logger("main")



def _print_lineage_detail(rec):
    """Render a stored lineage chain (from `history --show-lineage N`) as a
    rich panel + per-link table. `rec` comes from lineage_analyzer.fetch_lineage().
    """
    chain = rec.get("chain") or []
    lines = [
        f"[bold]history.id:[/bold] {rec.get('connection_id')}",
        f"[bold]pid:[/bold] {rec.get('pid')}",
        f"[bold]partial:[/bold] {rec.get('is_partial_chain')}"
        + (f" (orphan ppid: {rec.get('orphan_parent_pid')})" if rec.get('orphan_parent_pid') else ""),
        f"[bold]risk points:[/bold] {rec.get('risk_points', 0)}",
        f"[bold]signals:[/bold] {'; '.join(rec.get('signals') or []) or 'none'}",
        f"[bold]scanned at:[/bold] {rec.get('scanned_at', '')}",
    ]
    console.print(Panel("\n".join(lines), title="[bold cyan]Stored process lineage[/bold cyan]"))

    table = Table(title="Process chain (newest -> oldest parent)")
    for col in ("#", "PID", "Name", "EXE", "Cmdline"):
        table.add_column(col, no_wrap=col != "exe")
    for i, link in enumerate(chain, 1):
        exe = link.get("exe_path") or "unknown"
        if len(exe) > 80:
            exe = exe[:77] + "..."
        cmdline = (" ".join(link.get("cmdline") or [])) or "-"
        table.add_row(
            str(i),
            str(link.get("pid")),
            str(link.get("name") or "unknown"),
            exe,
            cmdline[:120] + ("..." if len(cmdline) > 120 else ""),
        )
    console.print(table)


def _summary_line(records):
    total = len(records)
    external = sum(1 for r in records if r.get("is_external"))
    listening = sum(1 for r in records if r.get("status") == "LISTEN")
    low = sum(1 for r in records if r.get("risk_level") == "LOW")
    med = sum(1 for r in records if r.get("risk_level") == "MEDIUM")
    high = sum(1 for r in records if r.get("risk_level") == "HIGH")
    crit = sum(1 for r in records if r.get("risk_level") == "CRITICAL")
    return (
        f"total={total} external={external} listen={listening} | "
        f"[green]LOW:{low}[/green] [yellow]MED:{med}[/yellow] "
        f"[red]HIGH:{high}[/red] [bold red]CRIT:{crit}[/bold red]"
    )


def cmd_scan(args):
    from monitor.pipeline import run_scan
    from database import database
    from analyzer import lineage_analyzer

    use_lineage = _lineage_enabled(args)
    use_defender = _defender_enabled(args)
    records = run_scan(use_baseline=not args.no_baseline, use_lineage=use_lineage, use_defender=use_defender, args=args)
    console.print(
        "\\[Feluda] single scan — heuristic signals only, not malware verdicts.",
        style="dim",
    )
    console.print(_summary_line(records))

    ids = None
    if use_lineage or use_defender:
        ids = database.save_scan(records, return_ids=True)

    if use_lineage and ids:
        with_lineage = [(i, r) for i, r in zip(ids, records) if r.get("lineage")]
        for i, r in with_lineage:
            lineage_analyzer.save_lineage(
                connection_id=i,
                lineage=r["lineage"],
                fires={},
                db_path=None,
            )
        console.print(f"[dim]lineage rows recorded: {len(with_lineage)} "
                      "(use 'history --show-lineage <id>' to drill in)[/dim]")

    if use_defender:
        def_data = getattr(run_scan, "_last_defender_data", {"confirmed": [], "gaps": []})
        confirmed = def_data.get("confirmed", [])
        gaps = def_data.get("gaps", [])
        if confirmed or gaps:
            if ids is None:
                ids = database.save_scan(records, return_ids=True)
            rec_id_map = {id(r): i for i, r in zip(ids, records)}
            def_db_rows = []
            for m in confirmed:
                r_id = rec_id_map.get(id(m["record"]))
                def_db_rows.append({
                    **m["event"],
                    "correlated_history_id": r_id,
                    "match_confidence": m["match_confidence"],
                })
            for g in gaps:
                def_db_rows.append({
                    **g,
                    "correlated_history_id": None,
                    "match_confidence": "gap",
                })
            database.save_defender_events(def_db_rows)
        console.print(render_defender_panel(confirmed, gaps))

    table = render_connections_table(
        records if args.all else [r for r in records if r.get("status") != "LISTEN" or r.get("risk_score", 0) > 0],
        title="Feluda — Network Connections",
        show_all=True,
    )
    console.print(table)
    if use_lineage and ids and with_lineage:
        console.print("\n[bold cyan]Lineage findings[/bold cyan]")
        for i, r in with_lineage:
            chain = r.get("lineage", {}).get("chain", [])
            console.print(f"[dim]conn id={i} pid={r.get('pid')}:[/dim] " +
                          " <- ".join(str(link.get("name")) for link in chain[:4])
                          + (" ..." if len(chain) > 4 else ""))
    return 0


def cmd_monitor(args):
    from monitor.realtime import run_monitor

    run_monitor(
        interval=args.interval, once=args.once, use_baseline=not args.no_baseline,
        use_reputation=_reputation_enabled(args),
        use_cert=_cert_enabled(args),
        use_geoip=_geoip_enabled(args),
        use_lineage=_lineage_enabled(args),
        use_defender=_defender_enabled(args),
        persistence_check=getattr(args, "persistence_check", False),
        alert_telegram=getattr(args, "alert_telegram", False),
        test_alert=getattr(args, "test_alert", False),
        telegram_control=getattr(args, "telegram_control", False),
        args=args,
    )
    return 0


def cmd_baseline(args):
    from monitor.pipeline import run_scan
    from database import database

    console.print("[bold cyan]Learning baseline from current connections...[/bold cyan]")
    records = run_scan(use_baseline=False)
    added = database.create_baseline(records)
    total = len(database.load_baseline())
    console.print(
        f"[green]Baseline updated:[/green] +{added} new patterns, {total} total known "
        f"process->port pairs."
    )
    console.print(
        "Future scans will flag external connections that fall outside this baseline "
        "as a *signal* (config weight: outside_baseline).",
        style="dim",
    )
    return 0


def cmd_history(args):
    from database import database
    from analyzer import lineage_analyzer

    # --show-lineage <id>: drill into a single past scan's process chain.
    if getattr(args, "show_lineage", None) is not None:
        rec = lineage_analyzer.fetch_lineage(args.show_lineage)
        if rec is None:
            console.print(f"[yellow]No lineage stored for history.id={args.show_lineage}. "
                          "Run with --lineage-check to capture chains.[/yellow]")
            return 0
        _print_lineage_detail(rec)
        return 0

    # --persistence: show past persistence scan snapshots.
    if getattr(args, "persistence", False):
        from persistence_scanner import fetch_entries
        rows_p = fetch_entries(limit=args.limit)
        if not rows_p:
            console.print("[yellow]No persistence snapshots yet. Run 'python main.py persistence' first.[/yellow]")
            return 0
        console.print(render_persistence_table(
            [{**r, "triggered_signals": json.loads(r.get("triggered_signals") or "[]")}
             for r in rows_p],
            title=f"Persistence snapshots (latest {len(rows_p)})"))
        return 0

    # --defender-only: show past defender event log correlations and gaps.
    if getattr(args, "defender_only", False):
        events = database.fetch_defender_events(limit=args.limit)
        if not events:
            console.print("[yellow]No Defender correlation records found in DB yet. Run 'python main.py scan --defender-check' in an elevated terminal.[/yellow]")
            return 0
        console.print(render_defender_events_table(events, title=f"Defender Events History (latest {len(events)})"))
        return 0

    # --telegram-sessions: show stored Telegram remote control sessions.
    if getattr(args, "telegram_sessions", False):
        sessions = database.fetch_telegram_sessions()
        if not sessions:
            console.print("[yellow]No Telegram sessions stored in DB yet.[/yellow]")
            return 0
        table = Table(title=f"Telegram Control Sessions (total {len(sessions)})")
        for col in ("Chat ID", "State", "Focus", "Session Started", "Session Ended", "Findings Sent", "Last Updated"):
            table.add_column(col)
        for s in sessions:
            table.add_row(
                str(s.get("chat_id", "")),
                str(s.get("last_known_state", "")),
                str(s.get("current_severity_focus") or "N/A"),
                str(s.get("session_started_at", "")),
                str(s.get("session_ended_at") or "Active / Connected"),
                str(s.get("total_findings_sent", 0)),
                str(s.get("updated_at", "")),
            )
        console.print(table)
        return 0

    rows = database.fetch_history(
        limit=args.limit, level=args.level, country=getattr(args, "country", None)
    )
    if not rows:
        console.print("[yellow]No history yet. Run 'python main.py scan' or 'monitor' first.[/yellow]")
        return 0

    table = Table(title=f"Feluda History (latest {len(rows)})")
    for col in ("Timestamp", "PID", "Process", "Local", "Remote", "Country", "Status", "Score", "Level", "Signals"):
        table.add_column(col, no_wrap=col in ("PID", "Status", "Score", "Level"))
    for r in reversed(rows):
        table.add_row(
            str(r.get("timestamp", "")),
            str(r.get("pid", "")),
            str(r.get("process_name", "")),
            f"{r.get('local_ip') or ''}:{r.get('local_port') or ''}",
            f"{r.get('remote_ip') or ''}:{r.get('remote_port') or ''}",
            str(r.get("country_code", "")),
            str(r.get("status", "")),
            str(r.get("risk_score", "")),
            str(r.get("risk_level", "")),
            str(r.get("signals", "")),
        )
    console.print(table)
    console.print(f"[dim]Total history rows in DB: {database.distinct_history_count()}[/dim]")
    return 0


def cmd_browsers(args):
    """Browser & URL threat detection: detect running browsers, extract
    recent/open URLs, score each structurally (and optionally via VirusTotal),
    persist, and render the Browser Activity panel (with optional live polling).

    --reputation-check is opt-in: without it, behavior exactly matches Phase 1/2
    (offline-only, no HTTP calls). WITH it, cached VT results are applied
    synchronously to known URLs and any new URLs are enqueued for the async
    worker â€” the next poll picks up their enriched risk_score.
    """
    from browser import browser_db
    from browser import browser_detector, reputation_engine, url_risk_engine

    alert_min = settings().get("browser", {}).get("alert_min_risk_score", 60)
    poll_interval = settings().get("browser", {}).get("poll_interval_seconds", 10)

    # reputation-check is flag-only; --no-reputation-check always wins.
    use_reputation = (
        getattr(args, "reputation_check", False)
        and not getattr(args, "no_reputation_check", False)
    )

    if use_reputation and not reputation_engine.vt_available():
        console.print(
            "[bold red]--reputation-check passed but FELUDA_VT_API_KEY is not set.[/bold red]\n"
            "Get a free key at https://www.virustotal.com/gui/join-us, then set:\n"
            "  powershell> $env:FELUDA_VT_API_KEY = \"<key>\"   (current session)\n"
            "  powershell> setx FELUDA_VT_API_KEY \"<key>\"       (permanent)\n"
            "  (or add FELUDA_VT_API_KEY=<key> to .env in the project root)"
        )
        logger.get_logger("main").error("reputation-check requested without FELUDA_VT_API_KEY")
        return 2

    vt_queue = None
    if use_reputation:
        vt_queue = reputation_engine.VTQueue()

    use_cert = _cert_enabled(args)
    use_geoip = _geoip_enabled(args)

    cert_worker = geo_worker = None
    if use_cert:
        from browser import cert_inspector as _cert_inspector
    if use_geoip:
        from browser import geoip_engine as _geoip_engine
        geo_worker = _geoip_engine.GeoIPQueue()

    def sweep_once():
        browsers = browser_detector.detect_running_browsers()
        if not browsers:
            console.print("[yellow]No supported browsers currently running.[/yellow]")
            return []
        records = browser_detector.extract_all_tabs(browsers)
        # Stage 1: free structural scoring. Stage 2: VT cache data applied only
        # if --reputation-check is on and a cached result exists (no blocking).
        url_risk_engine.score_records(
            records, use_reputation=use_reputation,
            use_certs=use_cert, use_geoip=use_geoip,
        )
        # Enqueue live lookups for cache misses only — never block this sweep.
        if use_reputation and vt_queue is not None:
            for rec in records:
                vt_queue.submit_url(rec.get("tab_url", ""))
        if use_cert:
            from browser import cert_inspector as _ci
            for rec in records:
                if (rec.get("tab_url") or "").lower().startswith("https://"):
                    host = ""
                    try:
                        from urllib.parse import urlsplit
                        host = (urlsplit(rec["tab_url"]).hostname or "").lower()
                    except (ValueError, TypeError):
                        pass
                    if host and _ci.cache_get(host) is None:
                        _ci.inspect_url(rec["tab_url"], connect_now=False)
                        # enqueue for live fetch inside a background thread
                        import threading
                        threading.Thread(
                            target=_ci.inspect_url,
                            args=(rec["tab_url"],), kwargs={"connect_now": True},
                            daemon=True,
                        ).start()
        if use_geoip and geo_worker is not None:
            from urllib.parse import urlsplit
            for rec in records:
                url = rec.get("tab_url") or ""
                if not url.lower().startswith("https://"):
                    continue
                try:
                    host = (urlsplit(url).hostname or "").lower()
                except (ValueError, TypeError):
                    continue
                if not host:
                    continue
                ip = _geoip_engine.resolve_hostname(host)
                if ip and geo_worker.submit(ip):
                    pass  # queued; get visible on next poll
        browser_db.upsert_browser_urls(records)
        records.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
        return records

    if args.live:
        interval = args.interval or poll_interval
        console.print(
            f"[bold cyan]Feluda browser watch[/bold cyan] â€” polling every {interval}s. Ctrl+C to stop."
        )
        seen = set()
        try:
            while True:
                records = sweep_once()
                current = {(r.get("browser_name"), r.get("tab_url")) for r in records}
                hits = [r for r in records
                        if (r.get("browser_name"), r.get("tab_url")) not in seen
                        and r.get("risk_score", 0) >= alert_min]
                console.print(
                    f"\\[browser sweep] {len(records)} URLs from "
                    f"{len({r.get('browser_name') for r in records})} browsers, "
                    f"[yellow]{sum(1 for r in records if r.get('risk_score', 0) >= alert_min)}[/yellow] "
                    f"at/above alert threshold"
                )
                for rec in hits:
                    logger.get_logger("browser.alert").info(
                        "url-detection browser=%s pid=%s url=%s score=%s signals=%s",
                        rec.get("browser_name"), rec.get("pid"), rec.get("tab_url"),
                        rec.get("risk_score"), "; ".join(rec.get("signals", [])),
                    )
                seen = current
                console.print(render_browser_activity_panel(records[:50]))
                if vt_queue is not None:
                    console.print(f"[dim]{vt_queue.quota_status()}[/dim]")
                import time
                time.sleep(max(1, int(interval)))
        except KeyboardInterrupt:
            console.line()
            console.print("[bold]Browser watch stopped by user.[/bold]")
    else:
        records = sweep_once()
        console.print(render_browser_activity_panel(records[:80]))
        if vt_queue is not None:
            console.print(f"[dim]{vt_queue.quota_status()}[/dim]")

    return 0


def cmd_persistence(args):
    """Phase 6: persistence / autorun / registry scan. Fully local, offline.

    Enumerates Run keys (HKCU + both HKLM hives incl. WOW6432Node), Startup
    folders (with .lnk resolution via WScript.Shell COM), Scheduled Tasks via
    Task Scheduler COM, and — only with --services — services outside trusted
    directories. Every entry is scored by local heuristics and cross-referenced
    against processes Feluda already flagged via the connection-scan path (or
    'history' rows when --cross-reference-history is off).

    By default it writes one persistence snapshot row per entry scanned. Run
    -v for the verbose table containing raw command text (potentially noisy).
    """
    from persistence_scanner import scan as persistence_scan
    from browser import browser_db  # noqa: F401 — keeps package imported for schema init

    entries, errors = persistence_scan(include_services=args.services)
    summary = (
        f"scanned {len(entries)} entries "
        f"({sum(1 for e in entries if e.get('source_type') == 'registry_run')} registry, "
        f"{sum(1 for e in entries if e.get('source_type') == 'startup_folder')} startup, "
        f"{sum(1 for e in entries if e.get('source_type') == 'scheduled_task')} tasks"
        + (", services=" + str(sum(1 for e in entries if e.get('source_type') == 'service')) if args.services else "")
        + f") — {sum(1 for e in entries if e.get('risk_points', 0) > 0)} with signals"
    )
    console.print(summary)
    if errors:
        console.print(
            "[yellow]Skipped surfaces:[/yellow] " +
            "; ".join(e.get("raw_command", "") for e in errors)
        )
    # default: nonzero scores first; the full list is too noisy in a terminal
    filtered = entries
    if not args.all:
        filtered = [e for e in entries if e.get("risk_points", 0) > 0]
    if filtered:
        console.print(render_persistence_table(
            filtered if args.all else filtered[:args.limit]))
    else:
        console.print("[green]No persistence entries triggered any rules.[/green]")


def cmd_export(args):
    from monitor.pipeline import run_scan
    from reports.csv_export import export_csv
    from reports.json_export import export_json
    from reports.html_export import export_html
    from browser import browser_db, browser_detector, reputation_engine, url_risk_engine

    outdir = Path(settings().get("export", {}).get("directory", "exports"))
    console.print(f"[bold cyan]Running scan for export -> {outdir}/[/bold cyan]")
    records = run_scan(use_baseline=not args.no_baseline)
    summary = {
        "total connections": len(records),
        "external": sum(1 for r in records if r.get("is_external")),
        "MEDIUM+": sum(1 for r in records if r.get("risk_score", 0) >= 25),
    }

    browser_records = []
    if args.scan_browsers:
        console.print("[bold cyan]Also exporting browser URL risk data ...[/bold cyan]")
        bs = browser_detector.detect_running_browsers()
        browser_records = browser_detector.extract_all_tabs(bs)
        use_rep = _reputation_enabled(args)
        url_risk_engine.score_records(browser_records, use_reputation=use_rep)
        summary["browser urls"] = len(browser_records)
        summary["browser MED+"] = sum(1 for r in browser_records if r.get("risk_score", 0) >= 30)
        if use_rep:
            vq = reputation_engine.VTQueue()
            for rec in browser_records:
                vq.submit_url(rec.get("tab_url", ""))
            console.print(f"[dim]{vq.quota_status()}[/dim]")

    persistence_records = []
    if getattr(args, "include_persistence", False):
        import persistence_scanner as _ps
        console.print("[bold cyan]Also running a persistence scan (registry/startup/tasks) ...[/bold cyan]")
        persistence_records, _perr = _ps.scan(include_services=False, save=True)
        summary["persistence entries"] = len(persistence_records)
        summary["persistence flagged"] = sum(1 for e in persistence_records if e.get("risk_points", 0) > 0)

    written = []
    if args.format in ("csv", "all"):
        written.append(export_csv(records, outdir / "connections.csv",
                                  browser_records=browser_records,
                                  persistence_records=persistence_records))
    if args.format in ("json", "all"):
        written.append(export_json(records, outdir / "connections.json",
                                   browser_records=browser_records,
                                   persistence_records=persistence_records))
    if args.format in ("html", "all"):
        written.append(export_html(records, outdir / "audit_report.html", summary=summary,
                                   browser_url_rows=browser_records,
                                   persistence_rows=persistence_records))
    for p in written:
        console.print(f"  [green]wrote[/green] {p}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="feluda",
        description="Defensive network connection monitor. Flags are signals, not verdicts.",
    )
    p.add_argument("--no-banner", action="store_true", help="Suppress startup ASCII banner")
    sub = p.add_subparsers(dest="command", required=True)

    def _add_reputation_flags(parser):
        """Opt-in VT reputation: scoring only happens if --reputation-check is
        passed AND FELUDA_VT_API_KEY is configured; --no-reputation-check
        always wins even if both flags are given.
        """
        parser.add_argument(
            "--reputation-check", action="store_true",
            help="include VirusTotal reputation signal (opt-in; needs FELUDA_VT_API_KEY)",
        )
        parser.add_argument(
            "--no-reputation-check", action="store_true",
            help="skip VirusTotal lookups even when a key exists",
        )
        parser.add_argument(
            "--cert-check", action="store_true",
            help="include TLS certificate inspection (opt-in; https:// URLs only)",
        )
        parser.add_argument(
            "--no-cert-check", action="store_true",
            help="skip TLS certificate checks (overrides --cert-check)",
        )
        parser.add_argument(
            "--geo-check", action="store_true",
            help="include GeoIP/ASN enrichment (opt-in; optional --geoip-provider maxmind)",
        )
        parser.add_argument(
            "--no-geo-check", action="store_true",
            help="skip GeoIP/ASN enrichment (overrides --geo-check)",
        )
        parser.add_argument(
            "--lineage-check", action="store_true",
            help="include process-tree lineage scoring on connection-owning processes (opt-in; local only)",
        )
        parser.add_argument(
            "--no-lineage-check", action="store_true",
            help="skip process-tree lineage scoring (overrides --lineage-check)",
        )
        parser.add_argument(
            "--defender-check", action="store_true",
            help="include Windows Defender event log correlation (opt-in; requires elevated/Admin terminal)",
        )
        parser.add_argument(
            "--no-defender-check", action="store_true",
            help="skip Windows Defender event log correlation (overrides --defender-check)",
        )

    def _add_persistence_flags(parser):
        """Phase 6: persistence cross-reference + include-in-export flags."""
        parser.add_argument(
            "--persistence-check", action="store_true",
            help="periodically re-scan persistence entries during monitor and cross-reference against active connections",
        )

    s = sub.add_parser("scan", help="Run a single scan and print a table")
    s.add_argument("--all", action="store_true", help="include quiet LISTEN sockets")
    s.add_argument("--no-baseline", action="store_true", help="skip baseline comparison")
    _add_reputation_flags(s)
    s.set_defaults(func=cmd_scan)

    m = sub.add_parser("monitor", help="Real-time polling monitor")
    m.add_argument("--interval", type=int, default=None, help="poll seconds (default from config)")
    m.add_argument("--once", action="store_true", help="run exactly one scan and exit")
    m.add_argument("--no-baseline", action="store_true", help="skip baseline comparison")
    _add_reputation_flags(m)
    _add_persistence_flags(m)
    m.add_argument(
        "--alert-telegram", action="store_true",
        help="send Telegram push notifications for findings at/above alert_threshold "
             "(needs FELUDA_BOT_TELEGRAM_TOKEN + FELUDA_TELEGRAM_CHAT_ID env vars)",
    )
    m.add_argument(
        "--telegram-control", action="store_true",
        help="enable two-way Telegram remote control loop (listens for /high, /medium, /low, /stop, /status)",
    )
    m.add_argument(
        "--test-alert", action="store_true",
        help="send a single sample Telegram message to verify credentials, then exit",
    )
    m.set_defaults(func=cmd_monitor)

    b = sub.add_parser("baseline", help="Learn normal process->remote-port patterns now")
    b.set_defaults(func=cmd_baseline)

    h = sub.add_parser("history", help="Show recent history from SQLite")
    h.add_argument("--limit", type=int, default=50)
    h.add_argument("--level", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None)
    h.add_argument("--country", help="filter by ISO-3166 country code (requires --geo-check data to be populated)")
    h.add_argument("--show-lineage", type=int, default=None,
                   help="show stored process lineage details for a past scan row (history.id)")
    h.add_argument("--persistence", action="store_true",
                   help="show past persistence snapshots instead of connection history")
    h.add_argument("--defender-only", action="store_true",
                   help="show stored Windows Defender event log correlation records instead of connection history")
    h.add_argument("--telegram-sessions", action="store_true",
                   help="show stored Telegram remote control sessions instead of connection history")
    h.set_defaults(func=cmd_history)

    e = sub.add_parser("export", help="Export current scan to CSV/JSON/HTML")
    e.add_argument("--format", choices=["csv", "json", "html", "all"], default="all")
    e.add_argument("--no-baseline", action="store_true")
    e.add_argument("--scan-browsers", action="store_true", help="also include Browser URL risk section")
    e.add_argument("--include-persistence", action="store_true",
                   help="run and include a persistence/autorun scan section in the export (fully local)")
    _add_reputation_flags(e)
    e.set_defaults(func=cmd_export)

    br = sub.add_parser("browsers", help="Browser & URL threat detection")
    br.add_argument("--live", action="store_true", help="poll for newly opened browsers/URLs")
    br.add_argument("--interval", type=int, default=None, help="poll seconds for --live (default from config)")
    _add_reputation_flags(br)
    br.set_defaults(func=cmd_browsers)

    pe = sub.add_parser("persistence",
                        help="Scan Windows persistence/autorun locations (registry Run keys, Startup folders, Scheduled Tasks, optional services)")
    pe.add_argument("--services", action="store_true",
                    help="also scan Windows services for untrusted binary paths (stretch goal; opt-in)")
    pe.add_argument("--all", action="store_true",
                    help="show every enumerated entry, not just ones with risk signals")
    pe.add_argument("--limit", type=int, default=80,
                    help="row cap when --all is passed")
    pe.set_defaults(func=cmd_persistence)

    stg = sub.add_parser("setup-telegram", help="Guided setup to connect your Telegram account to receive alerts")
    stg.set_defaults(func=cmd_setup_telegram)

    tgs = sub.add_parser("telegram-status", help="Show current Telegram recipient status & alert statistics")
    tgs.set_defaults(func=cmd_telegram_status)

    tgr = sub.add_parser("telegram-reset", help="Reset saved Telegram recipient configuration")
    tgr.set_defaults(func=cmd_telegram_reset)

    return p


def cmd_setup_telegram(args):
    import telegram_setup
    telegram_setup.setup_telegram_cli()


def cmd_telegram_status(args):
    import telegram_setup
    telegram_setup.show_telegram_status_cli()


def cmd_telegram_reset(args):
    import telegram_setup
    telegram_setup.reset_telegram_cli()


def _reputation_enabled(args):
    """True when VT is allowed to score: flag present AND key configured.
    Mirrors the logic used by cmd_browsers; scan/monitor/export read from the
    same env var + argument names so behavior is identical across modes.
    """
    from browser import reputation_engine
    if not getattr(args, "reputation_check", False):
        return False
    if getattr(args, "no_reputation_check", False):
        return False
    return reputation_engine.vt_available()


def _cert_enabled(args):
    """True when TLS cert inspection is enabled for this run."""
    if not getattr(args, "cert_check", False):
        return False
    return not getattr(args, "no_cert_check", False)


def _geoip_enabled(args):
    """True when GeoIP/ASN enrichment is enabled for this run."""
    if not getattr(args, "geo_check", False):
        return False
    return not getattr(args, "no_geo_check", False)


def _lineage_enabled(args):
    """True when Stage 5 lineage checks are enabled (`--lineage-check`)."""
    if not getattr(args, "lineage_check", False):
        return False
    return not getattr(args, "no_lineage_check", False)


def _defender_enabled(args):
    """True when Stage 7 Defender event log correlation is enabled (`--defender-check`)."""
    if not getattr(args, "defender_check", False):
        return False
    return not getattr(args, "no_defender_check", False)


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.no_banner:
        print_banner(console)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.line()
        console.print("[bold]Interrupted.[/bold]")
        return 130


if __name__ == "__main__":
    sys.exit(main())

