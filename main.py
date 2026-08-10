"""Feluda — defensive network connection monitor & triage CLI.

A monitoring/triage tool, not an antivirus. Every flag is a *signal* with an
explicit reason list — never a definitive threat determination.

Usage:
    python main.py scan                          # one-shot scan, rich table
    python main.py monitor                       # real-time polling loop
    python main.py baseline                      # learn normal process->port
    python main.py history [--limit N] [--level HIGH]
    python main.py export [--format csv|json|html|all]
"""

import argparse
import sys
from pathlib import Path

# Ensure project root on path so `analyzer`, `collector`, etc. import cleanly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.console import Console
from rich.table import Table

from utils import logger
from utils.config_loader import settings
from utils.formatting import print_banner, render_connections_table, render_browser_activity_panel

console = Console()
log = logger.get_logger("main")



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

    records = run_scan(use_baseline=not args.no_baseline)
    console.print(
        "\\[Feluda] single scan — heuristic signals only, not malware verdicts.",
        style="dim",
    )
    console.print(_summary_line(records))
    table = render_connections_table(
        records if args.all else [r for r in records if r.get("status") != "LISTEN" or r.get("risk_score", 0) > 0],
        title="Feluda — Network Connections",
        show_all=True,
    )
    console.print(table)
    return 0


def cmd_monitor(args):
    from monitor.realtime import run_monitor

    run_monitor(interval=args.interval, once=args.once, use_baseline=not args.no_baseline)
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

    rows = database.fetch_history(limit=args.limit, level=args.level)
    if not rows:
        console.print("[yellow]No history yet. Run 'python main.py scan' or 'monitor' first.[/yellow]")
        return 0

    table = Table(title=f"Feluda History (latest {len(rows)})")
    for col in ("Timestamp", "PID", "Process", "Local", "Remote", "Status", "Score", "Level", "Signals"):
        table.add_column(col, no_wrap=col in ("PID", "Status", "Score", "Level"))
    for r in reversed(rows):
        table.add_row(
            str(r.get("timestamp", "")),
            str(r.get("pid", "")),
            str(r.get("process_name", "")),
            f"{r.get('local_ip') or ''}:{r.get('local_port') or ''}",
            f"{r.get('remote_ip') or ''}:{r.get('remote_port') or ''}",
            str(r.get("status", "")),
            str(r.get("risk_score", "")),
            str(r.get("risk_level", "")),
            str(r.get("signals", "")),
        )
    console.print(table)
    console.print(f"[dim]Total history rows in DB: {database.distinct_history_count()}[/dim]")
    return 0


def cmd_browsers(args):
    """Phase 1 Browser & URL Threat Detection: detect running browsers,
    extract recent open/recent URLs, score each structurally, persist, and
    render the Browser Activity panel (with optional live polling)."""
    from browser import browser_db
    from browser import browser_detector, url_risk_engine

    alert_min = settings().get("browser", {}).get("alert_min_risk_score", 60)
    poll_interval = settings().get("browser", {}).get("poll_interval_seconds", 10)

    def sweep_once():
        browsers = browser_detector.detect_running_browsers()
        if not browsers:
            console.print("[yellow]No supported browsers currently running.[/yellow]")
            return []
        records = browser_detector.extract_all_tabs(browsers)
        url_risk_engine.score_records(records)
        browser_db.upsert_browser_urls(records)
        records.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
        return records


    if args.live:
        interval = args.interval or poll_interval
        console.print(
            f"[bold cyan]Feluda browser watch[/bold cyan] — polling every {interval}s. Ctrl+C to stop."
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
                import time
                time.sleep(max(1, int(interval)))
        except KeyboardInterrupt:
            console.line()
            console.print("[bold]Browser watch stopped by user.[/bold]")
    else:
        records = sweep_once()
        console.print(render_browser_activity_panel(records[:80]))

    return 0


def cmd_export(args):
    from monitor.pipeline import run_scan
    from reports.csv_export import export_csv
    from reports.json_export import export_json
    from reports.html_export import export_html
    from browser import browser_db, browser_detector, url_risk_engine

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
        url_risk_engine.score_records(browser_records)
        summary["browser urls"] = len(browser_records)
        summary["browser MED+"] = sum(1 for r in browser_records if r.get("risk_score", 0) >= 30)

    written = []
    if args.format in ("csv", "all"):
        written.append(export_csv(records, outdir / "connections.csv", browser_records=browser_records))
    if args.format in ("json", "all"):
        written.append(export_json(records, outdir / "connections.json", browser_records=browser_records))
    if args.format in ("html", "all"):
        written.append(export_html(records, outdir / "audit_report.html", summary=summary,
                                   browser_url_rows=browser_records))
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

    s = sub.add_parser("scan", help="Run a single scan and print a table")
    s.add_argument("--all", action="store_true", help="include quiet LISTEN sockets")
    s.add_argument("--no-baseline", action="store_true", help="skip baseline comparison")
    s.set_defaults(func=cmd_scan)

    m = sub.add_parser("monitor", help="Real-time polling monitor")
    m.add_argument("--interval", type=int, default=None, help="poll seconds (default from config)")
    m.add_argument("--once", action="store_true", help="run exactly one scan and exit")
    m.add_argument("--no-baseline", action="store_true", help="skip baseline comparison")
    m.set_defaults(func=cmd_monitor)

    b = sub.add_parser("baseline", help="Learn normal process->remote-port patterns now")
    b.set_defaults(func=cmd_baseline)

    h = sub.add_parser("history", help="Show recent history from SQLite")
    h.add_argument("--limit", type=int, default=50)
    h.add_argument("--level", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None)
    h.set_defaults(func=cmd_history)

    e = sub.add_parser("export", help="Export current scan to CSV/JSON/HTML")
    e.add_argument("--format", choices=["csv", "json", "html", "all"], default="all")
    e.add_argument("--no-baseline", action="store_true")
    e.add_argument("--scan-browsers", action="store_true", help="also include Browser URL risk section")
    e.set_defaults(func=cmd_export)

    br = sub.add_parser("browsers", help="Browser & URL threat detection (Phase 1)")
    br.add_argument("--live", action="store_true", help="poll for newly opened browsers/URLs")
    br.add_argument("--interval", type=int, default=None, help="poll seconds for --live (default from config)")
    br.set_defaults(func=cmd_browsers)

    return p


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

