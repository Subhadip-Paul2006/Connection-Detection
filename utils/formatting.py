"""Formatting helpers for Feluda: engine-neutral payload builders and rich rendering.

CLI-facing language contract: flags are always presented as *signals* with an
explicit reason list — never as a definitive threat determination.
"""

import html
from datetime import datetime, timezone


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def fmt_addr(ip, port):
    if ip in (None, ""):
        return "-"
    try:
        if ":" in ip:
            return f"[{ip}]:{port}" if port is not None else ip
    except (TypeError, ValueError):
        pass
    return f"{ip}:{port}" if port is not None else ip


def safe_text(value):
    if value is None:
        return ""
    return str(value)


RISK_COLORS = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}


def risk_color(level):
    return RISK_COLORS.get(level, "white")


def build_connection_payload(record):
    """Flatten an analyzed record into an export/DB-friendly dict."""
    proc = record.get("proc_info") or {}
    return {
        "timestamp": record.get("timestamp") or utc_now_iso(),
        "pid": record.get("pid"),
        "process_name": proc.get("name", "unknown"),
        "exe_path": proc.get("exe", ""),
        "sha256": record.get("sha256", ""),
        "local_ip": record.get("local_ip"),
        "local_port": record.get("local_port"),
        "remote_ip": record.get("remote_ip"),
        "remote_port": record.get("remote_port"),
        "status": record.get("status"),
        "ip_class": record.get("ip_class", ""),
        "is_external": bool(record.get("is_external")),
        "risk_score": record.get("risk_score", 0),
        "risk_level": record.get("risk_level", "LOW"),
        "reasons": list(record.get("reasons") or []),
        "baseline_hit": bool(record.get("baseline_hit", False)),
    }


# ---------------------------------------------------------------------------
# rich rendering
# ---------------------------------------------------------------------------

def print_banner(console=None):
    """Render the retro NETSIGHT-inspired block banner for FELUDA."""
    import sys
    from rich.console import Console

    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if console is None:
        console = Console()

    banner_art = (
        "[bold #ff9900]"
        " ╔════════╗  ╔════════╗  ╔═══╗       ╔═══╗    ╔═══╗  ╔═════════╗   ╔════════╗ \n"
        " ║ ██████ ║  ║ ██████ ║  ║ █ ║       ║ █ ║    ║ █ ║  ║ ███████ ╚╗  ║ ██████ ║ \n"
        " ║ █ ╔════╝  ║ █ ╔════╝  ║ █ ║       ║ █ ║    ║ █ ║  ║ █ ╔═══╗ █ ║ ║ █ ╔══╗ █ ║ \n"
        " ║ ████ ║    ║ ████ ║    ║ █ ║       ║ █ ║    ║ █ ║  ║ █ ║   ║ █ ║ ║ ██████ ║ \n"
        " ║ █ ╔══╝    ║ █ ╔══╝    ║ █ ╚════╗  ║ █ ╚════╝ █ ║  ║ █ ║   ║ █ ║ ║ █ ╔══╗ █ ║ \n"
        " ║ █ ║       ║ ██████ ║  ║ ██████ ║  ║ ██████████ ║  ║ ███████ ╔╝  ║ █ ║  ║ █ ║ \n"
        " ╚═══╝       ╚════════╝  ╚════════╝  ╚════════════╝  ╚═════════╝   ╚═══╝  ╚═══╝[/bold #ff9900]\n"
        "[bold #d97706]"
        "  ║   │       ║       │   ║       │   ║            │    ║         │   ║      │  \n"
        "  ╚═══╛       ╚═══════╛   ╚═══════╛   ╚════════════╛    ╚═════════╛   ╚══════╛  [/bold #d97706]\n"
        "[bold #ffb347] ─── DEFENSIVE NETWORK CONNECTION MONITOR & TRIAGE ENGINE ───[/bold #ffb347]\n"
    )
    console.print(banner_art)


def render_connections_table(records, title="Network Connections", show_all=False):
    """Build a rich Table. `records` are analyzed dicts (from analyzer.rules)."""
    from rich.table import Table
    from rich.text import Text

    table = Table(title=title, expand=True)
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("Process", no_wrap=True)
    table.add_column("Local", no_wrap=True)
    table.add_column("Remote", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Risk", justify="right", no_wrap=True)
    table.add_column("Level", no_wrap=True)
    if show_all:
        table.add_column("Signals", overflow="fold")

    for rec in records:
        proc = rec.get("proc_info") or {}
        reasons = rec.get("reasons") or []
        level = rec.get("risk_level", "LOW")
        score = rec.get("risk_score", 0)
        color = risk_color(level)
        row = [
            str(rec.get("pid") if rec.get("pid") is not None else "?"),
            Text(str(proc.get("name") or "unknown")),
            Text(fmt_addr(rec.get("local_ip"), rec.get("local_port"))),
            Text(fmt_addr(rec.get("remote_ip"), rec.get("remote_port"))),
            Text(rec.get("status") or ""),
            f"[{color}]{score}[/{color}]",
            f"[{color}]{level}[/{color}]",
        ]
        if show_all:
            row.append(Text("; ".join(reasons)))
        table.add_row(*row)
    return table


def render_alert_panel(rec):
    """Build a rich Panel for one suspicious connection."""
    from rich.markup import escape as _esc
    from rich.panel import Panel
    from rich.text import Text

    proc = rec.get("proc_info") or {}
    score = rec.get("risk_score", 0)
    level = rec.get("risk_level", "LOW")
    color = risk_color(level)

    # Escape every interpolated, process-controlled value (paths, names,
    # reason strings) — brackets in them must render literally, never as tags.
    lines = [
        f"[bold]Process:[/bold] {_esc(proc.get('name', 'unknown'))} (PID {_esc(str(rec.get('pid', '?')))})",
        f"[bold]Path:[/bold]    {_esc(proc.get('exe') or 'unknown')}",
        f"[bold]Remote:[/bold]  {_esc(fmt_addr(rec.get('remote_ip'), rec.get('remote_port')))}",
        f"[bold]Status:[/bold]  {_esc(rec.get('status', ''))}   [bold]Score:[/bold] [{color}]{score} ({level})[/{color}]",
        "[bold]Signals:[/bold]",
    ]
    reasons = rec.get("reasons") or ["(no reasons recorded)"]
    lines += [f"  • {_esc(r)}" for r in reasons]
    body = Text.from_markup("\n".join(lines))
    return Panel(
        body,
        title=f"[{color}]Suspicious connection signal — {level}[/{color}]",
        border_style=color,
        expand=True,
    )


def render_persistence_table(entries, errors=None, title="Persistence / Autorun Entries"):
    """Render persistence scan results. Rows colored green=0, yellow 1-39, red >=40.
    `errors` are permission/absence notes rendered at the bottom as dim lines —
    Feluda policy: never silently omit a skipped surface."""
    from rich.table import Table
    from rich.text import Text as _Text

    table = Table(title=title, expand=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Location / Name", overflow="fold")
    table.add_column("Target", overflow="fold")
    table.add_column("On disk", no_wrap=True)
    table.add_column("Signed", no_wrap=True)
    table.add_column("Risk", justify="right", no_wrap=True)
    table.add_column("Signals", overflow="fold")

    def _color(score):
        return "bold red" if score >= 40 else ("yellow" if score >= 1 else "green")

    for e in entries:
        score = int(e.get("risk_points", 0))
        sig = "; ".join(e.get("triggered_signals") or [])
        table.add_row(
            _Text(str(e.get("source_type", ""))),
            _Text(str(e.get("location_detail", ""))[:60]),
            _Text(str(e.get("resolved_exe_path", ""))[:70]),
            _Text("yes" if e.get("exists_on_disk") else "no" if e.get("resolved_exe_path") else "-"),
            _Text(str(e.get("signed_state", "-"))),
            f"[{_color(score)}]{score}[/{_color(score)}]",
            _Text(sig[:120]),
        )
    if errors:
        for e in errors:
            table.add_row(
                _Text("note"),
                _Text(str(e.get("location_detail", ""))[:60]),
                _Text(str(e.get("raw_command", ""))[:70]),
                _Text("-"), _Text("-"), _Text("-"),
                _Text(str(e.get("raw_command", "")), style="dim"),
            )
    return table


def render_defender_panel(confirmed_matches, gap_events):
    """Build a rich Panel/Group for Defender correlation findings and gaps."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    items = []

    if confirmed_matches:
        conf_table = Table(title="Confirmed Defender Matches (Scan + Defender)", expand=True)
        conf_table.add_column("Process (PID)", no_wrap=True)
        conf_table.add_column("Threat Name", overflow="fold")
        conf_table.add_column("Severity", no_wrap=True)
        conf_table.add_column("Confidence", no_wrap=True)
        conf_table.add_column("Affected Path", overflow="fold")

        for match in confirmed_matches:
            rec = match.get("record") or {}
            proc = rec.get("proc_info") or {}
            evt = match.get("event") or {}
            conf = match.get("match_confidence", "unknown")

            proc_str = f"{proc.get('name', 'unknown')} ({rec.get('pid', '?')})"
            conf_color = "green" if conf == "high" else ("yellow" if conf == "medium" else "dim")

            conf_table.add_row(
                Text(proc_str),
                Text(str(evt.get("threat_name", ""))),
                Text(str(evt.get("severity", ""))),
                f"[{conf_color}]{conf}[/{conf_color}]",
                Text(str(evt.get("affected_path", ""))),
            )
        items.append(conf_table)

    if gap_events:
        gap_table = Table(title="Defender Gaps (Detected by Defender, Missed by Scan)", expand=True)
        gap_table.add_column("Event ID", no_wrap=True)
        gap_table.add_column("Threat Name", overflow="fold")
        gap_table.add_column("Severity", no_wrap=True)
        gap_table.add_column("Process / Path", overflow="fold")
        gap_table.add_column("Detected At", no_wrap=True)

        for evt in gap_events:
            proc_or_path = evt.get("affected_path") or evt.get("process_name_if_known") or "-"
            gap_table.add_row(
                Text(str(evt.get("event_id", ""))),
                Text(str(evt.get("threat_name", ""))),
                Text(str(evt.get("severity", ""))),
                Text(proc_or_path),
                Text(str(evt.get("detected_at", ""))),
            )
        items.append(gap_table)

    if not items:
        return Panel(
            Text("No Windows Defender detections correlated in recent events.", style="dim"),
            title="[bold cyan]Windows Defender Correlation[/bold cyan]",
        )

    return Panel(
        Group(*items),
        title="[bold cyan]Windows Defender / Event Log Correlation[/bold cyan]",
        border_style="cyan",
        expand=True,
    )


def render_defender_events_table(events, title="Windows Defender Events History"):
    """Render stored Defender events from defender_events SQLite table."""
    from rich.table import Table
    from rich.text import Text

    table = Table(title=title, expand=True)
    table.add_column("Event ID", no_wrap=True)
    table.add_column("Threat Name", overflow="fold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Process", overflow="fold")
    table.add_column("Affected Path", overflow="fold")
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Correlated History ID", justify="right", no_wrap=True)
    table.add_column("Detected At", no_wrap=True)

    for e in events:
        conf = e.get("match_confidence") or "gap"
        conf_color = "green" if conf == "high" else ("yellow" if conf == "medium" else "dim")
        table.add_row(
            Text(str(e.get("event_id", ""))),
            Text(str(e.get("threat_name", ""))),
            Text(str(e.get("severity", ""))),
            Text(str(e.get("process_name_if_known", "") or "-")),
            Text(str(e.get("affected_path", "") or "-")),
            f"[{conf_color}]{conf}[/{conf_color}]",
            Text(str(e.get("correlated_history_id") if e.get("correlated_history_id") is not None else "-")),
            Text(str(e.get("detected_at", ""))),
        )
    return table


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------

_LEVEL_CLASS = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


# ---------------------------------------------------------------------------
# Browser URL panel (Browser & URL Threat Detection module)
# ---------------------------------------------------------------------------

def render_browser_activity_panel(records, title="Browser Activity"):
    """Render the Browser Activity panel: one rich Table, rows pre-scored up
    to color thresholds (green <30, yellow 30-60, red >60) per spec §5.

    Optional Stage 4 enrichment: when a record's `geoip` dict is present
    the extra `Country` and `ASN` columns are shown.

    `records` are output of browser.url_risk_engine.score_records().
    """
    from rich.table import Table
    from rich.text import Text

    table = Table(title=title, expand=True)
    table.add_column("Browser", no_wrap=True)
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("URL", overflow="fold")
    table.add_column("Risk", justify="right", no_wrap=True)
    table.add_column("Country", no_wrap=True)
    table.add_column("ASN", no_wrap=True)
    table.add_column("Top Signal", overflow="fold")

    def _url_score_color(score):
        if score > 60:
            return "bold red"
        if score >= 30:
            return "yellow"
        return "green"

    for rec in records:
        score = int(rec.get("risk_score", 0))
        color = _url_score_color(score)
        url = rec.get("tab_url") or "-"
        if len(url) > 80:
            url = url[:77] + "..."
        signals = rec.get("signals") or []
        top_signal = signals[0] if signals else "-"
        geo = rec.get("geoip") or {}
        table.add_row(
            Text(str(rec.get("browser_name", "unknown"))),
            Text(str(rec.get("pid", "?"))),
            Text(url),
            f"[{color}]{score}[/{color}]",
            Text(str(geo.get("country_code", "")) or "—"),
            Text(str(geo.get("asn", "")) or "—"),
            Text(top_signal),
        )
    return table


def _render_browser_urls_html(url_rows):
    """Build the Browser URL risk table body for the HTML report.

    `url_rows` come from browser.browser_db.fetch_browser_urls(). All values
    are HTML-escaped; the URL and title are truncated to keep cells small."""
    if not url_rows:
        return "<tr><td colspan='8'><em>No browser URL activity recorded.</em></td></tr>"
    rows = []
    for r in url_rows:
        score = int(r.get("risk_score", 0))
        lvl = "low" if score < 30 else ("medium" if score <= 60 else "high")
        badge = f'<span class="badge {lvl}">{score}</span>'
        title_cell = html.escape(safe_text(r.get("title", ""))[:60])
        url_cell = html.escape(safe_text(r.get("url", "")))
        signals = html.escape(safe_text(r.get("signals", ""))).replace("\n", "; ")
        rows.append(
            f"<tr>"
            f"<td>{html.escape(safe_text(r.get('browser_name', '')))}</td>"
            f"<td>{html.escape(safe_text(r.get('pid', '')))}</td>"
            f"<td>{url_cell}</td>"
            f"<td>{title_cell}</td>"
            f"<td>{'yes' if r.get('is_live_tab') else 'recent'}</td>"
            f"<td>{badge}</td>"
            f"<td>{signals}</td>"
            f"<td>{html.escape(safe_text(r.get('last_seen', '')))}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _render_persistence_html(rows):
    """Build the Persistence / Autorun section body for the HTML report.

    `rows` come from persistence_scanner.fetch_entries(). All values are
    HTML-escaped; command strings and signals are truncated for readability.
    """
    if not rows:
        return "<tr><td colspan='7'><em>No persistence entries recorded.</em></td></tr>"
    out_lines = []
    for e in rows:
        score = int(e.get("risk_points", 0))
        lvl = "low" if score == 0 else ("medium" if score < 40 else "high")
        badge = f'<span class="badge {lvl}">{score}</span>'
        signals_raw = e.get("triggered_signals", "")
        try:
            sig_list = json.loads(signals_raw) if isinstance(signals_raw, str) else list(signals_raw)
        except Exception:
            sig_list = [safe_text(signals_raw)]
        signals = "; ".join(html.escape(safe_text(s)) for s in sig_list)
        target = html.escape(safe_text(e.get("resolved_exe_path", "")))
        out_lines.append(
            f"<tr>"
            f"<td>{html.escape(safe_text(e.get('source_type', '')))}</td>"
            f"<td>{html.escape(safe_text(e.get('location_detail', ''))[:60])}</td>"
            f"<td>{target[:80]}</td>"
            f"<td>{'yes' if e.get('exists_on_disk') else 'no' if target else '-'}</td>"
            f"<td>{html.escape(safe_text(e.get('signed_state', '-')))}</td>"
            f"<td>{badge}</td>"
            f"<td>{signals[:160]}</td>"
            f"</tr>"
        )
    return "\n".join(out_lines)


def render_html_report(records, summary=None, title="Feluda Audit Report", browser_url_rows=None,
                       persistence_rows=None):
    """Return a self-contained HTML audit report string."""
    rows = []
    for rec in records:
        p = build_connection_payload(rec)
        lvl = p["risk_level"]
        lvl_cls = _LEVEL_CLASS.get(lvl, "low")
        # Data cells are HTML-escaped; the badge span and reason list carry
        # intentional markup, so escape their *content* then build markup raw.
        plain = [
            p["timestamp"],
            p["pid"],
            p["process_name"],
            p["exe_path"],
            fmt_addr(p["local_ip"], p["local_port"]),
            fmt_addr(p["remote_ip"], p["remote_port"]),
            p["status"],
            p["ip_class"],
            p["risk_score"],
        ]
        tds = "".join(f"<td>{html.escape(safe_text(c))}</td>" for c in plain)
        tds += f'<td><span class="badge {lvl_cls}">{html.escape(safe_text(lvl))}</span></td>'
        reasons_html = "<br>".join(
            f"• {html.escape(safe_text(r))}" for r in p["reasons"]
        )
        tds += f"<td>{reasons_html}</td>"
        tds += f"<td>{html.escape(safe_text(p['sha256']))}</td>"
        rows.append(f"<tr>{tds}</tr>")

    headers = "".join(
        f"<th>{h}</th>"
        for h in [
            "Timestamp", "PID", "Process", "Path", "Local", "Remote",
            "Status", "IP Class", "Score", "Level", "Signals", "SHA-256",
        ]
    )

    summary_html = ""
    if summary:
        items = "".join(
            f"<li><span class='k'>{html.escape(safe_text(k))}:</span> {html.escape(safe_text(v))}</li>"
            for k, v in summary.items()
        )
        summary_html = f"<h2>Summary</h2><ul class='summary'>{items}</ul>"

    body_rows = "\n".join(rows) if rows else (
        "<tr><td colspan='12'><em>No records.</em></td></tr>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: Segoe UI, Consolas, monospace; background:#0f1220; color:#e8e8f0; margin:24px; }}
  h1 {{ color:#9ecbff; }} h2 {{ color:#9ecbff; margin-top:28px; }}
  table {{ border-collapse: collapse; width:100%; font-size: 13px; }}
  th, td {{ border:1px solid #333a55; padding:6px 8px; text-align:left; vertical-align:top; }}
  th {{ background:#1b2240; color:#dbe7ff; position:sticky; top:0; }}
  tr:nth-child(even) {{ background:#141831; }}
  .badge {{ padding:2px 8px; border-radius:10px; font-weight:bold; }}
  .low {{ background:#1f7a3d; }} .medium {{ background:#a8871b; }}
  .high {{ background:#c0392b; }} .critical {{ background:#e74c3c; border:1px solid #fff; }}
  .summary {{ list-style:none; padding:0; }} .summary .k {{ color:#9ecbff; }}
  .note {{ color:#9aa3c0; font-size:12px; margin-top:8px; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p class="note">Generated by Feluda at {html.escape(utc_now_iso())} UTC.
All flags are <strong>signals with reasons</strong>, not malware verdicts.</p>
{summary_html}
<h2>Connections ({len(rows)})</h2>
<table>
<thead><tr>{headers}</tr></thead>
<tbody>
{body_rows}
</tbody>
</table>
<h2>Browser URL Activity</h2>
<table>
<thead><tr>
<th>Browser</th><th>PID</th><th>URL</th><th>Title</th><th>Live?</th><th>Risk</th><th>Signals</th><th>Last Seen</th>
</tr></thead>
<tbody>
{_render_browser_urls_html(browser_url_rows)}
</tbody>
</table>
<h2>Persistence / Autorun Entries</h2>
<table>
<thead><tr>
<th>Source</th><th>Location / Name</th><th>Target</th><th>On disk</th><th>Signed</th><th>Risk</th><th>Signals</th>
</tr></thead>
<tbody>
{_render_persistence_html(persistence_rows)}
</tbody>
</table>
</body>
</html>
"""
