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


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------

_LEVEL_CLASS = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def render_html_report(records, summary=None, title="Feluda Audit Report"):
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
</body>
</html>
"""
