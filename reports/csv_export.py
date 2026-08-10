"""Export analyzed connection records to CSV (Phase 18)."""

import csv
from pathlib import Path

from utils import logger
from utils.formatting import build_connection_payload

log = logger.get_logger("reports.csv")

FIELDS = [
    "timestamp", "pid", "process_name", "exe_path", "sha256",
    "local_ip", "local_port", "remote_ip", "remote_port",
    "status", "ip_class", "is_external", "risk_score", "risk_level", "reasons",
]

# Browser URL section fields — appended after the connection rows so the
# existing one-table layout still opens in a spreadsheet without breaking.
BROWSER_FIELDS = [
    "browser_name", "pid", "url", "domain", "title", "is_live_tab",
    "risk_score", "signals", "first_seen", "last_seen",
]


def export_csv(records, path, browser_records=None):
    """Original signature: export_csv(records, path).
    Extend with browser_records to also append a Browser URL section."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDS)
            writer.writeheader()
            for rec in records:
                p = build_connection_payload(rec)
                p["reasons"] = "; ".join(p["reasons"])
                writer.writerow({k: p.get(k, "") for k in FIELDS})
            if browser_records:
                fh.write("\n# Browser URL Activity (Feluda browser module)\n")
                bwriter = csv.DictWriter(fh, fieldnames=BROWSER_FIELDS)
                bwriter.writeheader()
                for b in browser_records:
                    row = dict(b)
                    row["signals"] = "; ".join(row.get("signals") or [])
                    row["is_live_tab"] = bool(row.get("is_live_tab"))
                    bwriter.writerow({k: row.get(k, "") for k in BROWSER_FIELDS})
        log.info("CSV export wrote %d rows to %s", len(records), path)
    except OSError as exc:
        log.error("CSV export failed: %s", exc)
        raise
    return path
