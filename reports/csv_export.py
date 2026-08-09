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


def export_csv(records, path):
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
        log.info("CSV export wrote %d rows to %s", len(records), path)
    except OSError as exc:
        log.error("CSV export failed: %s", exc)
        raise
    return path
