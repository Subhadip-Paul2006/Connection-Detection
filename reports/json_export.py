"""Export analyzed connection records to JSON (Phase 18)."""

import json
from pathlib import Path

from utils import logger
from utils.formatting import build_connection_payload

log = logger.get_logger("reports.json")


def export_json(records, path, browser_records=None, persistence_records=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not (browser_records or persistence_records):
        payload = [build_connection_payload(r) for r in records]
    else:
        payload = {"connections": [build_connection_payload(r) for r in records]}
        if browser_records:
            payload["browser_urls"] = browser_records
        if persistence_records:
            payload["persistence_entries"] = persistence_records
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        log.info("JSON export wrote to %s", path)
    except OSError as exc:
        log.error("JSON export failed: %s", exc)
        raise
    return path

