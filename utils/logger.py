"""Logging setup for Feluda.

AttributeDict lets us call logger.get_logger("analyzer.ips") from
subpackages as `from utils import logger` (package attribute access)
without importing utils.logger directly.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
_LOG_FILE = _LOG_DIR / "feluda.log"
_configured = False


def _setup():
    global _configured
    if _configured:
        return
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("feluda")
    root.setLevel(logging.INFO)
    if not root.handlers:
        fh = RotatingFileHandler(
            _LOG_FILE, maxBytes=1_048_576, backupCount=3, encoding="utf-8"
        )
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        root.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        root.addHandler(sh)
    _configured = True


def get_logger(name="feluda"):
    _setup()
    return logging.getLogger(f"feluda.{name}" if name else "feluda")


def log_detection(record):
    """Write a structured detection-event log line."""
    log = get_logger("detection")
    proc = record.get("proc_info") or {}
    reasons = "; ".join(record.get("reasons") or [])
    log.info(
        "detection pid=%s process=%s remote=%s:%s score=%s level=%s reasons=[%s]",
        record.get("pid"),
        proc.get("name", "unknown"),
        record.get("remote_ip"),
        record.get("remote_port"),
        record.get("risk_score", 0),
        record.get("risk_level", "LOW"),
        reasons,
    )


class _LoggerFacade:
    def get_logger(self, name="feluda"):
        return get_logger(name)

    def log_detection(self, record):
        return log_detection(record)

    def __getattr__(self, attr):
        # Delegate anything else to a real logger (info, warning, error, ...)
        return getattr(get_logger("feluda"), attr)


logger = _LoggerFacade()
