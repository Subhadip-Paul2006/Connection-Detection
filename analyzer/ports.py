"""Port intelligence (Phase 6).

Classifies ports against the well-known service map and the explicit
unusual-port list, both loaded from config/rules.json.

IMPORTANT FRAMING: an "unusual" port is a SIGNAL, not proof of malice.
Many legitimate tools use high or uncommon ports; this module only feeds
one weighted input into the risk score.
"""

from utils import logger
from utils.config_loader import settings

log = logger.get_logger("analyzer.ports")


def service_name(port):
    """Return the well-known service label for a port, or None."""
    if port is None:
        return None
    try:
        return settings().get("well_known_ports", {}).get(str(int(port)))
    except (TypeError, ValueError):
        return None


def is_unusual_remote_port(port):
    """True if the remote port is on the configured 'unusual' watchlist."""
    if port is None:
        return False
    try:
        return int(port) in settings().get("unusual_remote_ports", [])
    except (TypeError, ValueError):
        return False


def is_well_known(port):
    return service_name(port) is not None


def annotate(records):
    """Add `port_service` and `port_unusual_remote` flags to records."""
    for rec in records:
        rport = rec.get("remote_port")
        rec["port_service"] = service_name(rport)
        rec["port_unusual_remote"] = is_unusual_remote_port(rport)
    return records
