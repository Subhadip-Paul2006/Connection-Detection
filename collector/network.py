"""Network helpers (Phase 1 support): local interfaces and TCP-state labels.

Local-only: reads interface data from the local machine via psutil; never
touches remote hosts.
"""

import psutil

from utils import logger

log = logger.get_logger("collector.network")

# Phase 1: authoritative TCP state label reference (documentation for output).
TCP_STATE_LABELS = {
    "LISTEN": "Socket waiting for inbound connections",
    "ESTABLISHED": "Active, connected session",
    "TIME_WAIT": "Closed recently; waiting out retransmission window",
    "CLOSE_WAIT": "Remote side closed; local app has not yet closed",
    "SYN_SENT": "Outbound connection attempt in progress",
    "SYN_RECEIVED": "Inbound connection attempt in progress",
}


def get_local_ips():
    """Return set of IP addresses bound to local interfaces (IPv4+IPv6)."""
    ips = set()
    try:
        for _name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family.name.startswith("AF_INET"):
                    ips.add(a.address)
    except Exception as exc:
        log.debug("net_if_addrs failed: %s", exc)
    return ips


def describe_state(status):
    return TCP_STATE_LABELS.get((status or "").upper(), "Other/unknown state")
