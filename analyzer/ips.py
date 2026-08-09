"""IP classification (Phase 5).

Classifies a remote IP as PRIVATE / LOOPBACK / LINK-LOCAL / MULTICAST /
PUBLIC using the stdlib `ipaddress` module. Analysis later prioritizes
external (public) connections; a public IP is a signal input, not a verdict.
"""

import ipaddress

from utils import logger

log = logger.get_logger("analyzer.ips")

PRIVATE = "PRIVATE"
LOOPBACK = "LOOPBACK"
LINK_LOCAL = "LINK-LOCAL"
MULTICAST = "MULTICAST"
PUBLIC = "PUBLIC"
UNSPECIFIED = "UNSPECIFIED"
UNKNOWN = "UNKNOWN"


def classify_ip(ip_str):
    """Return one of the class constants above for an IP string."""
    if not ip_str:
        return UNKNOWN
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        log.debug("unparseable IP: %r", ip_str)
        return UNKNOWN

    if ip.is_loopback:
        return LOOPBACK
    if ip.is_link_local:
        return LINK_LOCAL
    if ip.is_multicast:
        return MULTICAST
    if ip.is_unspecified:
        return UNSPECIFIED
    if ip.is_private:
        return PRIVATE
    return PUBLIC


def is_external(ip_str):
    """True when the IP is a routable public address (i.e., off-machine)."""
    return classify_ip(ip_str) == PUBLIC


def annotate(records):
    """Add `ip_class` and `is_external` to each record (mutates, returns list)."""
    for rec in records:
        cls = classify_ip(rec.get("remote_ip"))
        rec["ip_class"] = cls
        rec["is_external"] = cls == PUBLIC
    return records
