"""Connection collection (Phase 3) and connection-memory/store (Phase 15).

Uses psutil.net_connections() to read the local machine's own TCP/UDP
connections. Local-only scope: Feluda never scans, probes, or connects to
remote hosts.
"""

import socket
from collections import Counter

import psutil

from utils import logger

log = logger.get_logger("collector.connections")

STATUSES_OF_INTEREST = {"LISTEN", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECEIVED"}


def _raw_connections():
    try:
        return psutil.net_connections(kind="inet")
    except PermissionError:
        log.error("Access denied reading connections. Re-run from an elevated shell.")
        print("[Feluda] Access denied reading network connections. Run as Administrator.")
        return []
    except Exception as exc:  # psutil can raise platform-specific errors
        log.error("net_connections failed: %s", exc)
        return []


def _addr_fields(addr):
    if addr and len(addr) >= 2:
        return addr[0], addr[1]
    return None, None


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def collect_connections(include_reverse_dns=False, interesting_only=True):
    """Collect connections into the canonical record shape.

    Returns a list of dicts with keys:
      pid, local_ip, local_port, remote_ip, remote_port, status, conn_type, hostname
    """
    records = []
    for nc in _raw_connections():
        status = nc.status or ""
        if interesting_only and status and status not in STATUSES_OF_INTEREST and status != "NONE":
            continue
        lip, lport = _addr_fields(nc.laddr)
        rip, rport = _addr_fields(nc.raddr)
        rec = {
            "pid": nc.pid,
            "local_ip": lip,
            "local_port": lport,
            "remote_ip": rip,
            "remote_port": rport,
            "status": status or "NONE",
            "conn_type": "TCP" if nc.type == socket.SOCK_STREAM else ("UDP" if nc.type == socket.SOCK_DGRAM else str(nc.type)),
            "hostname": "",
        }
        if include_reverse_dns and rec["remote_ip"]:
            rec["hostname"] = _reverse_dns(rec["remote_ip"])
        records.append(rec)
    log.info("collected %d connections", len(records))
    return records


class ConnectionStore:
    """In-memory memory of seen connections across scans.

    Tracks how many distinct scans each connection key appears in, which
    powers the "repeated external connection" signal (Phase 15). A record
    that reappears across polls is a *signal*, not a verdict.
    """

    def __init__(self):
        self._seen = {}      # key -> number of scans it appeared in
        self._last_scan = set()

    @staticmethod
    def key(rec):
        return (rec.get("pid"), rec.get("local_port"), rec.get("remote_ip"), rec.get("remote_port"))

    def observe_scan(self, records):
        """Record one completed scan; returns per-key count of scans seen.

        A key is counted ONE per scan regardless of how many duplicate
        records carry it in that scan (dual-stack TCP+UDP or duplicate psutil
        rows must not advance the repeat counter faster than real time)."""
        keys = {self.key(rec) for rec in records}
        self._last_scan = keys
        counts = Counter()
        for k in keys:
            self._seen[k] = self._seen.get(k, 0) + 1
            counts[k] = self._seen[k]
        return counts

    def count_for(self, key):
        return self._seen.get(key, 0)

    def repeat_keys(self, min_scans):
        return {k for k, v in self._seen.items() if v >= min_scans and k in self._last_scan}
