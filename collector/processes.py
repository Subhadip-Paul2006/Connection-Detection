"""Process mapping (Phase 4).

Enriches connection records with owning-process details via psutil.Process,
using a per-scan PID cache to avoid repeated syscalls. Runs entirely against
the local machine.
"""

import psutil

from utils import logger

log = logger.get_logger("collector.processes")

# PID 0/4 are Windows pseudo-processes; a short static answer avoids errors.
_PSEUDO = {0: "System Idle Process", 4: "System"}


def get_process_info(pid, cache=None):
    """Return {pid, name, exe, username, create_time}; safe on any failure."""
    if cache is not None and pid in cache:
        return cache[pid]

    info = {"pid": pid, "name": "unknown", "exe": "", "username": "", "create_time": None}
    if pid is None:
        if cache is not None:
            cache[pid] = info
        return info
    if pid in _PSEUDO:
        info["name"] = _PSEUDO[pid]
        if cache is not None:
            cache[pid] = info
        return info

    try:
        proc = psutil.Process(pid)
        info["name"] = proc.name() or "unknown"
        try:
            info["exe"] = proc.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info["exe"] = ""
        try:
            info["username"] = proc.username() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info["username"] = ""
        try:
            info["create_time"] = proc.create_time()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            info["create_time"] = None
    except psutil.NoSuchProcess:
        info["name"] = "unknown (exited)"
    except psutil.AccessDenied:
        info["name"] = "unknown (access denied)"
    except Exception as exc:
        log.debug("process info failed for pid=%s: %s", pid, exc)

    if cache is not None:
        cache[pid] = info
    return info


def enrich_connections(records):
    """Attach `proc_info` to every connection record. Returns the same list."""
    cache = {}
    for rec in records:
        rec["proc_info"] = get_process_info(rec.get("pid"), cache=cache)
    log.info("enriched %d records (%d unique pids)", len(records), len(cache))
    return records
