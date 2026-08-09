"""Process intelligence (Phases 7, 8, 9).

- Flags suspicious *execution locations* (e.g., Temp/Downloads) — a signal,
  never a "malware" determination.
- Recognizes configured system/normal process names and locations.
- Computes SHA-256 hashes of notable executables for stable identification
  (hash-and-store only; Feluda never executes or interacts with payloads).
"""

import hashlib
from pathlib import Path

from utils import logger
from utils.config_loader import settings

log = logger.get_logger("analyzer.processes")

# Files above this size are skipped for hashing to keep scans fast.
MAX_HASH_BYTES = 50 * 1024 * 1024


def _norm(path):
    return (path or "").lower()


def is_suspicious_location(exe_path):
    """True if the executable lives under a configured suspicious location."""
    p = _norm(exe_path)
    if not p:
        return False
    return any(sub in p for sub in settings().get("suspicious_location_substrings", []))


def is_normal_location(exe_path):
    p = _norm(exe_path)
    if not p:
        return False
    return any(sub in p for sub in settings().get("normal_location_substrings", []))


def is_known_system_process(name):
    n = _norm(name)
    return bool(n) and n in {_norm(x) for x in settings().get("system_process_names", [])}


def is_unknown_process(proc_info):
    """Heuristic: unrecognized name AND outside configured normal locations.

    'Unknown' is only a scoring input — plenty of legitimate software is not
    on the allow-list. Never treat this alone as a verdict.
    """
    if not proc_info:
        return True
    name = proc_info.get("name") or ""
    exe = proc_info.get("exe") or ""
    if is_known_system_process(name):
        return False
    if is_normal_location(exe):
        return False
    return True


def sha256_of_file(path):
    """Return the hex SHA-256 of a file, or "" on any failure."""
    if not path:
        return ""
    try:
        p = Path(path)
        if not p.is_file():
            return ""
        if p.stat().st_size > MAX_HASH_BYTES:
            log.debug("skip hashing large file: %s", path)
            return ""
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as exc:
        log.debug("hash failed for %s: %s", path, exc)
        return ""


def hash_notable_processes(records, min_risk_score=None):
    """Compute SHA-256 for processes whose score meets the config threshold."""
    if min_risk_score is None:
        min_risk_score = settings().get("thresholds", {}).get("hash_min_risk_score", 25)
    done = {}
    for rec in records:
        if rec.get("risk_score", 0) < min_risk_score:
            continue
        exe = (rec.get("proc_info") or {}).get("exe") or ""
        if not exe:
            continue
        if exe not in done:
            done[exe] = sha256_of_file(exe)
            if done[exe]:
                log.info("sha256 %s -> %s", exe, done[exe])
        rec["sha256"] = done[exe]
    return records
