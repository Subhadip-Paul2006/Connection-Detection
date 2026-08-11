"""Process-tree / parent-child lineage analysis (Phase 4, Stage 5).

Local-only: every record comes from psutil against the *current* process
table, so there's no cache and no risk of stale data (a walk per scan is
intentionally fresh). Each rule returns (triggered, points, reason) in the
same shape as Stages 1–4. Lines caught here are additive inputs into the same
0–100 score — never a verdict on their own.

Two reused conventions (no duplicates):
- suspicious locations: analyzer.processes.is_suspicious_location
- browser process names: browser_detector.known_browsers (config-driven list)
"""

import json
import time
from datetime import datetime, timezone

import psutil

from utils import logger
from utils.config_loader import settings

from analyzer import processes as proc_analyzer
from browser import browser_detector

log = logger.get_logger("analyzer.lineage")

# A parent appearing in the chain but outside the existing kill-chain list is
# still worth noting when it blankets a shell/browser parent.
LINEAGE_SIGNALS = [
    "office_spawned_shell",
    "browser_spawned_suspicious_binary",
    "unexpected_script_interpreter_parent",
    "orphaned_or_reparented_process",
    "unusual_chain_depth",
    "cmdline_obfuscation_indicator",
]


def _pcfg():
    return settings().get("lineage", {})


def _norm(s):
    return (s or "").lower()


def _norm_path(p):
    return _norm(p).replace("/", "\\")


def walk_lineage(pid):
    """Walk the parent chain of `pid`. Returns a roll record:

    {"pid", "chain", "is_partial_chain", "orphan_parent_pid", "signals",
     "risk_points", "scanned_at"}
    `chain` runs the process itself up through parents to PID 0/4 or wherever
    the walk exhausts — each link is {pid, name, exe_path, cmdline, create_time}.
    Process deaths/permission gaps/ppid races all collapse to is_partial_chain
    or early termination without ever raising.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    record = {
        "pid": pid,
        "chain": [],
        "is_partial_chain": False,
        "orphan_parent_pid": None,
        "signals": [],
        "risk_points": 0,
        "scanned_at": now_iso,
    }

    cfg = _pcfg()
    depth_limit = int(cfg.get("max_chain_depth", 6)) + 6  # allow slack
    # never walk past PID 4
    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        record["is_partial_chain"] = True
        return record

    # Working copy for the loop; always collect the current process first.
    current_pid = proc.pid
    previous_ppid = None
    visited = set()

    for _ in range(depth_limit):
        try:
            p = psutil.Process(current_pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            # Parent already exited or flunked permissions — the chain link is
            # absent, so previous link was dangling.
            record["is_partial_chain"] = True
            record["orphan_parent_pid"] = previous_ppid
            break

        info = {
            "pid": current_pid,
            "name": p.name() if not callable(getattr(p, "name", None)) else "",
            "exe_path": None,
            "cmdline": [],
            "create_time": None,
        }
        # name() can't be called on some pseudo targets (pid 0). psutil>=5.9 is
        # always callable, but guard anyway for robustness down to 4.
        try:
            info["name"] = p.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            info["name"] = "unknown"
        try:
            info["exe_path"] = p.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        try:
            info["cmdline"] = p.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        try:
            info["create_time"] = p.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        record["chain"].append(info)

        ppid = p.ppid()
        if not ppid or ppid <= 4:
            break  # hit root or pseudo-process — normal end of chain
        if ppid in visited:
            record["is_partial_chain"] = True
            record["orphan_parent_pid"] = ppid
            break      # ppid cycled mid-scan; treat as partial
        visited.add(current_pid)
        previous_ppid = ppid
        current_pid = ppid

    # Pit: chain stopped early only by depth_limit — caller should never see
    # this under normal depth defaults, but document the boundary anyway. not
    # orphaned; it's just a stopped walk at the limit.
    if len(record["chain"]) >= depth_limit and not record["is_partial_chain"]:
        record["is_partial_chain"] = True

    return record


# ---------------------------------------------------------------------------
# Rules — pure analysis on the chain (no process I/O)
# ---------------------------------------------------------------------------

def _names(chain):
    return [_norm(link.get("name")) for link in chain]


def rule_office_spawned_shell(record):
    """An office app spawned a shell/script-host descendant.

    Classic macro-malware pattern; high weight per spec §3.
    """
    cfg = _pcfg()
    office = {_norm(n) for n in cfg.get("office_processes", [])}
    shells = {_norm(n) for n in cfg.get("shell_and_script_hosts", [])}
    names = _names(record.get("chain", []))
    has_office = any(n in office for n in names)
    if not has_office:
        return False, 0, ""
    # any shell/script host later in the chain counts as "spawned"
    shell_hit = next((n for n in names if n in shells), None)
    if not shell_hit:
        return False, 0, ""
    of = names[next((i for i, n in enumerate(names) if n in office))]
    reason = (
        f"Office process '{of}' shares ancestry with shell/script host "
        f"'{shell_hit}' — Office-spawned shells are a common macro-malware pattern"
    )
    return True, int(cfg.get("weights", {}).get("office_spawned_shell", 45)), reason


def rule_browser_spawned_suspicious_binary(record):
    """A known browser process + a descendant that's a shell/script host or an
    exe running from a suspicious location.

    Reuses browser_detector.known_browsers + analyzer.processes.is_suspicious_location.
    """
    cfg = _pcfg()
    browser_names = set(browser_detector.known_browsers().keys())  # proc-name keys
    shells = {_norm(n) for n in cfg.get("shell_and_script_hosts", [])}
    names = _names(record.get("chain", []))
    has_browser = any(n in browser_names for n in names)
    if not has_browser:
        return False, 0, ""
    # shell descendant?
    shell_hit = next((n for n in names if n in shells), None)
    reason = None
    if shell_hit:
        reason = (
            f"Browser process chain contains shell/script host '{shell_hit}' — "
            "browser spawns shell is a red flag for client-side exploitation"
        )
    else:
        # exe from a suspicious location?
        locs = tuple(_norm_path(s) for s in
                     cfg.get("suspicious_location_keywords", []))
        for link in record.get("chain", []):
            exe = link.get("exe_path")
            if not exe:
                continue
            exelow = _norm_path(exe)
            if any(s in exelow for s in locs) and link is not record["chain"][0]:
                reason = (
                    f"Browser process chain contains a binary at suspicious "
                    f"location '{exe}' — common payload-drop pattern"
                )
                break
    if not reason:
        return False, 0, ""
    return True, int(cfg.get("weights", {}).get("browser_spawned_suspicious_binary", 35)), reason


def rule_unexpected_script_interpreter_parent(record):
    """The process itself is powershell/wscript/cscript.py-style interpreter
    whose immediate parent is not on the config allowlist.
    """
    cfg = _pcfg()
    shells = {_norm(n) for n in cfg.get("shell_and_script_hosts", [])}
    allowparents = {_norm(p) for p in cfg.get("allowed_script_parents", [])}
    chain = record.get("chain", [])
    if len(chain) < 2:
        return False, 0, ""
    leaf = _norm(chain[0].get("name"))
    parent = _norm(chain[1].get("name"))
    if leaf not in shells:
        return False, 0, ""
    if parent in allowparents:
        return False, 0, ""
    reason = (
        f"Script interpreter '{leaf}' has unexpected parent '{parent}' "
        f"(parent not on config allowlist of usual shell launchers)"
    )
    return True, int(cfg.get("weights", {}).get("unexpected_script_interpreter_parent", 25)), reason


def rule_orphaned_or_reparented(record):
    """Process lineage is partial (parent died / ppid reuse race) — an evasion
    pattern worth surfacing, not an error."""
    if not record.get("is_partial_chain"):
        return False, 0, ""
    cfg = _pcfg()
    opp = record.get("orphan_parent_pid")
    reason = (
        f"Process {record.get('pid')} chain ends early"
        + (f" — suspected reparent/orphan at ppid {opp}" if opp else "")
        + " (parent already exited at walk time)"
    )
    return True, int(cfg.get("weights", {}).get("orphaned_or_reparented_process", 20)), reason


def rule_unusual_chain_depth(record):
    """Externally-connected process sitting very deep in a spawn chain is a
    mild anomaly for EDR visibility.
    """
    cfg = _pcfg()
    limit = int(cfg.get("max_chain_depth", 6))
    depth = len(record.get("chain", []))
    if depth <= limit:
        return False, 0, ""
    reason = (
        f"Process chain depth {depth} exceeds configured threshold {limit}; "
        "long spawn chains for network-reaching processes are unusual"
    )
    return True, int(cfg.get("weights", {}).get("unusual_chain_depth", 10)), reason


_SUSPICIOUS_CMD_SNIPPETS = [
    "-encodedcommand", "-encodedcommands", "-windowstyle hidden",
    "-executionpolicy bypass", "-enc ", "-noprofile", "-noninteractive",
    "bypass", "hidden", "encoded", "oleobject", "powershell -e",
]


def rule_cmdline_obfuscation(record):
    """Encoded/pipeline-style command-line payloads anywhere in the chain.

    Every suspicious snippet is a pattern-level hit on a *lowercased* cmdline, so
    casings like `-Enc` vs `-e` are normalized before comparison.
    """
    cfg = _pcfg()
    for link in record.get("chain", []):
        cmdline = link.get("cmdline") or []
        joined = " ".join(_norm(x) for x in (cmdline or []))
        if not joined:
            continue
        for snip in _SUSPICIOUS_CMD_SNIPPETS:
            if snip in joined:
                pts = int(cfg.get("weights", {}).get("cmdline_obfuscation_indicator", 30))
                reason = (
                    f"Command line for pid {link.get('pid')} contains suspicious "
                    f"pattern '{snip}' — pipeline-style indicator of obfuscation"
                )
                return True, pts, reason
    return False, 0, ""


RULES = [
    rule_office_spawned_shell,
    rule_browser_spawned_suspicious_binary,
    rule_unexpected_script_interpreter_parent,
    rule_orphaned_or_reparented,
    rule_unusual_chain_depth,
    rule_cmdline_obfuscation,
]


def analyze(conn_record, save_to_db=True):
    """Walk the chain for a scanned connection record and run Stage 5 rules.

    Mutates the input record with:
        ["lineage"] = {pid, chain, is_partial_chain, orphan_parent_pid, signals, risk_points, scanned_at}
        ["risk_score"] += lineage risk_points
        ["rules_applied"]["lineage"] += lineage points (config-injected in
        "flags" as a dict of rule -> points)

    Returns (record, rule_fires) where rule_fires is {rule_name: (pts, reason)}
    for the flag/value dump.
    """
    cfg = _pcfg()
    weight_map = cfg.get("weights", {})

    if conn_record.get("pid") is None:
        return conn_record, {}

    # Collect chain (rule walk never raises)
    try:
        lineage = walk_lineage(conn_record["pid"])
    except Exception as exc:
        log.error("lineage walk failed for pid=%s: %s", conn_record["pid"], exc)
        return conn_record, {}

    fires = {}
    for rule in RULES:
        try:
            triggered, pts, reason = rule(lineage)
        except Exception as exc:
            log.error("lineage rule %s failed: %s", rule.__name__, exc)
            continue
        if triggered:
            fires[rule.__name__] = (pts, reason)

    lineage["signals"] = [reason for _r, (_p, reason) in fires.items()]
    lineage["risk_points"] = sum(pts for _r, (pts, _msg) in fires.items())

    conn_record["lineage"] = lineage
    # Fold into existing scoring — same additive pattern as Stages 1–4
    conn_record.setdefault("rules_applied", {})
    for name, (pts, reason) in fires.items():
        key = name.replace("rule_", "")
        conn_record["rules_applied"][key] = conn_record["rules_applied"].get(key, 0) + pts
        conn_record.setdefault("reasons", []).append(f"LINEAGE: {reason} (+{pts})")
    conn_record["risk_score"] = min(100, conn_record.get("risk_score", 0) + lineage["risk_points"])

    # Persist (no TTL — the recorded row is the only copy of a volatile
    # parent-chain snapshot)
    if save_to_db and fires:
        connection_id = conn_record.get("history_db_id")
        if connection_id is None:
            log.debug("lineage hits for pid=%s recorded but no history_db_id yet — "
                      "skipping DB write until the next scan with the FK available",
                      conn_record["pid"])
        else:
            save_lineage(connection_id, lineage, fires, db_path=None)
    return conn_record, fires


# ---------------------------------------------------------------------------
# Storage (history.db shares _connect; no separate DB)
# ---------------------------------------------------------------------------

_LINEAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS process_lineage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id INTEGER NOT NULL REFERENCES history(id),
    pid INTEGER NOT NULL,
    chain_json TEXT NOT NULL,
    is_partial_chain INTEGER NOT NULL DEFAULT 0,
    orphan_parent_pid INTEGER,
    triggered_signals TEXT NOT NULL,
    risk_points INTEGER NOT NULL,
    scanned_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lineage_scan ON process_lineage(scanned_at);
CREATE INDEX IF NOT EXISTS idx_lineage_conn ON process_lineage(connection_id);
"""


def save_lineage(connection_id, lineage, fires, db_path=None):
    """Persist a lineage record under the history.id key.

    `connection_id` must be the history.id of the matching history row, so
    call this after save_scan has inserted the current-system scan batch
    (cmd_scan and cmd_monitor do that automatically).
    """
    from database.database import _connect
    if connection_id is None:
        return
    payload = lineage.get("chain") or []
    try:
        with _connect(db_path) as conn, conn:
            conn.executescript(_LINEAGE_SCHEMA)
            conn.execute(
                """INSERT INTO process_lineage
                   (connection_id, pid, chain_json, is_partial_chain,
                    orphan_parent_pid, triggered_signals, risk_points, scanned_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    int(connection_id),
                    int(lineage.get("pid") or 0),
                    json.dumps(payload),
                    1 if lineage.get("is_partial_chain") else 0,
                    lineage.get("orphan_parent_pid"),
                    json.dumps(list(fires.keys())),
                    int(lineage.get("risk_points", 0)),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    except Exception as exc:
        log.error("save_lineage failed: %s", exc)


def fetch_lineage(connection_id, db_path=None):
    """Fetch the stored chain for a past history.id. Returns the parsed record."""
    from database.database import _connect
    try:
        with _connect(db_path) as conn, conn:
            conn.executescript(_LINEAGE_SCHEMA)
            row = conn.execute(
                """SELECT connection_id, pid, chain_json, is_partial_chain,
                          orphan_parent_pid, triggered_signals, risk_points, scanned_at
                   FROM process_lineage WHERE connection_id = ?
                   ORDER BY id DESC LIMIT 1""",
                (int(connection_id),),
            ).fetchone()
    except Exception as exc:
        log.error("fetch_lineage failed: %s", exc)
        return None
    if not row:
        return None
    row = dict(row)
    try:
        row["chain"] = json.loads(row.get("chain_json") or "[]")
        row["signals"] = json.loads(row.get("triggered_signals") or "[]")
    except json.JSONDecodeError:
        row["chain"] = []
        row["signals"] = []
    row["is_partial_chain"] = bool(row["is_partial_chain"])
    return row


# ---------------------------------------------------------------------------
# Timing helper — spec asks for the measured scan overhead of lineage walking
# ---------------------------------------------------------------------------

def scan_time_sample(records, save_to_db=False):
    """Walk lineages for a batch of connection records (which carry a pid) and
    return wall-clock seconds. Used during testing; monitor keeps calling this
    so impact on the poll loop is visible, not assumed.
    """
    t0 = time.monotonic()
    with_this = [r for r in records if r.get("pid") is not None]
    log.info("lineage walk over %d pids (of %d conn records)", len(with_this), len(records))
    for rec in with_this:
        analyze(rec, save_to_db=save_to_db)
    return time.monotonic() - t0
