"""Persistence / autorun / registry scanning (Phase 6).

Fully local and offline: stdlib `winreg` for Run keys, filesystem +
pywin32's WScript.Shell COM for `.lnk` resolution, Task Scheduler COM for
scheduled tasks, and `psutil.win_service_iter()` for the optional services
stretch check. No new dependencies, no network calls.

Every entry flows through the same rule-shaped functions as the other stages:
(triggered, points, reason). The cross-reference rule
("this persistence entry's exe is also a process Feluda already scored
against an external connection") is the highest-value signal in this phase —
a mechanism that both survives reboot *and* is actively talking out.

Reused rather than re-implemented:
  * Suspicious-location check -> analyzer.processes.is_suspicious_location
  * Cmdline obfuscation list  -> analyzer.lineage_analyzer._SUSPICIOUS_CMD_SNIPPETS
"""

import json
import os
import re
import winreg
from datetime import datetime, timezone
from pathlib import Path

import psutil

from utils import logger
from utils.config_loader import settings

from analyzer import processes as proc_analyzer
from analyzer import lineage_analyzer as _la

log = logger.get_logger("persistence")

from database.database import DB_PATH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS persistence_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,          -- registry_run | startup_folder | scheduled_task | service
    location_detail TEXT NOT NULL,      -- key path / folder / task name / service name
    value_name TEXT,
    raw_command TEXT,
    resolved_exe_path TEXT,
    exists_on_disk INTEGER NOT NULL DEFAULT 0,
    signed_state TEXT,                  -- signed | unsigned | unknown | not_checked
    triggered_signals TEXT NOT NULL DEFAULT '[]',
    risk_points INTEGER NOT NULL DEFAULT 0,
    matched_connection_id INTEGER,
    scanned_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_persist_scan ON persistence_entries(scanned_at);
"""


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path=None):
    import sqlite3
    conn = sqlite3.connect(str(db_path or DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


# ---------------------------------------------------------------------------
# 1. Registry Run keys
# ---------------------------------------------------------------------------

_RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKCU Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",     "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (WOW6432Node)"),
]


def enumerate_run_keys():
    """Yield entry dicts from every Run/RunOnce key. Each entry carries a
    `source_type='registry_run'`. Permission failures are captured into
    `errors` entries (source_type='error') so the report notes which keys were
    skipped rather than silently omitting them.
    """
    entries, errors = [], []
    for hive, subkey, label in _RUN_KEYS:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _type = winreg.EnumValue(key, i)
                    except OSError:
                        break               # no more values
                    i += 1
                    entries.append({
                        "source_type": "registry_run",
                        "location_detail": label,
                        "value_name": name,
                        "raw_command": str(value),
                        "resolved_exe_path": _extract_exe(str(value)),
                    })
        except PermissionError:
            errors.append({"source_type": "error",
                           "location_detail": label,
                           "value_name": "",
                           "raw_command": f"skipped: requires elevation ({label})",
                           "resolved_exe_path": ""})
            log.warning("Run key %s requires elevation — skipped", label)
        except FileNotFoundError:
            pass                              # key simply not present
        except OSError as exc:
            errors.append({"source_type": "error",
                           "location_detail": label,
                           "value_name": "",
                           "raw_command": f"skipped: {exc}",
                           "resolved_exe_path": ""})
    return entries, errors


_QUOTED_EXE = re.compile(r'^["\']([^"\']+\.exe)["\']', re.IGNORECASE)
_BARE_EXE = re.compile(r'([A-Za-z]:\\[^"\']+?\.exe|%[A-Za-z_]+%[^"\']+?\.exe)', re.IGNORECASE)


def _expand_env(path):
    """Expand Windows %-style env vars inside a command/path string.

    Uses function replacements so backslashes in the substituted value are
    never reinterpreted by the regex engine (C:\\Users\\... contains '\\\\U'
    which otherwise crashes re.sub).
    """
    for var in ("%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%", "%PROGRAMDATA%",
                "%USERPROFILE%", "%WINDIR%", "%PROGRAMFILES%", "%PROGRAMFILES(X86)%",
                "%PROGRAMW6432%", "%SYSTEMROOT%"):
        val = os.environ.get(var.strip("%"), "")
        if val and var.lower() in path.lower():
            # function replacement keeps '\' literal in `val`
            path = re.sub(re.escape(var), lambda _m, v=val: v, path,
                          flags=re.IGNORECASE)
    return path


def _extract_exe(raw):
    """Pull the executable path out of a Run-key command string.

    Handles both `"C:\\path\\x.exe" -arg` and bare `C:\\path\\x.exe -arg` forms,
    plus quoted-and-env-embedded forms like `"C:\\A\\b.exe" arg`."""
    raw = (raw or "").strip()
    m = _QUOTED_EXE.match(raw)
    if m:
        return _expand_env(m.group(1))
    m = _BARE_EXE.search(raw)
    if m:
        return _expand_env(m.group(1).strip())
    # bare env-prefixed path like %WINDIR%\\system32\\x.exe
    if raw.startswith("%"):
        return _expand_env(raw.split()[0].strip('"'))
    return ""


# ---------------------------------------------------------------------------
# 2. Startup folders (+ .lnk resolution via WScript.Shell COM)
# ---------------------------------------------------------------------------

_STARTUP_DIRS = [
    ("startup_folder (per-user)", Path(os.environ.get("APPDATA", "")) /
        r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ("startup_folder (all-users)", Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) /
        r"Microsoft\Windows\Start Menu\Programs\Startup"),
]


def _resolve_lnk(path):
    """Resolve a .lnk to its target path via WScript.Shell COM. Never raises."""
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(str(path))
        target = shortcut.TargetPath
        return _expand_env(target) if target else ""
    except Exception as exc:
        log.debug("lnk resolve failed for %s: %s", path, exc)
        return ""


def enumerate_startup_folders():
    """Yield startup-folder entries; .lnk files are resolved to their targets."""
    entries = []
    for label, folder in _STARTUP_DIRS:
        if not folder.is_dir():
            continue
        try:
            children = sorted(folder.iterdir())
        except OSError as exc:
            log.warning("startup folder unreadable (%s): %s", folder, exc)
            continue
        for f in children:
            loc = f"{label}\\{f.name}"
            if f.suffix.lower() == ".lnk":
                resolved = _resolve_lnk(f)
                entries.append({
                    "source_type": "startup_folder",
                    "location_detail": loc, "value_name": f.name,
                    "raw_command": f"[shortcut] -> {resolved}",
                    "resolved_exe_path": resolved,
                })
            else:
                # raw file dropped straight into Startup (bat/exe/vbs...)
                entries.append({
                    "source_type": "startup_folder",
                    "location_detail": loc, "value_name": f.name,
                    "raw_command": str(f),
                    "resolved_exe_path": str(f),
                })
    return entries


# ---------------------------------------------------------------------------
# 3. Scheduled Tasks via Task Scheduler COM
# ---------------------------------------------------------------------------

def _walk_task_folder(folder, depth=0, max_depth=8):
    """Recurse Task Scheduler folders; yields (task_name, enabled, triggers, exec_paths)."""
    for task in folder.GetTasks(0):       # 0 = don't include hidden only; all
        try:
            name = task.Name
            enabled = bool(task.Enabled)
            triggers = []
            try:
                td = task.Definition
                for t in td.Triggers:
                    triggers.append(_trigger_type_name(t.Type))
            except Exception:
                triggers.append("unknown")
            exec_paths = []
            try:
                for action in task.Definition.Actions:
                    p = getattr(action, "Path", "") or ""
                    if p:
                        exec_paths.append(_expand_env(p.strip('"')))
            except Exception:
                pass
            yield name, enabled, triggers, exec_paths
        except Exception as exc:
            log.debug("task read failed in %s: %s", folder.Path, exc)
            continue
    if depth >= max_depth:
        return
    for sub in folder.GetFolders(0):
        yield from _walk_task_folder(sub, depth + 1, max_depth)


def _trigger_type_name(t):
    # SCHEDULE trigger type constants (Task Scheduler schtypes)
    # Tolerably-complete mapping; unknowns surface as "type=N".
    TYPES = {1: "once", 2: "daily", 3: "weekly", 4: "monthly", 5: "monthly-dow",
             6: "idle", 7: "registration", 8: "boot", 9: "logon",
             10: "session-state-change", 11: "custom"}
    return TYPES.get(t, f"type{t}")


def enumerate_scheduled_tasks():
    """Enumerate scheduled tasks via COM. Returns entries; on any top-level
    failure returns a single error entry so the report notes the gap."""
    try:
        import win32com.client
        sched = win32com.client.Dispatch("Schedule.Service")
        sched.Connect()
        root = sched.GetFolder("\\")
    except Exception as exc:
        log.error("Task Scheduler COM unavailable: %s", exc)
        return [], [{"source_type": "error", "location_detail": "scheduled_task",
                     "value_name": "", "raw_command": f"skipped: {exc}",
                     "resolved_exe_path": ""}]
    entries = []
    try:
        for name, enabled, triggers, exec_paths in _walk_task_folder(root):
            for exe in (exec_paths or [""]):
                entries.append({
                    "source_type": "scheduled_task",
                    "location_detail": name,
                    "value_name": ",".join(triggers),
                    "raw_command": ("; ".join(exec_paths)) if exec_paths else "",
                    "resolved_exe_path": exe,
                    "task_enabled": enabled,
                    "triggers": triggers,
                })
    except Exception as exc:
        log.error("task enumeration failed: %s", exc)
    return entries, []


# ---------------------------------------------------------------------------
# 4. Services stretch check (opt-in)
# ---------------------------------------------------------------------------

def enumerate_services():
    """Flag services running binaries outside trusted vendor dirs or with
    unrecognized display names. Returns (entries, errors)."""
    entries = []
    trusted_dirs = [d.lower() for d in settings().get("persistence", {})
                    .get("trusted_exe_dirs", [])]
    name_allow = [s.lower() for s in settings().get("persistence", {})
                  .get("services_name_allowlist_substrings", [])]
    try:
        services = list(psutil.win_service_iter())
    except Exception as exc:
        log.error("win_service_iter failed: %s", exc)
        return [], [{"source_type": "error", "location_detail": "service",
                     "value_name": "", "raw_command": f"skipped: {exc}",
                     "resolved_exe_path": ""}]
    for svc in services:
        try:
            info = svc.as_dict()
        except Exception:
            continue
        binpath = (info.get("binpath") or "").strip('"').lower()
        name = (info.get("name") or "")
        display = (info.get("display_name") or "").lower()
        if not binpath:
            continue
        trusted = any(t in binpath for t in trusted_dirs)
        name_ok = any(a in name.lower() or a in display for a in name_allow) if name_allow else True
        if not trusted or not name_ok:
            entries.append({
                "source_type": "service",
                "location_detail": name,
                "value_name": info.get("display_name", ""),
                "raw_command": info.get("binpath", ""),
                "resolved_exe_path": _extract_exe(info.get("binpath", "")),
            })
    return entries, []


# ---------------------------------------------------------------------------
# Rule functions (spec §5)
# ---------------------------------------------------------------------------

_AUTO_NAME_RE = re.compile(r'^(\{[0-9A-Fa-f-]{20,}\}|[A-Za-z0-9]{16,})$')


def rule_untrusted_location(entry):
    """Persistence target lives under Temp/Downloads/Users\\Public etc.
    Reuses analyzer.processes.is_suspicious_location — no fork."""
    exe = entry.get("resolved_exe_path") or ""
    if not exe or not proc_analyzer.is_suspicious_location(exe):
        return False, 0, ""
    w = settings().get("persistence", {}).get("weights", {})
    pts = int(w.get("persistence_untrusted_location", 30))
    return True, pts, f"Persistence target runs from untrusted location: {exe}"


def rule_missing_or_unsigned(entry):
    """Target exe missing on disk (broken dropper artifact) or untrusted/unsigned.
    Authenticode check via stdlib ctypes WinVerifyTrust; unavailable -> 'unknown'
    (reported honestly rather than guessed).
    """
    exe = entry.get("resolved_exe_path") or ""
    w = settings().get("persistence", {}).get("weights", {})
    if not exe:
        return False, 0, ""
    exists = Path(exe).is_file()
    if not exists:
        pts = int(w.get("persistence_missing_or_unsigned_binary", 25))
        return True, pts, f"Persistence target no longer exists on disk: {exe}"
    signed_state = _check_signature(exe)
    if signed_state == "unsigned":
        pts = int(w.get("persistence_missing_or_unsigned_binary", 25))
        return True, pts, f"Persistence target has no valid Authenticode signature: {exe}"
    return False, 0, ""


def _check_signature(exe):  # pragma: no cover - depends on OS trust store
    """WinVerifyTrust via urlmon (stdlib ctypes). Returns signed/unsigned/unknown."""
    try:
        import ctypes
        from ctypes import wintypes

        WINTRUST_ACTION_GENERIC_VERIFY_V2 = ctypes.c_wchar_p(
            "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}")
        wintrust_struct_home = ctypes.sizeof(wintypes.WCHAR) * 4096  # safe oversize
        # Minimal WTD struct (subset sufficient for generic verify):
        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8)]
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD),
                        ("pcwszFilePath", wintypes.LPCWSTR)]
        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", wintypes.LPVOID),
                        ("pSIPClientData", wintypes.LPVOID), ("dwUIChoice", wintypes.DWORD),
                        ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                        ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                        ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD),
                        ("dwUIContext", wintypes.DWORD),
                        ("pSignatureSettings", wintypes.LPVOID)]
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), exe)
        data = WINTRUST_DATA(ctypes.sizeof(WINTRUST_DATA), None, None, 2, 0, 1,
                             ctypes.pointer(file_info), 0, None, None, 0, 0, None)
        result = ctypes.windll.wintrust.WinVerifyTrust(
            None, ctypes.byref(GUID(0x00AAC56B, 0xCD44, 0x11d0,
                                    (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))),
            ctypes.byref(data))
        return "signed" if result == 0 else ("unsigned" if result in (
            0x800B0100, 0x800B0109, 0x80096010) else "unknown")
    except Exception:
        return "unknown"


def rule_cmdline_obfuscation(entry):
    """Reuse Stage 4's snippet list against the persistence command string."""
    raw = (entry.get("raw_command") or "").lower()
    if not raw:
        return False, 0, ""
    for snip in _la._SUSPICIOUS_CMD_SNIPPETS:
        if snip in raw:
            w = settings().get("persistence", {}).get("weights", {})
            pts = int(w.get("persistence_cmdline_obfuscation", 30))
            return True, pts, (f"Persistence command contains obfuscation indicator "
                               f"'{snip}' (entry: {entry.get('location_detail')})")
    return False, 0, ""


def rule_matches_active_connection(entry, flagged_exes):
    """Cross-reference: this persistence entry's exe matches a process Feluda
    already scored >0 via the connection scan path — the strongest signal in
    this phase (survives reboot AND currently talking out)."""
    exe = (entry.get("resolved_exe_path") or "").lower()
    if not exe or exe not in {_e.lower() for _e in flagged_exes}:
        return False, 0, ""
    w = settings().get("persistence", {}).get("weights", {})
    pts = int(w.get("persistence_matches_active_connection", 50))
    return True, pts, (f"Persistence entry '{entry.get('location_detail')}' launches "
                       f"{exe} which is already flagged as making external connections")


def rule_suspicious_task_name(entry):
    """Random/GUID-looking scheduled task names on boot/logon triggers."""
    if entry.get("source_type") != "scheduled_task":
        return False, 0, ""
    if not entry.get("task_enabled", True):
        return False, 0, ""            # dead tasks can't persist anywhere
    triggers = {t.lower() for t in entry.get("triggers", [])}
    if not ({"boot", "logon"} & triggers):
        return False, 0, ""
    name = entry.get("location_detail", "")
    # take the leaf of a task path like "\Microsoft\...\{ABC-...}"
    leaf = name.rsplit("\\", 1)[-1]
    if _AUTO_NAME_RE.match(leaf):
        w = settings().get("persistence", {}).get("weights", {})
        pts = int(w.get("persistence_suspicious_task_name", 15))
        return True, pts, (f"Scheduled task leaf name '{leaf}' looks auto-generated "
                           f"(trigger: {'/'.join(entry.get('triggers', []))})")
    return False, 0, ""


RULES = [rule_untrusted_location, rule_missing_or_unsigned,
         rule_cmdline_obfuscation, rule_suspicious_task_name]


# ---------------------------------------------------------------------------
# Scan orchestration + storage
# ---------------------------------------------------------------------------

def _flagged_connection_exes():
    """Build the cross-reference set: every distinct exe_path from the history
    table seen with nonzero risk (any signal at all — cheap and defensible)."""
    from database import database as db
    try:
        with db._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT exe_path FROM history "
                "WHERE risk_score > 0 AND exe_path != ''").fetchall()
    except Exception as exc:
        log.error("cross-ref lookup failed: %s", exc)
        return []
    return [r["exe_path"] for r in rows]


def scan(include_services=False, active_exes=None, save=True):
    """Run a full persistence scan. Returns (entries_with_scores, errors).

    `active_exes` — optional iterable of exe paths to cross-reference; defaults
    to history-derived set. Cross-ref rule runs on every entry that clears all
    other checks (its absence shouldn't silence other signals).
    """
    entries, errors = [], []
    reg_entries, reg_errors = enumerate_run_keys()
    entries += reg_entries
    errors += reg_errors
    entries += enumerate_startup_folders()
    task_entries, task_errors = enumerate_scheduled_tasks()
    entries += task_entries
    errors += task_errors
    entries = [e for e in entries if e.get("source_type") != "service"]
    if include_services:
        svc_entries, svc_errors = enumerate_services()
        entries += svc_entries
        errors += svc_errors

    if active_exes is None:
        active_exes = _flagged_connection_exes()

    cfg_w = settings().get("persistence", {}).get("weights", {})
    for entry in entries:
        sigs, total = [], 0
        for rule in RULES:
            try:
                hit, pts, reason = rule(entry)
            except Exception as exc:
                log.error("persistence rule %s failed: %s", rule.__name__, exc)
                continue
            if hit:
                sigs.append(reason)
                total += pts
        hit, pts, reason = rule_matches_active_connection(entry, active_exes)
        if hit:
            sigs.append(reason)
            total += pts
            entry["matched_connection_id"] = _matched_history_id(entry)
        entry["exists_on_disk"] = 1 if Path(entry.get("resolved_exe_path", "")).is_file() else 0
        entry["signed_state"] = "unknown"
        if entry.get("exists_on_disk") and entry.get("resolved_exe_path", "").lower().endswith(".exe"):
            entry["signed_state"] = _check_signature(entry["resolved_exe_path"])
        entry["triggered_signals"] = sigs
        entry["risk_points"] = total
        entry["scanned_at"] = _now_iso()

    entries.sort(key=lambda e: e.get("risk_points", 0), reverse=True)
    log.info("persistence scan: %d entries, %d with signals, %d errors",
             len(entries), sum(1 for e in entries if e["risk_points"] > 0), len(errors))
    if save:
        save_entries(entries, errors)
    return entries, errors


def _matched_history_id(entry):
    """Resolve which history row the cross-reference matched (for the FK col)."""
    from database import database as db
    exe = (entry.get("resolved_exe_path") or "").lower()
    if not exe:
        return None
    try:
        with db._connect() as conn:
            row = conn.execute(
                "SELECT id FROM history WHERE lower(exe_path) = ? AND risk_score > 0 "
                "ORDER BY id DESC LIMIT 1", (exe,)).fetchone()
            return row["id"] if row else None
    except Exception:
        return None


def save_entries(entries, errors, db_path=None):
    """Persist the scan snapshot. Fresh-write per explicit invocation (no TTL —
    persistence surface changes rarely; rows accumulate by scanned_at)."""
    try:
        with _connect(db_path) as conn, conn:
            for e in entries + errors:
                conn.execute(
                    """INSERT INTO persistence_entries
                       (source_type, location_detail, value_name, raw_command,
                        resolved_exe_path, exists_on_disk, signed_state,
                        triggered_signals, risk_points, matched_connection_id, scanned_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        e.get("source_type", ""), e.get("location_detail", ""),
                        e.get("value_name", ""), e.get("raw_command", ""),
                        e.get("resolved_exe_path", ""), int(e.get("exists_on_disk", 0)),
                        e.get("signed_state", ""),
                        json.dumps(e.get("triggered_signals", [])),
                        int(e.get("risk_points", 0)), e.get("matched_connection_id"),
                        e.get("scanned_at", _now_iso()),
                    ),
                )
        log.info("persisted %d persistence rows", len(entries) + len(errors))
    except Exception as exc:
        log.error("persisting persistence entries failed: %s", exc)


def fetch_entries(limit=500, min_points=0, db_path=None):
    """Fetch most recent persistence scan snapshot rows."""
    try:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """SELECT * FROM persistence_entries
                   WHERE risk_points >= ? ORDER BY id DESC LIMIT ?""",
                (int(min_points), int(limit)),
            ).fetchall()
    except Exception as exc:
        log.error("fetch_entries failed: %s", exc)
        return []
    return [dict(r) for r in rows]


def latest_snapshot_at(db_path=None):
    """Return scanned_at of the most recent persistence scan (for monitor cadence)."""
    try:
        with _connect(db_path) as conn:
            row = conn.execute("SELECT MAX(scanned_at) AS m FROM persistence_entries").fetchone()
            return row["m"] if row and row["m"] else None
    except Exception:
        return None
