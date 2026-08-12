# Phase 6: Persistence & Autorun Scanning Technical Specification

## Overview

Phase 6 implements offline, local Windows persistence & autorun mechanism scanning. It checks system startup locations to detect software configured to run automatically on system boot or user logon, scoring each entry with rule-based heuristics and cross-referencing persistence binaries against active process connections identified by Feluda's connection scanner.

---

## Enumerated Persistence Surfaces

1. **Registry Run / RunOnce Keys**:
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
   - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
   - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`

2. **Startup Folders**:
   - Per-user startup folder: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
   - All-users startup folder: `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
   - `.lnk` shortcut targets resolved via Windows `WScript.Shell` COM interface (`win32com.client`).

3. **Scheduled Tasks**:
   - Enumerates root folder tasks via Windows Task Scheduler COM interface (`Schedule.Service`).

4. **Windows Services (Opt-in `--services`)**:
   - Inspects running/configured Windows services (`psutil.win_service_iter()`) for binaries executing outside trusted system directories (`System32`, `SysWOW64`, `Program Files`).

---

## Scoring Rules & Signal Heuristics

| Signal | Score | Criteria |
|:---|:---:|:---|
| `persistence_untrusted_location` | +30 | Executable targets `Temp`, `AppData\Local\Temp`, `Downloads`, or `Users\Public`. |
| `persistence_missing_or_unsigned_binary` | +25 | File path does not exist on disk or missing digital signature. |
| `persistence_cmdline_obfuscation` | +30 | Contains powershell `-enc`, base64, hidden window flags, or command-chaining. |
| `persistence_matches_active_connection` | +50 | Persistence binary matches an active socket process currently making external connections. |
| `persistence_suspicious_task_name` | +15 | Scheduled task name contains randomized hex strings or typosquatted system names. |

---

## Storage Schema (`database/history.db`)

```sql
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
```
