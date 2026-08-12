# Feluda — Workflow & Architecture

This document explains **how Feluda actually works**, **which part does what**,
and **what each file is responsible for**, with diagrams.

> Reminder baked into every layer: Feluda is a **monitoring/triage** tool. It
> emits *signals with explicit reasons* — never "malware" verdicts, and it
> never scans/probes/connects to remote hosts (purely local `psutil` reads).

---

## Contents
1. [Big picture](#1-big-picture)
2. [The 5-layer pipeline](#2-the-5-layer-pipeline)
3. [Module dependency graph](#3-module-dependency-graph)
4. [File-by-file responsibility map](#4-file-by-file-responsibility-map)
5. [Data shapes that travel through the pipeline](#5-data-shapes-that-travel-through-the-pipeline)
6. [Command mode workflows (flowcharts)](#6-command-mode-workflows-flowcharts)
   - [`scan`](#61-scan)
   - [`monitor`](#62-monitor)
   - [`baseline`](#63-baseline)
   - [`history`](#64-history)
   - [`export`](#65-export)
7. [The rule engine in detail](#7-the-rule-engine-in-detail)
8. [Risk scoring & banding](#8-risk-scoring--banding)
9. [Database schema](#9-database-schema)
10. [Execution trace of a single scan](#10-execution-trace-of-a-single-scan)
11. [How config drives behavior](#11-how-config-drives-behavior)

---

## 1. Big picture

```
┌──────────────────────────────────────────────────────────────────────┐
│                              USER (CLI)                               │
│   python main.py {scan | monitor | baseline | history | export}      │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │ argparse dispatch (5 sub-commands)
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│   LAYER 1 — COLLECT      collector/connections.py + processes.py      │
│   Read local TCP/UDP sockets → attach owning process (PID→name/exe)   │
└────────────────────────────────┬─────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│   LAYER 2 — ANNOTATE     analyzer/ips.py + analyzer/ports.py          │
│   Tag each record: ip_class (PUBLIC/PRIVATE/…), port service, flags   │
└────────────────────────────────┬─────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│   LAYER 3 — ANALYZE      analyzer/rules.py + processes.py + risk_score.py│
│   Additive weighted rules → reasons[] + risk_score (0–100) + level     │
└────────────────────────────────┬─────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│   LAYER 4 — PRESENT/ACT  utils/formatting.py + monitor/realtime.py    │
│   rich tables, boxed alert panels, log_detection() events             │
└────────────────────────────────┬─────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│   LAYER 5 — STORE/EXPORT database/database.py + reports/              │
│   SQLite history, learned baseline, CSV / JSON / HTML audit report    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. The 5-layer pipeline

Every fully-analyzed record passes through the same fixed pipeline. `scan`,
`monitor`, and `baseline` all share it via `monitor/pipeline.py::run_scan` —
this is the single source of truth for "one complete scan".

```
RAW SOCKETS                RECORD DICT                ANALYZED RECORD
(psutil)  ──collect──▶  pid/ip/port/status  ──enrich──▶  +proc_info
      ──ips.annotate──▶  +ip_class +is_external
      ──ports.annotate──▶ +port_service +port_unusual_remote
      ──rules.analyze──▶  +rules_applied{} +reasons[] +risk_score +risk_level
                        +sha256 (if score >= hash_min_risk_score)
```

Steps and owning functions:

| # | Step | Function | File |
|---|------|----------|------|
| 1 | Collect sockets | `collect_connections()` | `collector/connections.py` |
| 2 | Enrich with process | `enrich_connections()` | `collector/processes.py` |
| 3 | Classify IP | `ips.annotate()` | `analyzer/ips.py` |
| 4 | Tag ports | `ports.annotate()` | `analyzer/ports.py` |
| 5 | Track repeats | `store.observe_scan()` | `collector/connections.py` (`ConnectionStore`) |
| 6 | Apply rules + score | `rules.analyze()` → `risk_score.apply_score()` | `analyzer/rules.py` + `risk_score.py` |
| 7 | Hash notable exes | `hash_notable_processes()` | `analyzer/processes.py` |
| 8 | Persist | `save_scan()` | `database/database.py` |
| 9 | Render/alert/export | `render_*`, `run_monitor`, `export_*` | `utils/formatting.py`, `monitor/realtime.py`, `reports/*` |

---

## 3. Module dependency graph

Direction of arrows: `A ──imports──▶ B` means **A depends on B** (B is "lower level").
Thick vertical spine is the hot path executed per scan.

```
                          main.py  (CLI: argparse → 5 cmd_* handlers)
                             │
        ┌────────────────────┼──────────────────────────────┐
        ▼                    ▼                               ▼
 monitor/pipeline.py   monitor/realtime.py            reports/{csv,json,html}
  (scan unified        (loop + alerting)               export_*()
   pipeline)                 │                               │
        │                    │                               ▼
        │                    │                        utils/formatting.py
        ▼                    ▼                          (render tables/panels,
 collector/*            analyzer/*                        build_connection_payload,
  connections.py ──────▶  ips.py                            render_html_report)
  processes.py           ports.py
        │                rules.py ───────┐
        │                processes.py    │
        ▼                risk_score.py   ▼
 utils/config_loader.py         utils/logger.py
   (settings() singleton)        (get_logger, log_detection,
        │                          RotatingFileHandler → logs/feluda.log)
        ▼
 config/rules.json  ◀── single source of truth for weights/ports/thresholds

                     database/database.py
                     save_scan / fetch_history /
                     create_baseline / load_baseline
                               │
                               ▼
                     database/history.db (SQLite)
```

Key note: `utils/formatting.py::build_connection_payload()` is the shared
"flatten analyzed record → export row" function used identically by
**sqlite insert, CSV, JSON, and the HTML report** — one contract, four sinks.

---

## 4. File-by-file responsibility map

Grouped by package, in dependency order (leaf utilities first).

| File | Responsibility | Key public functions / objects |
|------|----------------|--------------------------------|
| `config/rules.json` | **Single source of truth** for every tunable: well-known ports, unusual ports, suspicious/normal path substrings, system process allow-list, rule weights, thresholds, risk bands, poll interval, export dir. Consumed by 7 modules; never parsed ad-hoc — always via `settings()`. | JSON keys: `rule_weights`, `thresholds`, `risk_bands`, `well_known_ports`, … |
| `utils/config_loader.py` | Load & **merge** `rules.json` over built-in `DEFAULTS` (deep dict merge). Exposes cached singleton `settings()` so every module sees identical config without re-reading the file. Falls back to defaults on missing/corrupt file. | `Settings.get/[]`, `load_config(path)`, `settings()` |
| `utils/logger.py` | Structured logging. Lazily builds a `RotatingFileHandler` (`logs/feluda.log`, 1 MB × 3) + stderr stream once per process. `log_detection(rec)` writes one canonical detection-event line per alert. | `get_logger(name)`, `log_detection(record)`, `logger` facade |
| `utils/formatting.py` | **Presentation-layer contract** — engine-neutral builders + rich rendering. `build_connection_payload()` is the canonical flat dict used by DB insert and every exporter. `render_connections_table()`, `render_alert_panel()`, `render_html_report()` turn analyzed records into rich/HTML output. Enforces the "signals, not verdicts" wording everywhere. | `utc_now_iso()`, `fmt_addr()`, `risk_color()`, `build_connection_payload()`, `render_*()` |
| `collector/connections.py` | **Phase 3**: `psutil.net_connections()` → canonical record list (pid, local/remote ip:port, status, conn_type). Handles permission errors. `ConnectionStore` = **Phase 15**: in-memory cross-scan memory that counts how many scans each connection key appears in and reports `repeat_keys(min_scans)`. | `collect_connections()`, `ConnectionStore.observe_scan/repeat_keys`, `STATUSES_OF_INTEREST` |
| `collector/processes.py` | **Phase 4**: PID → process metadata via `psutil.Process`. Per-scan PID dict cache avoids repeated syscalls (44 unique PIDs vs 209 records in a real run). Special-cases PID 0/4 pseudo-processes; every psutil access wrapped in try/except. | `get_process_info(pid, cache)`, `enrich_connections(records)` |
| `collector/network.py` | **Phase 1 support**: authoritative TCP-state label table + interface IP listing. `TCP_STATE_LABELS` is the human-readable legend for LISTEN/ESTABLISHED/TIME_WAIT/CLOSE_WAIT/SYN_SENT/SYN_RECEIVED. | `TCP_STATE_LABELS`, `get_local_ips()`, `describe_state(status)` |
| `analyzer/ips.py` | **Phase 5**: classify each `remote_ip` as PRIVATE/LOOPBACK/LINK-LOCAL/MULTICAST/UNSPECIFIED/PUBLIC/UNKNOWN via stdlib `ipaddress`. `annotate()` stamps `ip_class` + `is_external` on every record — the flag that gates most rules. | `classify_ip()`, `is_external()`, `annotate()` |
| `analyzer/ports.py` | **Phase 6**: map `remote_port` → service label from config; detect configured "unusual ports". Adds `port_service`, `port_unusual_remote`. (Framing coded in docstring: unusual port = signal, never proof of malice.) | `service_name()`, `is_unusual_remote_port()`, `annotate()` |
| `analyzer/processes.py` | **Phases 7/8/9**: suspicious location check (`Temp`/`Downloads`/`Users\Public`…), normal location check (`Program Files`/`Windows`…), known system process names, combined `is_unknown_process()` heuristic, and SHA-256 hashing of notable executables (hash-and-store only, 50 MB cap, cached per-exe path). | `is_suspicious_location()`, `is_normal_location()`, `is_unknown_process()`, `sha256_of_file()`, `hash_notable_processes()` |
| `analyzer/rules.py` | **Phase 10**: the additive, weighted **rule engine**. Precomputes `ext_per_pid` burst counts, then evaluates 6 rules in fixed `RULE_ORDER`, each contributing a weight + a human-readable reason (with the `+N` weight shown). Applies `risk_score.apply_score()` per record and triggers process hashing. | `RULE_ORDER`, `_add()`, `analyze(records, baseline, repeat_keys, hash_processes)` |
| `analyzer/risk_score.py` | **Phase 11**: sums `rules_applied` → clamps to 0–100 → maps to band via config `risk_bands` (checks CRITICAL→HIGH→MEDIUM→LOW). Explicitly documented as a heuristic score, never a probability. | `apply_score(record)`, `band_for_score(score)` |
| `database/database.py` | **Phases 14 & 16**: SQLite persistence + baseline learning. `save_scan()` inserts analyzed rows; `fetch_history()` reads back; `create_baseline()` learns `process:remote_port` patterns from external connections; `load_baseline()` returns the known set; `_connect()` bootstraps schema + indexes on every use. | `baseline_key()`, `save_scan()`, `fetch_history()`, `create_baseline()`, `load_baseline()`, `clear_baseline()` |
| `monitor/pipeline.py` | **The shared scan glue.** `run_scan()` wires collector → annotate → store → rules → hash → sort (risk desc). Lazily holds a module-level `ConnectionStore` so successive `run_scan` calls in one process share repeat memory. Used identically by `scan`, `baseline`, and `export`. | `run_scan(use_baseline, repeat_keys, hash_processes)` |
| `monitor/realtime.py` | **Phase 13**: the polling loop. Per tick: collect → enrich → annotate → observe_scan → repeat_keys → analyze → sort → save → diff vs previous scan → alert (boxed rich panels) on **new** records ≥ `alert_min_risk_score` whose status is an active session → sleep. `Ctrl+C` exits cleanly. | `run_monitor(interval, alert_min, once, show_table, use_baseline)`, `ALERT_STATUSES` |
| `reports/csv_export.py` | **Phase 18a**: write flattened records to CSV using `build_connection_payload()`; joins `reasons` with `"; "`; raises on I/O failure after logging. | `export_csv(records, path)`, `FIELDS` |
| `reports/json_export.py` | **Phase 18b**: dump flattened records as pretty JSON (`default=str` to survive datetimes/sets). | `export_json(records, path)` |
| `reports/html_export.py` | **Phase 18c**: render self-contained dark-themed `audit_report.html` via `render_html_report()`, with optional summary box. | `export_html(records, path, summary, title)` |
| `main.py` | **Entry point.** Builds argparse with 5 sub-commands, dispatches to `cmd_scan/monitor/baseline/history/export`, prints the risk-band summary line, handles `Ctrl+C` → exit 130. Adds project root to `sys.path` so subpackages import from anywhere. | `main()`, `cmd_*()`, `_summary_line()` |
| 6 × `__init__.py` | Package markers so `collector`, `analyzer`, `monitor`, `database`, `reports`, `utils` are importable under the project root inserted by `main.py`. | — |

_Supporting dirs:_ `logs/feluda.log` (rotating structured event log),
`database/history.db` (SQLite: `history` + `baseline` tables),
`exports/` (csv/json/html output, created on demand).

---

## 5. Data shapes that travel through the pipeline

One uniform record dict flows end-to-end and progressively accumulates fields.

**Stage A — after `collect_connections()`** (raw)
```json
{ "pid": 8368, "local_ip": "192.168.1.2", "local_port": 52144,
  "remote_ip": "172.217.114.4", "remote_port": 443,
  "status": "ESTABLISHED", "conn_type": "TCP", "hostname": "" }
```

**Stage B — after `enrich_connections()`** (adds `proc_info`)
```json
{ ... "proc_info": { "pid": 8368, "name": "language_server_windows_x64.exe",
      "exe": "D:\\Antigravity IDE\\...\\language_server_windows_x64.exe",
      "username": "DESKTOP\\SUBHADIP PAUL", "create_time": 1723198800.1 } }
```

**Stage C — after `ips.annotate() + ports.annotate()`**
```json
{ ... "ip_class": "PUBLIC", "is_external": true,
  "port_service": "HTTPS", "port_unusual_remote": false }
```

**Stage D — after `rules.analyze()`** (final analyzed record)
```json
{ ... "rules_applied": {"external_unknown_process": 30,
                         "multiple_external_connections": 10,
                         "outside_baseline": 15},
  "reasons": ["External (public) connection from unrecognized process '…' (+30)",
              "'…' holds 4 external connections (>= 3) (+10)",
              "'…:443' is outside the learned baseline (+15)"],
  "baseline_hit": false,
  "risk_score": 55, "risk_level": "HIGH",
  "sha256": "...", "timestamp": "2026-08-09T02:55:00.54+00:00" }
```

**Stage E — `build_connection_payload()`** flatten (used by DB + all 3 exporters)
```json
{ "timestamp": "...", "pid": 8368, "process_name": "...", "exe_path": "...",
  "sha256": "...", "local_ip": "...", "local_port": 52144, "remote_ip": "...",
  "remote_port": 443, "status": "ESTABLISHED", "ip_class": "PUBLIC",
  "is_external": true, "risk_score": 55, "risk_level": "HIGH",
  "reasons": [ ... ], "baseline_hit": false }
```

---

## 6. Command mode workflows (flowcharts)

### 6.1 `scan`

```
scan --all? --no-baseline?
        │
        ▼
  monitor.pipeline.run_scan()
        │
        ├─ collector.connections.collect_connections()      ──▶ [A records]
        ├─ collector.processes.enrich_connections()         ──▶ [B +proc_info]
        ├─ analyzer.ips.annotate()                          ──▶ [C +ip_class/is_external]
        ├─ analyzer.ports.annotate()                        ──▶ [C +port_service/port_unusual]
        ├─ store.observe_scan() + store.repeat_keys(3)      ──▶ repeat_keys set
        ├─ database.load_baseline()  (unless --no-baseline) ──▶ baseline set
        └─ analyzer.rules.analyze()                         ──▶ [D fully analyzed]
                      │
                      ▼
        _summary_line() band counts (LOW/MED/HIGH/CRIT)
                      │
                      ▼
   filter rows (drop quiet LISTEN unless --all)
                      │
                      ▼
   utils.formatting.render_connections_table(show_all=True)
                      │
                      ▼
              rich table → stdout
        
   (no DB write, no alerts, no export — read-only snapshot)
```

### 6.2 `monitor`

```
monitor --interval N --once --no-baseline
        │
        ▼
 monitor.realtime.run_monitor()
        │
        ►────── loop (n += 1) ──────────────────────────────────────────┐
        │     collect → enrich → ips.annotate → ports.annotate          │
        │     store.observe_scan → repeat_keys                          │
        │     load_baseline → rules.analyze → sort by risk desc         │
        │     database.save_scan(all records)   ← persist every tick    │
        │                                                                 │
        │     current = {key(r)}                                          │
        │     new  = current − previous                                   │
        │     hits = new ∩ {score ≥ alert_min} ∩ {active status}          │
        │                                                                 │
        │     print "[scan n] totals" line                                │
        │     for r in hits:  logger.log_detection(r)                     │
        │                    print render_alert_panel(r)    ← boxed alert │
        │     if once: print snapshot table; break                        │
        │     previous = current                                          │
        │     sleep(interval)                                             │
        └─────────────────────────────────────────────────────────────────┘
                    │
              Ctrl+C ──▶ "Monitor stopped by user." (clean exit)
```

### 6.3 `baseline`

```
baseline
   │
   ▼
run_scan(use_baseline=False)     ← analyze WITHOUT any baseline so the
   │                               currently-normal patterns aren't penalized
   ▼
database.create_baseline(records)
   │   keep only is_external=True AND remote_port is not None
   │   key = f"{process_name.lower()}:{remote_port}"
   │   INSERT OR IGNORE into baseline table  →  added count
   ▼
total = len(load_baseline())  →  "Baseline updated: +N new patterns, M total"
   
Effect on all FUTURE scans/monitor runs:
  external connection whose "name:port" ∉ baseline  ──▶ +15 outside_baseline signal
```

### 6.4 `history`

```
history --limit 50 --level HIGH
   │
   ▼
database.fetch_history(limit, level)
   │   SELECT * FROM history [WHERE risk_level=?] ORDER BY id DESC LIMIT ?
   ▼
rich Table per row (oldest→newest after reverse)
   │
   ▼
+ "Total history rows in DB: N"
```

### 6.5 `export`

```
export --format csv|json|html|all   --no-baseline
   │
   ▼
run_scan(...)                          ← fresh analyzed records
   │
   ├─ format in (csv , all) → reports.csv_export.export_csv  → exports/connections.csv
   ├─ format in (json, all) → reports.json_export.export_json → exports/connections.json
   └─ format in (html, all) → reports.html_export.export_html → exports/audit_report.html
                                  (summary = {total, external, MEDIUM+}, browser_url_rows, persistence_rows)
   ▼
print each written path
```

### 6.6 `persistence`

```
persistence --services? --all? --limit 80
   │
   ▼
persistence_scanner.scan(include_services, save=True)
   │
   ├─ enumerate_run_keys()         ──▶ HKCU/HKLM Run & RunOnce keys
   ├─ enumerate_startup_folders()  ──▶ Startup folder .lnk targets (WScript.Shell COM)
   ├─ enumerate_scheduled_tasks() ──▶ Task Scheduler COM root folder walk
   └─ enumerate_services()        ──▶ psutil win_services outside trusted dirs (if --services)
   │
   ▼
score_entry() + cross_reference() against active connection exes
   │
   ▼
save_entries() sqlite persistence to database/history.db
   │
   ▼
utils.formatting.render_persistence_table()
```

---

## 7. The rule engine in detail

`analyzer/rules.py::analyze()` evaluates 6 additive rules in a fixed order.
Each rule calls `_add(rec, key, weight, reason)` which writes both the weight
into `rules_applied{}` and a readable reason into `reasons[]`.

```
for each record:
  ┌─ R1 external_unknown_process          +30   (is_external AND is_unknown_process)
  │      "External (public) connection from unrecognized process 'X'"
  ├─ R2 unusual_remote_port               +20   (port on configured watchlist)
  │      "Unusual remote port 4444 (service: unrecognized)"
  ├─ R3 suspicious_location               +25   (exe under Temp/Downloads/Users\Public)
  │      "Executable running from suspicious location: C:\Users\...\Temp\..."
  ├─ R4 multiple_external_connections     +10   (ext_per_pid[pid] ≥ 3, precomputed Counter)
  │      "'X' holds 6 external connections (>= 3)"
  ├─ R5 repeated_connection               +10   (this key already in repeat_keys)
  │      "Connection repeatedly reappears across polling intervals"
  └─ R6 outside_baseline                  +15   (baseline set loaded AND
         "'X:443' is outside the learned baseline"   "name:port" ∉ baseline)
  
  apply_score(rec)   → sum weights → clamp 0–100 → band
```

Supporting inputs each rule depends on:

| Rule | Needs | Produced by |
|------|-------|-------------|
| R1 | `is_external`, `proc_info` | ips.annotate, collector.processes |
| R2 | `port_unusual_remote`, `port_service` | ports.annotate |
| R3 | `proc_info.exe` | collector.processes |
| R4 | `is_external`, `pid`, `ext_per_pid` | rules.py pre-pass |
| R5 | repeat_keys from `ConnectionStore` | collector.connections |
| R6 | baseline set | database.load_baseline |

`RULE_ORDER` guarantees the deterministic order above so the printed reason
list is stable between runs.

---

## 8. Risk scoring & banding

```
rules_applied = {external_unknown_process: 30,
                 multiple_external_connections: 10,
                 outside_baseline: 15}
                 │
                 ▼ sum
               raw = 55
                 │
                 ▼ clamp(0,100)
            risk_score = 55
                 │
                 ▼ band_for_score()
            checks CRITICAL(75-100) → no
                    HIGH(50-74)     → yes
                 │
                 ▼
            risk_level = "HIGH"
```

| Score | Band | rich color |
|-------|------|------------|
| 0–24 | LOW | green |
| 25–49 | MEDIUM | yellow |
| 50–74 | HIGH | red |
| 75–100 | CRITICAL | bold red |

All band cutoffs come from `config/rules.json :: risk_bands` and can be
re-tuned without code changes. The score is **heuristic** — a sum of weights —
never a "probability of malware".

---

## 9. Database schema

```
database/history.db (SQLite)

TABLE history                         TABLE baseline
┌───────────────┬────────────┐        ┌──────────────┬────────┐
│ id            │ PK         │        │ key          │ PK     │ e.g. "chrome.exe:443"
├───────────────┼────────────┤        ├──────────────┼────────┤
│ timestamp     │ TEXT       │        │ process_name │ TEXT   │
│ pid           │ INTEGER    │        │ remote_port  │ INTEGER│
│ process_name  │ TEXT       │        │ created_at   │ TEXT   │
│ exe_path      │ TEXT       │        └──────────────┴────────┘
│ sha256        │ TEXT       │
│ local_ip      │ TEXT       │       Indexes on history:
│ local_port    │ INTEGER    │         idx_history_ts  (timestamp)
│ remote_ip     │ TEXT       │         idx_history_pid (pid)
│ remote_port   │ INTEGER    │
│ status        │ TEXT       │
│ risk_score    │ INTEGER    │
│ risk_level    │ TEXT       │
│ signals       │ TEXT       │ ("; "-joined reasons)
└───────────────┴────────────┘
```

- `save_scan()` inserts every analyzed record on every monitor tick.
- `create_baseline()` learns `process:remote_port` (external only, port present).
- `load_baseline()` returns a `set` of keys consumed by rule R6.

---

## 10. Execution trace of a single scan

Annotated trace of a real `python main.py scan` on this machine (run with `--no-baseline`, log timestamps stripped):

```
main.py
 └─ cmd_scan(args)
    └─ monitor.pipeline.run_scan()
       ├─ ConnectionStore() (lazy, module-level)
       ├─ collector.connections.collect_connections()
       │     [psutil.net_connections(kind="inet")]
       │     → 209 raw records                    "collected 209 connections"
       ├─ collector.processes.enrich_connections()
       │     per-PID cache, ~44 unique PIDs       "enriched 209 records (44 unique pids)"
       ├─ analyzer.ips.annotate()
       ├─ analyzer.ports.annotate()
       ├─ store.observe_scan(records) → repeat_keys = store.repeat_keys(3)
       ├─ database.load_baseline()           (skipped on --no-baseline)
       ├─ analyzer.rules.analyze()
       │     ext_per_pid Counter
       │     per record: R1..R6 → apply_score
       │     analyzer.processes.hash_notable_processes(threshold=25)
       │     → "sha256 C:\Program Files\...\Arc.exe -> 599a3bca…" (once per exe)
       │     → "analyzed 209 records; 20 at MEDIUM+"
       └─ sort key=risk_score desc
    └─ _summary_line(records)
        total=209 external=43 listen=52 | LOW:189 MED:20 HIGH:0 CRIT:0
    └─ render_connections_table(rows, show_all=True) → rich table
```

Cross-checked against native tooling: `netstat -ano` returned the same PIDs
(e.g. 23184, 12592, 21788 with ESTABLISHED :443 rows), so Feluda's view
matches Windows ground truth (Plan Phase 2 requirement).

---

## 11. How config drives behavior

`utils/config_loader.settings()` loads `config/rules.json` once and every
analytic decision reads from it. Nothing numeric is hard-coded in logic files.

| Config key | Used by | Effect when changed |
|------------|---------|---------------------|
| `well_known_ports` | `analyzer/ports.py` | New service labels, which ports look "normal" |
| `unusual_remote_ports` | `analyzer/ports.py` → rule R2 | Add/remove ports that get the +20 unusual-port signal |
| `suspicious_location_substrings` | `analyzer/processes.py` → R3 | Change where an exe must live to get +25 |
| `normal_location_substrings` | `analyzer/processes.py` → R1 | Widen/narrow what counts as a "known" install dir |
| `system_process_names` | `analyzer/processes.py` → R1 | Allow-list names that never count as "unrecognized" |
| `rule_weights.*` | `analyzer/rules.py` | Tune any of the 6 rule point values |
| `thresholds.multiple_external_connections_min` | R4 pre-pass | Burst-count sensitivity (default 3) |
| `thresholds.repeated_connection_min_scans` | `ConnectionStore.repeat_keys` | How many polls before "reappears" fires |
| `thresholds.hash_min_risk_score` | `analyzer/processes.py` | Minimum score before exe is SHA-256 hashed |
| `thresholds.alert_min_risk_score` | `monitor/realtime.py` | Minimum score to raise a boxed alert |
| `risk_bands` | `analyzer/risk_score.py` | Move LOW/MED/HIGH/CRIT cutoffs |
| `monitor.poll_interval_seconds` | `monitor/realtime.py` | Default monitor sleep between ticks |
| `export.directory` | `main.py::cmd_export` | Where exports land |

`Settings.get(key, default)` merges user keys over built-in defaults, so a
partial `rules.json` still runs safely; if the file is missing or malformed,
Feluda prints a notice and falls back to `DEFAULTS` rather than crashing.

---

### TL;DR

```
raw sockets ──collector──▶ records ──analyzer──▶ scored records ──formatting──▶ CLI tables
                │                 │                    │
             ConnectionStore   rules +            database.save_scan ──▶ history.db
             (repeat memory)   risk_score              │
                                               reports/* ──▶ csv / json / audit_report.html
             baseline learned via main.py baseline ──▶ database.baseline
             rules.json read via settings() drives every weight & threshold
```

Everything is local, additive, explainable, and tunable from one config file.
