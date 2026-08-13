# Feluda — Workflow & Architecture

This document explains **how Feluda actually works**, **which part does what**, and **what each file is responsible for**, complete with architectural diagrams and data flow specifications.

> Reminder baked into every layer: Feluda is a **monitoring/triage** tool. It emits *signals with explicit reasons* — never "malware" verdicts, and it never performs unauthorized remote network scans (purely local `psutil`, Winreg, WScript, EvtQuery, and browser profile snapshot reads).

---

## Contents
1. [Big picture](#1-big-picture)
2. [The 7-stage pipeline & correlation layer](#2-the-7-stage-pipeline--correlation-layer)
3. [Module dependency graph](#3-module-dependency-graph)
4. [File-by-file responsibility map](#4-file-by-file-responsibility-map)
5. [Data shapes that travel through the pipeline](#5-data-shapes-that-travel-through-the-pipeline)
6. [Command mode workflows (flowcharts)](#6-command-mode-workflows-flowcharts)
   - [`scan`](#61-scan)
   - [`monitor` & Telegram Remote Control](#62-monitor--telegram-remote-control)
   - [`persistence`](#63-persistence)
   - [`baseline`](#64-baseline)
   - [`history`](#65-history)
   - [`export`](#66-export)
7. [The rule engine & Attack Chain Correlation](#7-the-rule-engine--attack-chain-correlation)
8. [Risk scoring, banding & HIGH floor override](#8-risk-scoring-banding--high-floor-override)
9. [Database schema](#9-database-schema)
10. [Execution trace of a single scan](#10-execution-trace-of-a-single-scan)
11. [How config drives behavior](#11-how-config-drives-behavior)

---

## 1. Big picture

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                                    USER (CLI / Telegram)                          │
│   python main.py {scan | monitor | baseline | history | export | persistence | …}  │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │ dispatch (argparse / Telegram listener)
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│   LAYER 1 — COLLECT       collector/connections.py + processes.py + persistence_  │
│                           scanner.py + analyzer/defender_correlator.py            │
│   Read local sockets, process table, autorun entries, and Defender Event Logs     │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│   LAYER 2 — ANNOTATE      analyzer/ips.py + analyzer/ports.py                     │
│   Tag each record: ip_class (PUBLIC/PRIVATE/…), port service, unusual port flags  │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│   LAYER 3 — STAGE ENRICHMENT & ANALYZERS (Stages 1–7)                             │
│   VT reputation, TLS certs, GeoIP/ASN, process lineage, autoruns, Defender events │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│   LAYER 4 — CORRELATE & SCORE   analyzer/correlation.py + rules.py + risk_score.py │
│   Additive rule engine + Composite Correlation Engine (Attack Chains & HIGH Floor) │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│   LAYER 5 — PRESENT, ALERT & STORE  utils/formatting.py + monitor/realtime.py +   │
│                                     telegram_alerter.py / listener.py             │
│   Rich CLI tables, Attack Chain panels, Telegram bot commands, SQLite persistence │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The 7-stage pipeline & correlation layer

Every fully-analyzed scan pass flows through a unified orchestration pipeline (`monitor/pipeline.py::run_scan`).

```
RAW SOCKETS             RECORD DICT             ENRICHED RECORD            CORRELATED ATTACK CHAIN
 (psutil)   ─collect─▶ pid/ip/port  ─enrich─▶ +proc_info         ─analyze─▶  +risk_score +risk_level
                                               +ip_class +is_external            +rules_applied{}
                                               +lineage +defender               +chain_correlation_bonus
                                               +persistence +browser             +chain_narrative (HIGH floor)
```

Pipeline steps executed in order:

| # | Step | Owning Function | File |
|---|------|-----------------|------|
| 1 | Collect raw sockets | `collect_connections()` | `collector/connections.py` |
| 2 | Enrich with process info | `enrich_connections()` | `collector/processes.py` |
| 3 | Classify IP address | `ips.annotate()` | `analyzer/ips.py` |
| 4 | Tag ports & services | `ports.annotate()` | `analyzer/ports.py` |
| 5 | Track connection repeats | `store.observe_scan()` | `collector/connections.py` (`ConnectionStore`) |
| 6 | Defender Event Log correlation | `query_defender_events()` + `correlate_events()` | `analyzer/defender_correlator.py` |
| 7 | Apply additive rules | `rules.analyze()` | `analyzer/rules.py` |
| 8 | Attack Chain Correlation | `correlation.evaluate_chain()` | `analyzer/correlation.py` |
| 9 | Persist chains & scan rows | `save_scan()` + `save_correlated_chain()` | `database/database.py` |
| 10 | Render CLI / Telegram | `render_*()`, `run_monitor()`, `TelegramListener` | `utils/formatting.py`, `monitor/realtime.py`, `telegram_*` |

---

## 3. Module dependency graph

```
                                  main.py (CLI entry point)
                                     │
         ┌───────────────────────────┼────────────────────────────┐
         ▼                           ▼                            ▼
  monitor/pipeline.py       monitor/realtime.py          reports/{csv,json,html}
   (scan pipeline)           (polling loop & controller)   (report exporters)
         │                           │                            │
         ├───────────────────────────┼────────────────────────────┘
         ▼                           ▼
  analyzer/correlation.py   telegram_listener.py / telegram_alerter.py
   (Attack Chain Engine)     (Two-Way Telegram Remote Control)
         │                           │
         ▼                           ▼
  collector/*               database/database.py
   connections.py            (SQLite history.db: history, baseline,
   processes.py               defender_events, telegram_sessions,
         │                    correlated_chains)
         ▼
  analyzer/*
   ips.py, ports.py, rules.py, risk_score.py,
   lineage_analyzer.py, defender_correlator.py
```

---

## 4. File-by-file responsibility map

| File | Responsibility | Key public functions / objects |
|------|----------------|--------------------------------|
| `config/rules.json` | **Single source of truth** for all tunables: rule weights, risk bands, thresholds, ports, and brand targets. | `rule_weights`, `risk_bands`, `thresholds`, `unusual_remote_ports`, … |
| `utils/config_loader.py` | Central settings loader and deep dict merger. Exposes cached singleton `settings()`. | `settings()`, `load_config()` |
| `utils/logger.py` | Structured event logging (`logs/feluda.log`, 1 MB × 3 rotating handler). | `get_logger()`, `log_detection()` |
| `utils/formatting.py` | Rich CLI tables, boxed alert panels, attack chain panels (`render_chain_panel`), and HTML audit reports. | `render_connections_table()`, `render_alert_panel()`, `render_chain_panel()`, `render_chains_table()` |
| `collector/connections.py` | Local TCP/UDP socket collection via `psutil.net_connections()` and cross-scan `ConnectionStore` repeat tracking. | `collect_connections()`, `ConnectionStore` |
| `collector/processes.py` | PID → process metadata enrichment (`psutil.Process`) with per-scan PID cache. | `get_process_info()`, `enrich_connections()` |
| `collector/network.py` | TCP state labels legend and local IP address resolution. | `TCP_STATE_LABELS`, `get_local_ips()` |
| `analyzer/ips.py` | IP classification (PUBLIC, PRIVATE, LOOPBACK, etc.) and `is_external` tagging. | `classify_ip()`, `annotate()` |
| `analyzer/ports.py` | Remote service name resolution and unusual port tagging. | `service_name()`, `annotate()` |
| `analyzer/processes.py` | Path location heuristics (`Temp`, `Downloads`, `Users\Public`), system process allow-list, SHA-256 binary hashing. | `is_suspicious_location()`, `sha256_of_file()` |
| `analyzer/lineage_analyzer.py` | **Stage 5**: Parent-child process tree walking via `psutil`, detecting shell spawning, obfuscation, and unusual parents. | `walk_lineage()`, `LINEAGE_SIGNALS` |
| `analyzer/defender_correlator.py` | **Stage 7**: Windows Defender Event Log correlation (`EvtQuery` for IDs 1116/1117/1006) and detection gap analysis. | `query_defender_events()`, `correlate_events()` |
| `analyzer/correlation.py` | **Composite Correlation Engine**: Identity resolution (`resolve_target_identity`), multi-stage bonuses (+25/+40/+60), `HIGH` band floor, and narrative generation. | `resolve_target_identity()`, `evaluate_chain()`, `generate_chain_narrative()` |
| `analyzer/rules.py` | Additive weighted rule engine evaluating R1–R6, line-item reasons, and score triggering. | `RULE_ORDER`, `analyze()` |
| `analyzer/risk_score.py` | Clamps rule scores into 0–100 range, maps to risk bands, and provides `apply_banding_floor()` helper. | `apply_score()`, `band_for_score()`, `apply_banding_floor()` |
| `persistence_scanner.py` | **Stage 6**: Autorun location scanner (Registry Run keys, Startup folder shortcuts via WScript, Task Scheduler COM, Windows Services). | `scan()`, `score_entry()`, `cross_reference()` |
| `telegram_setup.py` | Per-user Telegram Chat ID setup wizard saving configuration to `%LOCALAPPDATA%\Feluda\user_settings.json`. | `run_setup()`, `load_user_settings()` |
| `telegram_alerter.py` | Outbound Telegram notification dispatcher, `setMyCommands` registration, and Inline Keyboard builder. | `send_telegram_alert()`, `register_bot_commands()`, `build_inline_keyboard()` |
| `telegram_listener.py` | Inbound Telegram command long-poller (`getUpdates`), command router (`/high`, `/medium`, `/low`, `/pause`, `/stop`, `/chains`, `/status`, `/help`). | `TelegramListener`, `process_command()` |
| `database/database.py` | SQLite database manager (`history`, `baseline`, `defender_events`, `telegram_sessions`, `correlated_chains`). | `save_scan()`, `save_correlated_chain()`, `fetch_correlated_chains()`, `fetch_telegram_sessions()` |
| `monitor/pipeline.py` | Single-scan orchestration glue wiring collector → enrich → annotate → defender → rules → correlation → sort. | `run_scan()` |
| `monitor/realtime.py` | Continuous monitor loop, `MonitorController` state machine, boxed CLI alerts, and async gather task. | `run_monitor()`, `MonitorController` |
| `reports/csv_export.py` | CSV exporter for connection and persistence records. | `export_csv()` |
| `reports/json_export.py` | JSON exporter including connections, browser URLs, persistence entries, and correlated attack chains. | `export_json()` |
| `reports/html_export.py` | Dark-themed self-contained HTML audit report builder. | `export_html()` |
| `main.py` | CLI entry point parsing subcommands (`scan`, `monitor`, `baseline`, `history`, `export`, `browsers`, `persistence`, `setup-telegram`). | `main()`, `cmd_*()` |

---

## 5. Data shapes that travel through the pipeline

### Stage A — Raw Socket Record (`collector/connections.py`)
```json
{ "pid": 8368, "local_ip": "192.168.1.2", "local_port": 52144,
  "remote_ip": "172.217.114.4", "remote_port": 443, "status": "ESTABLISHED" }
```

### Stage B — Analyzed & Correlated Record (`analyzer/correlation.py`)
```json
{
  "pid": 8368,
  "proc_info": { "name": "evil.exe", "exe": "C:\\Users\\Public\\evil.exe" },
  "ip_class": "PUBLIC",
  "is_external": true,
  "rules_applied": {
    "external_unknown_process": 30,
    "chain_correlation_bonus": 25
  },
  "reasons": [
    "External (public) connection from unrecognized process 'evil.exe' (+30)",
    "Composite attack chain correlation (2 stages: connection, persistence) (+25)"
  ],
  "risk_score": 55,
  "risk_level": "HIGH",
  "is_attack_chain": true,
  "chain_narrative": "A persistent autorun process actively communicating over external network connections.",
  "chain_stages": ["connection", "persistence"]
}
```

### Stage C — Stored Correlated Attack Chain (`database/database.py`)
```json
{
  "id": 1,
  "target_identity": "c:\\users\\public\\evil.exe",
  "stages_involved": ["connection", "persistence"],
  "chain_narrative": "A persistent autorun process actively communicating over external network connections.",
  "bonus_points": 25,
  "final_risk_score": 55,
  "final_risk_level": "HIGH",
  "detected_at": "2026-08-13T07:20:00+00:00",
  "related_history_ids": [102]
}
```

---

## 6. Command mode workflows (flowcharts)

### 6.1 `scan`

```
scan [--reputation-check] [--cert-check] [--geo-check] [--lineage-check] [--defender-check]
        │
        ▼
  monitor.pipeline.run_scan()
        ├─ collect_connections() + enrich_connections()
        ├─ ips.annotate() + ports.annotate()
        ├─ defender_correlator.query_defender_events() & correlate_events()
        ├─ rules.analyze()
        └─ correlation.evaluate_chain() ──▶ save_correlated_chain()
        │
        ▼
  render_chain_panel() (for detected attack chains)
        │
        ▼
  render_connections_table() (Rich table → stdout)
```

### 6.2 `monitor` & Telegram Remote Control

```
monitor --interval 5 --alert-telegram --telegram-control
        │
        ▼
  run_monitor_control() (async gather loop)
        ├─ Task 1: Monitor polling loop (run_scan → save_scan → send Telegram alert)
        └─ Task 2: TelegramListener (long-polling getUpdates loop)
                     │
                     ├─ /high, /medium, /low ──▶ MonitorController.set_mode()
                     ├─ /pause               ──▶ MonitorController.pause_scan()
                     ├─ /stop                ──▶ MonitorController.stop_session() (exits)
                     ├─ /chains              ──▶ fetch_correlated_chains()
                     └─ /status              ──▶ MonitorController.get_status_markdown()
```

---

## 7. The rule engine & Attack Chain Correlation

Feluda's rule engine combines additive point scoring with composite attack chain correlation.

### Multi-Stage Stage Categories Evaluated
1. `connection`: R1–R6 network connection rules and location heuristics.
2. `lineage`: Process tree parent-child lineage signals (Office spawning shells, script interpreters with abnormal parents, obfuscation).
3. `persistence`: Autorun registry keys, Startup shortcuts, Task Scheduler jobs, or Windows services cross-referenced against target.
4. `defender`: Native Windows Defender event log detections matching process identity.
5. `browser`: Browser URL structural threat engine findings linked to browser PID/path.

---

## 8. Risk scoring, banding & HIGH floor override

```
raw_score = sum(rules_applied.values())
clamped_score = max(0, min(100, raw_score))
risk_level = band_for_score(clamped_score)

# If target is flagged by 2+ distinct stages in Attack Chain Correlation:
if distinct_stages_count >= 2:
    apply_banding_floor(record, min_level="HIGH")
    # Forces risk_level = "HIGH" and risk_score >= 50
```

| Score Range | Risk Band | Rich CLI Color |
|:---:|:---:|:---:|
| 0–24 | LOW | Green |
| 25–49 | MEDIUM | Yellow |
| 50–74 | HIGH | Red |
| 75–100 | CRITICAL | Bold Red |

---

## 9. Database schema

`database/history.db` contains 5 primary tables:

```
TABLE history                         TABLE baseline
┌───────────────┬────────────┐        ┌──────────────┬────────┐
│ id            │ PK         │        │ key          │ PK     │ e.g. "chrome.exe:443"
│ timestamp     │ TEXT       │        │ process_name │ TEXT   │
│ pid           │ INTEGER    │        │ remote_port  │ INTEGER│
│ process_name  │ TEXT       │        │ created_at   │ TEXT   │
│ exe_path      │ TEXT       │        └──────────────┴────────┘
│ sha256        │ TEXT       │
│ local_ip      │ TEXT       │        TABLE defender_events
│ local_port    │ INTEGER    │        ┌─────────────────────┬────────────┐
│ remote_ip     │ TEXT       │        │ id                  │ PK         │
│ remote_port   │ INTEGER    │        │ event_id            │ INTEGER    │
│ status        │ TEXT       │        │ threat_name         │ TEXT       │
│ risk_score    │ INTEGER    │        │ affected_path       │ TEXT       │
│ risk_level    │ TEXT       │        │ correlated_pid      │ INTEGER    │
│ signals       │ TEXT       │        │ initial_detection_ts│ TEXT       │
└───────────────┴────────────┘        └─────────────────────┴────────────┘

TABLE telegram_sessions               TABLE correlated_chains
┌───────────────────────┬──────────┐  ┌─────────────────────┬────────────┐
│ chat_id               │ PK       │  │ id                  │ PK         │
│ session_started_at    │ TEXT     │  │ target_identity     │ TEXT       │
│ session_ended_at      │ TEXT     │  │ stages_involved     │ TEXT (JSON)│
│ last_known_state      │ TEXT     │  │ chain_narrative     │ TEXT       │
│ current_severity_focus│ TEXT     │  │ bonus_points        │ INTEGER    │
│ total_findings_sent   │ INTEGER  │  │ final_risk_score    │ INTEGER    │
│ updated_at            │ TEXT     │  │ final_risk_level    │ TEXT       │
└───────────────────────┴──────────┘  │ detected_at         │ TEXT       │
                                      │ related_history_ids │ TEXT (JSON)│
                                      └─────────────────────┴────────────┘
```

---

## 10. Execution trace of a single scan

Annotated trace of a full 7-stage scan with correlation enabled:

```
main.py
 └─ cmd_scan(args)
    └─ monitor.pipeline.run_scan()
       ├─ collector.connections.collect_connections()  ──▶ 209 raw sockets
       ├─ collector.processes.enrich_connections()     ──▶ PIDs enriched
       ├─ ips.annotate() + ports.annotate()
       ├─ defender_correlator.query_defender_events()  ──▶ EvtQuery Event IDs 1116/1117/1006
       ├─ rules.analyze()                              ──▶ R1-R6 evaluated
       ├─ correlation.evaluate_chain()                 ──▶ 2+ stages matched -> +25 bonus, HIGH floor
       │     └─ database.save_correlated_chain()       ──▶ persisted to correlated_chains
       └─ sort key=risk_score desc
    └─ render_chain_panel()                           ──▶ Rich Attack Chain Panel
    └─ render_connections_table()                     ──▶ Rich Connections Table
```

---

## 11. How config drives behavior

`config/rules.json` remains the single source of truth for all weights, thresholds, and cutoffs:

| Config Key | Used By | Description |
|------------|---------|-------------|
| `rule_weights.external_unknown_process` | `analyzer/rules.py` | Weight for unrecognized process connecting externally (+30) |
| `rule_weights.defender_correlated_detection` | `analyzer/rules.py` | Weight for active process matching Defender detection (+50) |
| `rule_weights.chain_correlation_bonus_2` | `analyzer/correlation.py` | Bonus when 2 distinct stages flag target (+25) |
| `rule_weights.chain_correlation_bonus_3` | `analyzer/correlation.py` | Bonus when 3 distinct stages flag target (+40) |
| `rule_weights.chain_correlation_bonus_4` | `analyzer/correlation.py` | Bonus when 4+ distinct stages flag target (+60) |
| `risk_bands` | `analyzer/risk_score.py` | Score boundaries for LOW, MEDIUM, HIGH, and CRITICAL bands |
| `thresholds.alert_threshold` | `monitor/realtime.py` | Minimum score triggering CLI and Telegram alerts (50) |
