# Feluda

![Feluda Banner](assets/image.png)

A Python-based **defensive security monitoring & triage** tool for Windows.

Feluda watches your machine's active network connections, maps each one to its
owning process, and applies **rule-based heuristics** to flag *potentially
suspicious* activity with a transparent, explainable **risk score**.

> ⚠️ **This is a monitoring/triage tool, not an antivirus.** Every flag is a
> *signal* with an explicit reason list — never a definitive threat
> determination.

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Usage](#usage)
- [Risk Bands](#risk-bands-heuristic-not-a-malware-probability)
- [Project Layout](#project-layout)
- [Verification Against Native Tools](#verification-against-native-tools)
- [Design Principles](#design-principles)

## Features


- Real-time connection monitoring (TCP/UDP) via `psutil.net_connections()`
- PID → process mapping (name, exe path, user, create time)
- Remote-IP classification: PRIVATE / LOOPBACK / LINK-LOCAL / PUBLIC
- Port intelligence against a config-driven well-known service map
- Weighted, additive rule engine → 0–100 **heuristic** risk score
- Rich CLI dashboard with color-coded alerts and reason lists
- SQLite history for every scan
- Baseline learning (`process → port` patterns)
- Export to CSV / JSON / self-contained HTML audit report
- SHA-256 hashing of notable executables (hash-and-store only; no execution)
- **Browser & URL threat detection** — detects running browsers (Chrome, Brave, Edge, Arc, Firefox), extracts open/recent URLs, and scores each URL for phishing/obfuscation risk with a dedicated panel and export section
- **Local-only scope** — inspects only this machine; never scans/probes remote hosts

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```powershell
python main.py scan                 # one-shot scan, color-coded rich table
python main.py monitor              # live polling monitor with alerts
python main.py monitor --once       # run a single monitor iteration and exit
python main.py baseline             # learn current process->remote-port patterns
python main.py history --limit 50   # view recent history from SQLite
python main.py history --level HIGH # filter by risk band
python main.py export --format all  # writes exports/connections.{csv,json} + audit_report.html

# Browser & URL threat detection (Phase 1 — offline heuristics)
python main.py browsers                     # one-pass scan -> Rich Browser Activity panel
python main.py browsers --live --interval 3 # live polling of newly opened browsers/URLs
```

For clean output in Windows PowerShell, set UTF-8 first:

```powershell
$env:PYTHONIOENCODING='utf-8'
```

## Risk bands (heuristic, not a malware probability)

| Range   | Level    |
|---------|----------|
| 0–24    | LOW      |
| 25–49   | MEDIUM   |
| 50–74   | HIGH     |
| 75–100  | CRITICAL |

Scores are the sum of weighted signals, e.g.:

- External connection from an unrecognized process: **+30**
- Unusual remote port: **+20** *(a signal, not proof of malice)*
- Process running from a suspicious location (`Temp`, `Downloads`, …): **+25**
- Process holding multiple simultaneous external connections: **+10**
- Connection repeatedly reappears across polls: **+10**
- Outside the learned baseline: **+15**

All weights, thresholds, port lists, and band cutoffs live in
[`config/rules.json`](config/rules.json) — tune them without touching code.

## Project layout

```
Feluda/
├── main.py                  # CLI entry: scan / monitor / baseline / history / export
├── collector/
│   ├── connections.py       # psutil.net_connections() + ConnectionStore (phase 3, 15)
│   ├── processes.py         # PID → process enrichment (phase 4)
│   └── network.py           # local interfaces & TCP-state labels (phase 1)
├── analyzer/
│   ├── ips.py               # IP classification (phase 5)
│   ├── ports.py             # well-known / unusual port intelligence (phase 6)
│   ├── processes.py         # location heuristics + SHA-256 (phase 7, 8, 9)
│   ├── rules.py             # additive weighted detection engine (phase 10)
│   └── risk_score.py        # 0–100 scoring & banding (phase 11)
├── monitor/
│   ├── pipeline.py          # shared single-scan orchestration
│   └── realtime.py          # polling monitor loop (phase 13)
├── database/database.py     # SQLite history + baseline (phase 14, 16)
├── reports/                 # csv / json / html export (phase 18)
├── utils/                   # config loader, logger, rich/HTML formatting
├── config/rules.json        # all tunable weights, ports, thresholds
└── logs/feluda.log          # structured detection event log (phase 19)
```

## Verification against native tools

Feluda's records mirror what `netstat -ano` + `tasklist` show, so you can
verify any row manually:

```powershell
netstat -ano
tasklist /FI "PID eq 8368"
```

## Design principles

1. **Signals, not verdicts.** Every alert lists *why* a score was given.
2. **Modular** — logic lives in subpackages, never collapsed into `main.py`.
3. **Config-driven** — thresholds and port lists in `config/rules.json`.
4. **Local-only** — inspects only this machine via `psutil`; no remote probing.
5. **Explainability first** — CLI output and exports are legible to non-experts.
