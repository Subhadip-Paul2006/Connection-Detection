# Feluda — Complete System & Usage Guide

![Feluda Banner](assets/image.png)

## Overview

**Feluda** is a Python-based, local-only **defensive security monitoring, triage, and threat detection engine** designed for Windows.

Feluda monitors active network connections and running web browsers in real time, maps every socket to its owning process, inspects executables and remote URLs, and applies transparent **rule-based heuristics** to calculate an explainable **risk score (0–100)**.

> [!IMPORTANT]
> **Signals, Not Verdicts:** Feluda is a triage and monitoring tool, not an antivirus or automated malware remover. Every flagged item provides an explicit **reason list** showing *why* a score was assigned—never an absolute malware determination.

---

## Key Capabilities

1. **Real-Time Network Connection Monitoring**:
   - Inspects TCP/UDP sockets (`psutil.net_connections()`).
   - Maps sockets to owning processes (PID, executable path, username, creation timestamp).
   - Classifies remote IP addresses (`PUBLIC`, `PRIVATE`, `LOOPBACK`, `LINK-LOCAL`, `MULTICAST`).
   - Detects unusual remote ports against configurable service definitions.

2. **Execution Path & Binary Fingerprinting**:
   - Flags executables running from untrusted or temporary directories (`Temp`, `Downloads`, `Users\Public`).
   - Generates SHA-256 binary hashes for notable processes for stable identification.

3. **Browser & URL Threat Detection Engine**:
   - Detects active instances of major browsers (**Chrome**, **Brave**, **Edge**, **Arc**, **Firefox**).
   - Safely extracts open tabs and recent history using lock-free temporary SQLite profile copies.
   - Applies offline structural URL threat scoring:
     - **Homograph / IDN Spoofing**: Mixed-script detection (e.g., Cyrillic glyphs in Latin domains).
     - **Typosquatting**: Levenshtein edit distance $\le 2$ against major brands (`paypal`, `google`, `microsoft`, `github`, etc.).
     - **Obfuscation**: Excessive percent-encoding (`%XX` escapes).
     - **IP Literals**: Direct IP addresses in URLs skipping DNS.
     - **Abused TLDs**: High-risk top-level domains (`.xyz`, `.zip`, `.mov`, `.tk`, `.ml`).
     - **Length Outliers**: Abnormally long URLs common in tracking or phishing payloads.

4. **Additive Risk Scoring Engine**:
   - Evaluates weighted signals additively to produce a 0–100 score mapped into four risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

5. **SQLite Persistence & Baseline Learning**:
   - Automatically logs scan snapshots to `database/history.db`.
   - Supports learning normal `process:port` patterns to highlight deviations.

6. **Multi-Format Security Reporting**:
   - Rich color-coded CLI tables & boxed alert panels.
   - Exports audit findings to **CSV**, **JSON**, and self-contained **HTML** audit reports.

---

## Installation & Requirements

### System Requirements
- **OS**: Windows 10 / 11 (64-bit)
- **Python**: Python 3.12+

### Setup Environment

```powershell
# 1. Clone or open project directory
cd D:\Feluda

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

---

## CLI Command Reference

All Feluda operations are invoked through `main.py` using the following general syntax:

```powershell
python main.py [--no-banner] <command> [command-flags]
```

### Global Options
- `--no-banner`: Suppresses the startup ASCII logo banner for scriptable or compact terminal output (must be placed *before* the subcommand).

---

### Subcommand Summary & Purpose Matrix

| Subcommand | Primary Purpose | Key Output / Action | When to Use |
|---|---|---|---|
| **`scan`** | **Point-in-Time Triage** | Rich terminal table of active connections with 0–100 risk scores & explicit reasons. | When you want a quick, instant snapshot of active network connections and suspicious process behavior. |
| **`browsers`** | **URL Threat Inspection** | Rich Browser Activity panel analyzing open & recent browser tab URLs for phishing & obfuscation. | When inspecting browser security, checking open tabs for homographs/typosquats, or watching for new malicious links. |
| **`monitor`** | **Real-Time Guard** | Continuous polling loop + SQLite auto-persistence + pop-up boxed alerts for HIGH/CRITICAL connections. | When actively monitoring a live Windows machine for real-time network threats and connection spikes. |
| **`baseline`** | **Anomaly Training** | Records normal `process_name:remote_port` pairs to SQLite baseline storage. | After system startup or when you know current connections are clean, to train Feluda's baseline engine. |
| **`history`** | **Forensic Query** | Terminal tables of previous scan snapshots retrieved from SQLite database (`database/history.db`). | During post-incident investigations to check past connections or filter high-risk connection history. |
| **`export`** | **Report Generation** | Exports connection & browser findings to CSV (`.csv`), JSON (`.json`), or dark-themed HTML (`.html`). | When sharing audit findings with team members, generating compliance reports, or feeding SIEM pipelines. |

---

### Detailed Subcommand Specifications

#### 1. `scan` — Instant Point-in-Time Connection Triage

**Purpose**: Performs an instant, read-only snapshot analysis of all TCP/UDP connections currently established or listening on the local machine. It maps sockets to PIDs, checks binary execution locations, calculates heuristic risk scores, and prints a formatted Rich table.

* **Usage Syntax**:
  ```powershell
  python main.py scan [flags]
  ```

* **Command Flags**:
  - `--all`: Includes quiet listening sockets (`LISTEN` state) alongside active established sessions. By default, `scan` hides quiet listening ports to reduce noise.
  - `--no-baseline`: Skips checking connections against the learned baseline stored in SQLite.

* **Practical Examples**:
  ```powershell
  # Standard triage scan (active established connections only)
  python main.py scan

  # Comprehensive scan showing listening ports as well
  python main.py scan --all

  # Pure heuristic scan without baseline penalty check
  python main.py scan --no-baseline
  ```

---

#### 2. `browsers` — Browser & URL Threat Detection Engine

**Purpose**: Inspects running web browsers (**Chrome**, **Brave**, **Edge**, **Arc**, **Firefox**), extracts active tab URLs and recent history using lock-free temporary profile copies, and applies 6 offline structural risk rules (Homograph IDNs, Typosquatting, IP Literals, Obfuscation, Abused TLDs, Length Outliers).

* **Usage Syntax**:
  ```powershell
  python main.py browsers [flags]
  ```

* **Command Flags**:
  - `--live`: Enables continuous live watch mode, polling every $N$ seconds for newly launched browser instances or newly opened tab URLs.
  - `--interval N`: Sets the polling interval in seconds for `--live` mode (default: `10` seconds, configurable in `config/rules.json`).

* **Practical Examples**:
  ```powershell
  # Single-pass browser tab scan -> render Browser Activity panel
  python main.py browsers

  # Live watch mode polling every 5 seconds for newly opened tabs
  python main.py browsers --live --interval 5
  ```

---

#### 3. `monitor` — Real-Time Background Monitor & Alert Engine

**Purpose**: Runs a persistent polling loop that analyzes connections every tick, saves every scan to SQLite (`database/history.db`), logs detection events to `logs/feluda.log`, and displays prominent boxed CLI alert panels whenever a connection reaches or exceeds the alert threshold (default risk score $\ge 60$).

* **Usage Syntax**:
  ```powershell
  python main.py monitor [flags]
  ```

* **Command Flags**:
  - `--interval N`: Sets the polling loop delay in seconds (default: `5` seconds).
  - `--once`: Executes a single monitoring tick (including database persistence and alert evaluation) and exits cleanly.
  - `--no-baseline`: Disables baseline comparison during monitoring ticks.
  - `--persistence-check`: Periodically scans Windows persistence/autorun entries and cross-references them against active connection processes.

* **Practical Examples**:
  ```powershell
  # Continuous real-time monitor with default 5s polling
  python main.py monitor

  # Real-time monitor polling every 15 seconds with persistence cross-referencing
  python main.py monitor --interval 15 --persistence-check

  # One-shot test iteration of the monitor engine
  python main.py monitor --once
  ```

---

#### 4. `persistence` — Windows Autorun & Persistence Location Scanner

**Purpose**: Scans Windows autorun & persistence mechanisms (Registry `Run` / `RunOnce` keys across HKCU and HKLM hives including WOW6432Node, Startup folders with `.lnk` resolution via `WScript.Shell` COM, Task Scheduler COM jobs, and optional untrusted Windows services). Scores entries offline and cross-references binaries against active process connections.

* **Usage Syntax**:
  ```powershell
  python main.py persistence [flags]
  ```

* **Command Flags**:
  - `--services`: Enables opt-in scan of Windows services whose binary executable resides outside trusted system paths.
  - `--all`: Displays every enumerated entry (by default, only entries triggering risk signals are shown).
  - `--limit N`: Row cap when `--all` is passed (default: `80`).

* **Practical Examples**:
  ```powershell
  # Scan persistence locations for entries with risk signals
  python main.py persistence

  # Include Windows service path scanning and show all enumerated entries
  python main.py persistence --services --all
  ```

---

#### 5. `baseline` — Learn Normal Process Connection Baseline

**Purpose**: Captures a snapshot of currently active external network connections and stores normal `process_name:remote_port` pairs into the `baseline` table in SQLite (`database/history.db`). In subsequent scans or monitor runs, any external connection matching an unlearned pattern is assigned a **+15 Outside Baseline** risk signal.

* **Usage Syntax**:
  ```powershell
  python main.py baseline
  ```

* **Practical Example**:
  ```powershell
  # Run after verifying current system connections are clean
  python main.py baseline
  ```

---

#### 5. `history` — Forensic SQLite History Query

**Purpose**: Queries historical connection records stored in SQLite database (`database/history.db`). Useful for investigating past network activity, reviewing historical risk scores, or auditing specific risk levels.

* **Usage Syntax**:
  ```powershell
  python main.py history [flags]
  ```

* **Command Flags**:
  - `--limit N`: Maximum number of historical records to return (default: `50`).
  - `--level LEVEL`: Filters records by risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

* **Practical Examples**:
  ```powershell
  # View the 20 most recent connection records
  python main.py history --limit 20

  # Retrieve all historical HIGH and CRITICAL risk records
  python main.py history --level HIGH
  ```

---

#### 6. `export` — Multi-Format Security Report Generator

**Purpose**: Executes a connection scan (and optionally a browser tab scan), formats the findings, and exports audit reports into `exports/connections.csv`, `exports/connections.json`, and `exports/audit_report.html`.

* **Usage Syntax**:
  ```powershell
  python main.py export [flags]
  ```

* **Command Flags**:
  - `--format FORMAT`: Specifies export target format (`csv`, `json`, `html`, or `all`; default: `all`).
  - `--scan-browsers`: Includes Browser URL threat findings as a dedicated section in CSV, JSON, and HTML reports.
  - `--no-baseline`: Excludes baseline checking during export scan.

* **Practical Examples**:
  ```powershell
  # Export connections to all formats (CSV, JSON, HTML)
  python main.py export --format all

  # Export connection & browser URL security data to HTML audit report
  python main.py export --scan-browsers --format html
  ```

---

## Recommended Operational Workflows

### Workflow A: Initial System Setup & Baseline Training
1. Start Feluda and run a clean connection scan:
   ```powershell
   python main.py scan
   ```
2. Verify existing connections are trusted, then train the baseline model:
   ```powershell
   python main.py baseline
   ```

### Workflow B: Real-Time Threat Guard & Browser Watch
1. Terminal 1 — Run real-time connection monitor:
   ```powershell
   python main.py monitor --interval 5
   ```
2. Terminal 2 — Run live browser URL watch mode:
   ```powershell
   python main.py browsers --live --interval 5
   ```

### Workflow C: Incident Investigation & Audit Export
1. Query historical suspicious connections:
   ```powershell
   python main.py history --level HIGH --limit 100
   ```
2. Generate comprehensive HTML audit report for leadership or triage review:
   ```powershell
   python main.py export --scan-browsers --format html
   ```

---



## Risk Scoring & Banding Engine

### Score Cutoffs

| Range | Risk Band | CLI Styling |
|:---:|:---:|:---:|
| **0–24** | **LOW** | Green |
| **25–49** | **MEDIUM** | Yellow |
| **50–74** | **HIGH** | Red |
| **75–100** | **CRITICAL** | Bold Red |

---

### Rule Weights Reference

All rules are additive, weighted, and configurable in [`config/rules.json`](file:///d:/Feluda/config/rules.json):

#### Connection Rules
| Rule Key | Weight | Description |
|---|:---:|---|
| `external_unknown_process` | **+30** | External public connection from an unrecognized process |
| `suspicious_location` | **+25** | Process running from `Temp`, `Downloads`, or `Users\Public` |
| `unusual_remote_port` | **+20** | Connection to an unusual or unassigned remote port |
| `outside_baseline` | **+15** | Connection pattern not seen during baseline training |
| `multiple_external_connections` | **+10** | Process holding $\ge 3$ simultaneous external connections |
| `repeated_connection` | **+10** | Connection reappears continuously across multiple scans |

#### URL Risk Rules
| Rule Key | Weight | Description |
|---|:---:|---|
| `homograph_idn` | **+35** | Mixed-script domain (e.g. Cyrillic glyphs in domain name) |
| `typosquat` | **+30** | Domain label edit-distance $\le 2$ from major brands |
| `ip_literal` | **+25** | URL uses direct IP address instead of domain |
| `suspicious_tld` | **+20** | Domain uses frequently abused free/cheap TLD (`.xyz`, `.zip`, `.tk`) |
| `excessive_percent_encoding` | **+15** | URL contains $\ge 6$ percent-encoded (`%XX`) characters |
| `url_length_outlier` | **+10** | URL length exceeds 100 characters |

---

## Verification & Troubleshooting

### Verification Against Windows Native Tools
You can cross-reference any socket or PID reported by Feluda using Windows CLI tools:

```powershell
# Verify PID & connection status
netstat -ano | findstr <PID>

# Inspect process details
tasklist /FI "PID eq <PID>"
```

### Log File Location
Detailed structured event logs are written to:
- `logs/feluda.log` (Rotating log, 1 MB $\times$ 3 backups)
