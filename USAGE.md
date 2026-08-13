# Feluda — Complete System & Usage Guide

![Feluda Banner](assets/image.png)

## Overview

**Feluda** is a Python-based, local-only **defensive security monitoring, triage, threat detection & correlation engine** designed for Windows.

Feluda monitors active network connections, running web browsers, autorun/persistence entries, and native Windows Defender event logs in real time, maps every socket to its owning process, inspects executables and remote URLs across a **7-stage detection architecture**, and applies transparent **rule-based heuristics & attack chain correlation** to calculate an explainable **risk score (0–100)** and **headline attack chain narrative**.

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
   - Applies offline structural URL threat scoring (Homographs, Typosquatting, Obfuscation, IP Literals, Abused TLDs, Length Outliers).

4. **Multi-Stage Opt-In Enrichment (Stages 1–7)**:
   - **Stage 1**: Base Connection & Structural URL Baseline.
   - **Stage 2**: VirusTotal Reputation Engine (`--reputation-check`).
   - **Stage 3**: HTTPS TLS Certificate Inspection (`--cert-check`).
   - **Stage 4**: GeoIP & ASN Enrichment Engine (`--geo-check`).
   - **Stage 5**: Process Tree Lineage Analysis (`--lineage-check`).
   - **Stage 6**: Windows Persistence / Autorun Scanner (`--persistence-check`).
   - **Stage 7**: Windows Defender Event Log Correlation (`--defender-check`).

5. **Composite Correlation Engine (Attack Chain Detection)**:
   - Evaluates findings across all 7 stages per target identity (resolved executable path or PID).
   - Applies multi-stage correlation bonuses (**+25** for 2 stages, **+40** for 3 stages, **+60** for 4+ stages).
   - Explicitly floors risk levels at **`HIGH`** (minimum score 50) when 2+ distinct detection stages agree.
   - Generates deterministic headline attack chain narratives (e.g. macro-malware execution chains, drive-by compromises).

6. **Two-Way Telegram Remote Control (`--telegram-control`)**:
   - Interactive remote control via Telegram bot slash commands (`/high`, `/medium`, `/low`, `/pause`, `/stop`, `/chains`, `/status`, `/help`) and Inline Keyboard buttons.
   - Per-user runtime Chat ID configuration via `python main.py setup-telegram` (stored in `%LOCALAPPDATA%\Feluda\user_settings.json`).
   - Persistent session tracking (`telegram_sessions` table in SQLite) with two-tier stop semantics (`/pause` soft stop vs `/stop` hard stop).

7. **SQLite Persistence & Baseline Learning**:
   - Automatically logs scan snapshots, Defender events, Telegram sessions, and correlated attack chains to `database/history.db`.
   - Learns normal `process:port` patterns to highlight deviations.

8. **Multi-Format Security Reporting**:
   - Rich color-coded CLI tables, alert panels, and attack chain panels.
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
| **`scan`** | **Point-in-Time Triage** | Rich terminal table of active connections + Attack Chain Panels with 0–100 risk scores & explicit reasons. | When you want an instant snapshot of active network connections, process lineage, and attack chains. |
| **`browsers`** | **URL Threat Inspection** | Rich Browser Activity panel analyzing open & recent browser tab URLs for phishing, cert issues, & reputation. | When inspecting browser security, checking open tabs for homographs/typosquats, or watching for new malicious links. |
| **`monitor`** | **Real-Time Guard** | Continuous polling loop + SQLite persistence + pop-up boxed alerts + Telegram remote control. | When actively monitoring a live Windows machine for real-time network threats, alerts, and remote bot control. |
| **`persistence`** | **Windows Autorun Scan** | Scans Registry Run keys, Startup shortcuts, Task Scheduler jobs, and Windows services. | When auditing startup persistence mechanisms or cross-referencing autoruns against active connections. |
| **`setup-telegram`** | **Telegram Chat ID Config** | Interactive wizard to set per-user Telegram Chat ID (saved in `%LOCALAPPDATA%\Feluda\user_settings.json`). | When setting up or changing the Telegram recipient for alert notifications and remote control. |
| **`baseline`** | **Anomaly Training** | Records normal `process_name:remote_port` pairs to SQLite baseline storage. | After system startup or when you know current connections are clean, to train Feluda's baseline engine. |
| **`history`** | **Forensic Query** | Terminal tables of historical scans, Defender events, persistence snapshots, correlated chains, or Telegram sessions. | During post-incident investigations to query past activity or review correlated attack chains (`--chains-only`). |
| **`export`** | **Report Generation** | Exports connection, browser, persistence, and attack chain findings to CSV, JSON, or dark-themed HTML. | When sharing audit findings with team members, generating compliance reports, or feeding SIEM pipelines. |

---

### Detailed Subcommand Specifications

#### 1. `scan` — Instant Point-in-Time Connection & Correlation Triage

**Purpose**: Performs an instant snapshot analysis of all TCP/UDP connections, running multi-stage rules, Defender events, and composite correlation scoring. Displays formatted Rich tables and `🔗 CORRELATED ATTACK CHAIN` panels.

* **Usage Syntax**:
  ```powershell
  python main.py scan [flags]
  ```

* **Command Flags**:
  - `--all`: Includes quiet listening sockets (`LISTEN` state) alongside active established sessions.
  - `--no-baseline`: Skips checking connections against the learned baseline.
  - `--reputation-check`: Enables Stage 2 VirusTotal IP reputation lookup (reads cache).
  - `--cert-check`: Enables Stage 3 TLS Certificate inspection.
  - `--geo-check`: Enables Stage 4 GeoIP & ASN enrichment.
  - `--lineage-check`: Enables Stage 5 parent-child process tree lineage analysis.
  - `--defender-check`: Enables Stage 7 Windows Defender event log correlation (requires Admin terminal).

* **Practical Examples**:
  ```powershell
  # Standard triage scan
  python main.py scan

  # Full 7-stage scan with Defender correlation in an Admin terminal
  python main.py scan --reputation-check --cert-check --geo-check --lineage-check --defender-check
  ```

---

#### 2. `monitor` — Real-Time Monitor, Alert & Remote Control Engine

**Purpose**: Runs a continuous monitoring loop, saving every scan pass to SQLite (`database/history.db`), raising CLI boxed alerts, dispatching Telegram notifications, and accepting inbound Telegram remote control commands.

* **Usage Syntax**:
  ```powershell
  python main.py monitor [flags]
  ```

* **Command Flags**:
  - `--interval N`: Sets polling loop delay in seconds (default: `5`).
  - `--once`: Executes a single monitoring iteration and exits.
  - `--no-baseline`: Disables baseline comparison.
  - `--persistence-check`: Enables Stage 6 persistence location scanning and cross-referencing.
  - `--alert-telegram`: Enables outbound Telegram alert dispatching.
  - `--telegram-control`: Enables inbound two-way Telegram remote control long-polling loop.

* **Practical Examples**:
  ```powershell
  # Real-time monitor with Telegram alerts & remote control
  python main.py monitor --interval 5 --persistence-check --alert-telegram --telegram-control
  ```

---

#### 3. `setup-telegram` — Per-User Telegram Chat ID Configurator

**Purpose**: Guides the user through setting up or updating their Telegram Chat ID without modifying `.env`. Chat ID is saved in `%LOCALAPPDATA%\Feluda\user_settings.json`.

* **Usage Syntax**:
  ```powershell
  python main.py setup-telegram
  ```

---

#### 4. `persistence` — Windows Autorun & Persistence Location Scanner

**Purpose**: Scans Windows autorun locations (HKCU/HKLM Registry Run keys, Startup folder shortcuts via COM, Task Scheduler COM jobs, and Windows services). Scores entries offline and cross-references binaries against active process connections.

* **Usage Syntax**:
  ```powershell
  python main.py persistence [flags]
  ```

* **Command Flags**:
  - `--services`: Enables scanning of Windows services with binary paths outside trusted system directories.
  - `--all`: Displays all enumerated entries (default: only entries triggering risk signals).
  - `--limit N`: Maximum row output when `--all` is passed (default: `80`).

---

#### 5. `history` — Forensic SQLite Database Query

**Purpose**: Queries historical scan snapshots, process lineage, Defender events, persistence snapshots, correlated attack chains, or Telegram sessions stored in `database/history.db`.

* **Usage Syntax**:
  ```powershell
  python main.py history [flags]
  ```

* **Command Flags**:
  - `--limit N`: Maximum historical rows to display (default: `50`).
  - `--level LEVEL`: Filters connection records by risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - `--country CC`: Filters connection records by ISO-3166 country code.
  - `--show-lineage ID`: Shows stored parent-child process lineage for a specific scan ID.
  - `--persistence`: Shows historical persistence scan snapshots.
  - `--defender-only`: Shows historical Windows Defender event correlation records.
  - `--chains-only`: Displays stored correlated attack chain records.
  - `--telegram-sessions`: Displays stored Telegram remote control session records.

* **Practical Examples**:
  ```powershell
  # Query correlated attack chains
  python main.py history --chains-only

  # Query Telegram remote control sessions
  python main.py history --telegram-sessions

  # Query historical Defender event correlations
  python main.py history --defender-only
  ```

---

#### 6. `export` — Multi-Format Security Report Generator

**Purpose**: Runs a scan pass and exports audit reports into `exports/connections.csv`, `exports/connections.json`, and `exports/audit_report.html`.

* **Usage Syntax**:
  ```powershell
  python main.py export [flags]
  ```

* **Command Flags**:
  - `--format FORMAT`: Specifies target export format (`csv`, `json`, `html`, or `all`; default: `all`).
  - `--scan-browsers`: Includes Browser URL threat findings in reports.
  - `--include-persistence`: Runs and includes a persistence scan section in reports.

---

## Telegram Remote Control Guide

When `monitor` is launched with `--telegram-control`, your Telegram app acts as a two-way remote control interface for Feluda:

```
                  ┌─────────────────────────────────────────┐
                  │          Telegram App (Mobile/Desktop)   │
                  │   Sends /high, /pause, /chains, etc.    │
                  └────────────────────┬────────────────────┘
                                       │ HTTP Long-Polling (getUpdates)
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │    telegram_listener.py (Feluda)        │
                  │      Parses command & updates state     │
                  └────────────────────┬────────────────────┘
                                       ▼
                  ┌─────────────────────────────────────────┐
                  │  MonitorController (monitor/realtime.py)│
                  │    Adjusts active scan mode & polling   │
                  └─────────────────────────────────────────┘
```

### Slash Commands & Inline Keyboard Buttons

| Command | Inline Button | Action / Effect |
|:---:|:---:|---|
| `/high` | 🔴 High Risk (>=50) | Restarts/sets scan loop to alert on HIGH & CRITICAL risk findings (score $\ge 50$). |
| `/medium` | 🟡 Medium+ (>=25) | Restarts/sets scan loop to alert on MEDIUM+ findings (score $\ge 25$). |
| `/low` | 🟢 All Low+ (>=0) | Restarts/sets scan loop to alert on ALL findings (score $\ge 0$). |
| `/pause` | ⏸ Pause | **Soft Stop**: Pauses the scan loop while keeping the Telegram listener active to resume anytime. |
| `/stop` | 🛑 End Session | **Hard Stop**: Ends the session completely, marks session as `stopped` in DB, and exits listener process. |
| `/chains` | 🔗 Attack Chains | Queries and displays recent correlated attack chains directly in Telegram. |
| `/status` | 📊 Status | Displays current session status, active mode, uptime, and total findings sent. |
| `/help` | ❓ Help | Renders the interactive command menu with Inline Keyboard buttons. |

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

All rules are additive, weighted, and configurable in [`config/rules.json`](config/rules.json):

#### Connection & Correlation Rules
| Rule Key | Weight | Description |
|---|:---:|---|
| `defender_correlated_detection` | **+50** | Active process matched against recent Windows Defender event log detection |
| `external_unknown_process` | **+30** | External public connection from an unrecognized process |
| `suspicious_location` | **+25** | Process running from `Temp`, `Downloads`, or `Users\Public` |
| `chain_correlation_bonus_2` | **+25** | Bonus when 2 distinct detection stages flag the same target identity |
| `chain_correlation_bonus_3` | **+40** | Bonus when 3 distinct detection stages flag the same target identity |
| `chain_correlation_bonus_4` | **+60** | Bonus when 4+ distinct detection stages flag the same target identity |
| `unusual_remote_port` | **+20** | Connection to an unusual or unassigned remote port |
| `outside_baseline` | **+15** | Connection pattern not seen during baseline training |
| `multiple_external_connections` | **+10** | Process holding $\ge 3$ simultaneous external connections |
| `repeated_connection` | **+10** | Connection reappears continuously across multiple scans |

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
