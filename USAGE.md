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

All commands are executed via `main.py`:

```powershell
python main.py [options] <command> [command-options]
```

### Options
- `--no-banner`: Suppress the startup ASCII banner.

---

### 1. `scan` — Point-in-Time Connection Scan

Runs a single scan of active network connections and displays a color-coded Rich table.

```powershell
# Basic scan (shows active sessions & external connections)
python main.py scan

# Include quiet LISTEN sockets
python main.py scan --all

# Skip comparison against learned baseline
python main.py scan --no-baseline
```

#### Sample Output Fields
- **Process / PID**: Executable name and Process ID.
- **Local / Remote Address**: IP address and port.
- **Status**: TCP state (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`).
- **Risk Score**: 0–100 score color-coded by severity.
- **Reasons**: Bulleted list of triggered heuristic rules showing score contributions (e.g. `+30`, `+25`).

---

### 2. `browsers` — Browser & URL Threat Detection

Scans running web browsers, extracts open/recent tabs, and evaluates structural URL security risks.

```powershell
# One-pass scan and render Browser Activity panel
python main.py browsers

# Live watch mode: poll for newly opened tabs every 5 seconds
python main.py browsers --live --interval 5
```

#### Features & Signals Inspected
- **Browser & PID**: Process info for Chrome, Brave, Edge, Arc, or Firefox.
- **URL**: Full web address inspected offline.
- **Risk Score**:
  - `0–29`: Green (Low risk)
  - `30–60`: Yellow (Medium risk)
  - `>60`: Red (High risk)
- **Signals**: Homograph IDN, Typosquatting, IP Literals, Obfuscation, Abused TLDs.

---

### 3. `monitor` — Real-Time Polling & Boxed Alerts

Runs a continuous background polling loop, persisting scan data to SQLite and raising boxed CLI panels for high-risk connections.

```powershell
# Continuous monitoring (default 5-second polling interval)
python main.py monitor

# Custom polling interval (e.g. every 10 seconds)
python main.py monitor --interval 10

# Single iteration test run
python main.py monitor --once
```

---

### 4. `baseline` — Baseline Learning Mode

Learns current process-to-remote-port patterns from active external connections.

```powershell
# Record baseline
python main.py baseline
```

> [!NOTE]
> Once a baseline is learned, any future external connection matching an unlearned `process:port` combination will trigger a **+15 Outside Baseline** risk signal.

---

### 5. `history` — Query Past Audits

Retrieves historical scan records stored in SQLite (`database/history.db`).

```powershell
# View last 50 recorded connections
python main.py history --limit 50

# Filter history by risk level
python main.py history --level HIGH
```

---

### 6. `export` — Generate Security Reports

Scans current connections (and optionally browser activity) and exports audit reports.

```powershell
# Export connections to CSV, JSON, and HTML
python main.py export --format all

# Export only CSV
python main.py export --format csv

# Include Browser URL threat detections in export
python main.py export --scan-browsers --format all
```

#### Output Artifacts (written to `exports/`):
- `exports/connections.csv`: Spreadsheet-ready audit rows.
- `exports/connections.json`: Structured JSON for SIEM / automation integration.
- `exports/audit_report.html`: Self-contained HTML report with summary stats, badges, and browser activity sections.

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
