# Feluda — Build Prompt

## Project Summary
Build **Feluda**, a Python-based defensive security tool for Windows that:
- Monitors active network connections in real time
- Maps each connection to its owning process (PID → executable)
- Applies rule-based heuristics to flag potentially suspicious activity
- Assigns a transparent, explainable **risk score** (not a malware verdict)
- Provides CLI dashboard output, history storage, and export options

This is a **monitoring/triage tool**, not an antivirus or malware classifier. Every "suspicious" flag must be presented as a *signal*, with an explicit reason list — never as a definitive threat determination.

---

## Tech Stack
- **Language:** Python 3.12+
- **Core libraries:** `psutil`, `socket`, `ipaddress`, `subprocess`, `os`, `pathlib`, `datetime`, `sqlite3`, `json`, `csv`, `hashlib`
- **CLI/UI:** `rich`
- **Optional (later):** `requests`, Flask/FastAPI for a v2 dashboard

---

## Folder Structure
```
Feluda/
├── main.py
├── collector/
│   ├── connections.py
│   ├── processes.py
│   └── network.py
├── analyzer/
│   ├── ports.py
│   ├── processes.py
│   ├── ips.py
│   ├── rules.py
│   └── risk_score.py
├── monitor/
│   └── realtime.py
├── database/
│   ├── database.py
│   └── history.db
├── reports/
│   ├── csv_export.py
│   └── json_export.py
├── utils/
│   ├── logger.py
│   └── formatting.py
├── config/
│   └── rules.json
├── requirements.txt
└── README.md
```

---

## Functional Requirements by Phase

### Phase 1 — Connection Fundamentals
Understand and correctly label TCP states: `LISTEN`, `ESTABLISHED`, `TIME_WAIT`, `CLOSE_WAIT`, `SYN_SENT`, `SYN_RECEIVED`. Primary focus: `LISTEN` and `ESTABLISHED`.

### Phase 2 — Manual Baseline Understanding
Reference behavior should match what `netstat -ano` + `tasklist` shows manually (PID → local/remote address/port → process name), so output is verifiable against native Windows tools.

### Phase 3 — Connection Collection
Use `psutil.net_connections()` to collect, per connection:
```json
{
  "pid": 4212,
  "local_ip": "192.168.1.5",
  "local_port": 52144,
  "remote_ip": "142.250.xx.xx",
  "remote_port": 443,
  "status": "ESTABLISHED"
}
```

### Phase 4 — Process Mapping
For each PID, use `psutil.Process(pid)` to collect: process name, executable path, username, creation time.

### Phase 5 — IP Classification
Use `ipaddress.ip_address()` to classify each remote IP as Private / Loopback / Link-local / Public. Analysis should prioritize external (public) connections.

### Phase 6 — Port Intelligence
Maintain a `config/rules.json` mapping of well-known ports (21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80 HTTP, 443 HTTPS, 445 SMB, 3389 RDP, 5900 VNC, 8080 HTTP Proxy, etc.) to classify ports as common/low-risk vs. unusual. **Unusual port = signal, not proof of malice** — this framing must appear in code comments and any user-facing text.

### Phase 7 — Process Intelligence
Combine signals: unknown/unrecognized process + external connection + unusual port → contributes to a higher risk score, not an automatic verdict.

### Phase 8 — Execution Path Heuristics
Flag processes running from `AppData\Local\Temp` or `Downloads` as "suspicious execution location" (not "malware"). Normal locations: `Program Files`, `Windows\System32`.

### Phase 9 — Process Hashing
For flagged/notable processes, compute SHA-256 of the executable file for stable identification and future comparison (this mirrors how real EDR/AV tooling fingerprints binaries — no execution, no payload interaction, purely a hash-and-store operation).

### Phase 10 — Rule-Based Detection Engine
Implement `analyzer/rules.py` with additive, weighted rules, e.g.:
- External connection + unknown process → +30
- Unusual remote port → +20
- Process running from Temp → +25
- Process has multiple external connections → +10
- Connection repeatedly reappears → +10

Rules should be config-driven where reasonable so weights can be tuned without code changes.

### Phase 11 — Risk Scoring
Sum rule contributions into a 0–100 score with bands:
| Range | Level |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

Label this explicitly as a **heuristic risk score**, never as a "probability of malware."

### Phase 12 — Alerts
Render suspicious connections as a boxed CLI alert (via `rich`) showing process, PID, remote IP/port, status, risk score, and a bulleted reason list.

### Phase 13 — Real-Time Monitoring
Loop: collect connections → diff against previous scan → analyze new connections → alert on new/changed entries → sleep on a reasonable polling interval (avoid tight-loop polling).

### Phase 14 — Connection History
Persist every scan to `database/history.db` (SQLite): timestamp, PID, process, local/remote IP+port, status, risk score.

### Phase 15 — Repeated Connection Detection
Flag connections that reappear across multiple polling intervals as a distinct signal ("repeated external connection").

### Phase 16 — Baseline Learning
Support a "create baseline" mode that records normal process→port patterns (e.g., `chrome.exe → 443`). Later scans flag connections that fall outside the learned baseline.

### Phase 17 — Dashboard (v2, optional)
Local Flask/FastAPI dashboard summarizing active/external/suspicious/high-risk connection counts and a live table.

### Phase 18 — Export
Support export to `connections.csv`, `connections.json`, and an `audit_report.html`.

### Phase 19 — Logging
Write structured logs to `logs/feluda.log` for every detection event (timestamp, PID, process, risk level).

---

## Design Principles (apply throughout)
1. **Signals, not verdicts.** Every flag/alert must list *why* (reasons), and avoid absolute language like "malware" or "infected."
2. **Modular from the start** — respect the folder structure above; don't collapse logic into `main.py`.
3. **Config-driven rules** — thresholds and port lists live in `config/rules.json`, not hardcoded.
4. **Local-only scope** — this tool inspects the local machine's own connections/processes via `psutil`; it does not scan, probe, or connect to remote hosts.
5. **Explainability first** — the CLI output and exports should always make the reasoning behind a score legible to a non-expert reviewer.

---

## Deliverable for This Session
Scaffold the project per the folder structure above, starting with:
1. `collector/connections.py` + `collector/processes.py` (Phases 3–4)
2. `analyzer/ports.py`, `analyzer/ips.py` (Phases 5–6)
3. `config/rules.json` skeleton (Phase 6)
4. A working `main.py` that runs a single scan and prints a `rich`-formatted table (Phase 3 output shape)

Then iterate toward the detection engine, scoring, and real-time monitor.