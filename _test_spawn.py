"""Manual test: spawn a suspicious lineage chain and scan against it.

Spins up NOI-style: cmd.exe -> powershell.exe -> ping (network-ish pid), so
the lineage walk sees: cmd.exe as the immediate parent of powershell.exe.
office_spawned_shell expects an Office app parent — we simulate that rule name
by monkey-patching the parent name to trigger the same path. Everything is
local + clean; no persistence, no network.
"""
import subprocess
import sys
import time

import psutil

from analyzer import lineage_analyzer as la
from monitor.pipeline import run_scan

# spawn our test chain: powershell.exe lives under cmd.exe
ps = subprocess.Popen(
    ["powershell.exe", "-NoProfile", "-Command", "Start-Sleep -Seconds 120"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
time.sleep(1.5)  # let the tree settle

chain = la.walk_lineage(ps.pid)
print("spawned ps pid:", ps.pid, "chain:", [(l["name"], l["pid"]) for l in chain["chain"]])

# Rule verification against the real chain
fires = {}
for rule in la.RULES:
    hit, pts, reason = rule(chain)
    if hit:
        fires[rule.__name__] = (pts, reason)
        print("TRIGGERS:", rule.__name__, "+", pts, "-", reason[:100])

# spawn a second shell directly under the default parent: creates a benign baseline
ps2 = subprocess.Popen(
    ["powershell.exe", "-Command", "echo hello"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
time.sleep(0.5)
control = la.walk_lineage(ps2.pid)
c_fires = {}
for rule in la.RULES:
    hit, pts, reason = rule(control)
    if hit:
        c_fires[rule.__name__] = (pts, reason)
print("benign control fires:", len(c_fires))

# office_spawned_shell needs an Office name in the chain; temporarily claim the
# first link is winword so the rule engages against the real structure.
print("(simulation only: first chain entry seen as winword.exe)")
chain_sim = la.walk_lineage(ps.pid)
chain_sim["chain"][0]["name"] = "winword.exe"
hit, pts, reason = la.rule_office_spawned_shell(chain_sim)
print("office_spawned_shell (simulated): hit=", hit, f"+{pts}", reason[:100])

for p in (ps, ps2):
    try:
        p.terminate()
    except Exception:
        pass
