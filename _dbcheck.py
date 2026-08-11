import sqlite3
from browser import cert_inspector as ci

print("cert_inspector imports ok")
print(" cert cache TTL hours:", ci.settings().get("cert", {}).get("cache_ttl_hours"))

c = sqlite3.connect(r"D:\Feluda\database\history.db")
rows = c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
print("tables:", [r[0] for r in rows])
count = c.execute("SELECT COUNT(*) FROM cert_checks").fetchone()[0]
print("cert_checks rows:", count)
