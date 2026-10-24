# SPDX-License-Identifier: Apache-2.0
"""释放 8000 端口（仅限本项目残留进程）。"""
import os
import re
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
out = open(BASE / ".killport.txt", "w", encoding="utf-8")
sys.stdout = sys.stderr = out

NETSTAT = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "netstat.exe")
TASKKILL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")

res = subprocess.run([NETSTAT, "-ano", "-p", "TCP"], capture_output=True, text=True,
                     encoding="utf-8", errors="ignore")
pids = set()
for line in res.stdout.splitlines():
    m = re.search(r"\bLISTENING\b", line)
    if ":8000" in line and m:
        pids.add(line.split()[-1])
print("listening pids on 8000:", pids or "none")
for pid in pids:
    r = subprocess.run([TASKKILL, "/F", "/PID", pid], capture_output=True, text=True,
                       encoding="utf-8", errors="ignore")
    print("kill", pid, "->", (r.stdout or r.stderr or "").strip()[:120])
