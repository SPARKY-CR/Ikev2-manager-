#!/usr/bin/env python3
"""ikev2lib - shared helpers for ikev2-manager (SA parsing, formatting).

CLI:
  ikev2lib.py online [--json]   list connected clients
  ikev2lib.py count             number of connected clients
  ikev2lib.py kick NAME         terminate all sessions of user NAME
"""
import json
import re
import subprocess
import sys

SA_HEAD = re.compile(r"^(?P<conn>\S+): #(?P<id>\d+), (?P<state>[A-Z_]+), IKEv(?P<ver>\d)")
REMOTE = re.compile(
    r"^\s*remote '(?P<rid>[^']*)' @ (?P<rip>\S+?)\[(?P<rport>\d+)\]"
    r"(?:\s+EAP: '(?P<eap>[^']*)')?(?:\s+\[(?P<vip>[^\]]+)\])?"
)
ESTAB = re.compile(r"established (?P<secs>\d+)s ago")
BYTES_IN = re.compile(r"^\s+in\s+\S+,\s+(?P<n>\d+) bytes")
BYTES_OUT = re.compile(r"^\s+out\s+\S+,\s+(?P<n>\d+) bytes")


def list_sas_text():
    try:
        p = subprocess.run(
            ["swanctl", "--list-sas"],
            capture_output=True, text=True, timeout=15,
        )
        return p.stdout
    except Exception:
        return ""


def parse_sas(text):
    """Parse `swanctl --list-sas` text into a list of dicts."""
    sas = []
    cur = None
    for line in text.splitlines():
        m = SA_HEAD.match(line)
        if m:
            cur = {
                "conn": m.group("conn"), "id": int(m.group("id")),
                "state": m.group("state"), "user": "", "ip": "", "vip": "",
                "secs": 0, "rx": 0, "tx": 0,
            }
            sas.append(cur)
            continue
        if cur is None:
            continue
        m = REMOTE.match(line)
        if m and not cur["ip"]:
            cur["ip"] = m.group("rip")
            cur["user"] = m.group("eap") or m.group("rid")
            cur["vip"] = (m.group("vip") or "").split()[0] if m.group("vip") else ""
            continue
        m = ESTAB.search(line)
        if m and not cur["secs"]:
            cur["secs"] = int(m.group("secs"))
            continue
        m = BYTES_IN.match(line)
        if m:
            cur["rx"] += int(m.group("n"))
            continue
        m = BYTES_OUT.match(line)
        if m:
            cur["tx"] += int(m.group("n"))
    return [s for s in sas if s["state"] == "ESTABLISHED"]


def online():
    return parse_sas(list_sas_text())


def kick(name):
    n = 0
    for sa in online():
        if sa["user"] == name:
            subprocess.run(
                ["swanctl", "--terminate", "--ike-id", str(sa["id"])],
                capture_output=True, timeout=15,
            )
            n += 1
    return n


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_dur(secs):
    secs = int(secs)
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m"
    return f"{s}s"


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "online":
        sas = online()
        if "--json" in argv:
            print(json.dumps(sas))
        else:
            for s in sas:
                print(f"{s['user']}|{s['ip']}|{s['vip']}|{fmt_dur(s['secs'])}|"
                      f"{fmt_bytes(s['rx'])}|{fmt_bytes(s['tx'])}|{s['id']}")
        return 0
    if cmd == "count":
        print(len(online()))
        return 0
    if cmd == "kick" and len(argv) > 2:
        print(kick(argv[2]))
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
