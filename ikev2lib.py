#!/usr/bin/env python3
"""ikev2lib - shared helpers for ikev2-manager (SA parsing, formatting).

CLI:
  ikev2lib.py online [--json]   list connected clients
  ikev2lib.py count             number of connected clients
  ikev2lib.py kick NAME         terminate all sessions of user NAME
  ikev2lib.py zedsecure NAME SERVER USER [CA_PEM_FILE] [MTU]
                                print a ZedSecure import link (zedsecure://...).
                                The password is read from the environment variable
                                IKEV2_ZED_PASS (empty = link without password) so that it
                                never appears on a command line.
  ikev2lib.py check-backup FILE [ROOT...]
                                verify that a backup archive only touches etc/ikev2, etc/swanctl
                                and etc/letsencrypt (or the given ROOTs); exit 1 + reasons
                                otherwise - run before extracting an archive as root
"""
import base64
import json
import os
import posixpath
import re
import subprocess
import sys
import tarfile

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


def zedsecure_link(name, server, username, password, ca_pem="", mtu=1400):
    """Build a ZedSecure IKEv2 share link: zedsecure:// + base64(compact JSON).

    Format (reverse-engineered from an exported link): {"v":1,"n":name,"s":{"kind":"ikev2",
    "settings":{server, remoteId, localId, authType, username, password, psk, caCertPem,
    userCertAlias, ikeProposal, espProposal, mtu}},"m":[]}.
    JSON allows whitespace, so we pad it until the base64 has no '=' padding and no '+' or '/'
    (these only appear for the bytes > ? ~ DEL), which makes standard and URL-safe base64 identical.
    """
    obj = {
        "v": 1, "n": name,
        "s": {"kind": "ikev2", "settings": {
            "server": server, "remoteId": "", "localId": "", "authType": "eap_mschapv2",
            "username": username, "password": password, "psk": "", "caCertPem": ca_pem,
            "userCertAlias": "", "ikeProposal": "", "espProposal": "", "mtu": int(mtu)}},
        "m": [],
    }
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    first = None
    for lead in range(3):
        body = "{" + " " * lead + raw[1:]
        body += " " * ((-len(body.encode())) % 3)
        enc = base64.b64encode(body.encode()).decode()
        if first is None:
            first = enc
        if "+" not in enc and "/" not in enc:
            return "zedsecure://" + enc
    return "zedsecure://" + first.rstrip("=")


BACKUP_ROOTS = ("etc/ikev2", "etc/swanctl", "etc/letsencrypt")
BACKUP_MAX_MEMBER = 512 * 1024 * 1024


def _in_roots(path, roots=BACKUP_ROOTS):
    return any(path == r or path.startswith(r + "/") for r in roots)


def check_backup(path, roots=BACKUP_ROOTS):
    """Return the problems found in a backup archive; an empty list means it is safe to
    extract with `tar -C / -xzf` as root: every member stays inside BACKUP_ROOTS, and there
    are no absolute names, '..' components, hard links, device files, setuid bits,
    world-writable entries or symlinks that point outside the allowed folders."""
    problems = []
    try:
        tf = tarfile.open(path, "r:*")
    except Exception as exc:  # not an archive / unreadable
        return [f"cannot read archive: {exc}"]
    count = 0
    with tf:
        for m in tf:
            count += 1
            raw = m.name
            if raw.startswith("/"):
                problems.append(f"absolute path: {raw}")
                continue
            parts = [x for x in raw.split("/") if x not in ("", ".")]
            if ".." in parts:
                problems.append(f"path traversal: {raw}")
                continue
            name = "/".join(parts)
            if not _in_roots(name, roots):
                problems.append(f"outside the allowed folders: {raw}")
                continue
            if m.isdev() or m.isfifo():
                problems.append(f"device/fifo member: {raw}")
            elif m.islnk():
                problems.append(f"hard link: {raw}")
            elif m.issym():
                if m.linkname.startswith("/"):
                    problems.append(f"absolute symlink: {raw} -> {m.linkname}")
                else:
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(name), m.linkname))
                    if not _in_roots(target, roots):
                        problems.append(f"symlink leaves the allowed folders: {raw} -> {m.linkname}")
            elif not (m.isfile() or m.isdir()):
                problems.append(f"unsupported member type: {raw}")
            if m.mode & 0o6000:
                problems.append(f"setuid/setgid bit: {raw}")
            if m.mode & 0o002:
                problems.append(f"world-writable: {raw}")
            if m.isfile() and m.size > BACKUP_MAX_MEMBER:
                problems.append(f"member too large: {raw}")
    if count == 0:
        problems.append("archive is empty")
    return problems


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
    if cmd == "zedsecure" and len(argv) >= 5:
        password = os.environ.get("IKEV2_ZED_PASS", "")
        ca = ""
        if len(argv) > 5 and argv[5]:
            with open(argv[5], encoding="utf-8") as f:
                ca = f.read().strip()
        mtu = argv[6] if len(argv) > 6 else 1400
        print(zedsecure_link(argv[2], argv[3], argv[4], password, ca, mtu))
        return 0
    if cmd == "check-backup" and len(argv) >= 3:
        # optional extra arguments replace the allowed roots (used by `vpn` with its configured paths)
        problems = check_backup(argv[2], tuple(a.strip("/") for a in argv[3:]) or BACKUP_ROOTS)
        for line in problems:
            print(line, file=sys.stderr)
        return 1 if problems else 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
