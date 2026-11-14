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
  ikev2lib.py quota SUBCOMMAND  traffic limits and expiry per user (list|show|set|add|reset|init|forget|tick|
                                parse-size|parse-expiry|parse-days); called by `vpn quota`, which holds the lock
  ikev2lib.py check-backup FILE [ROOT...]
                                verify that a backup archive only touches etc/ikev2, etc/swanctl
                                and etc/letsencrypt (or the given ROOTs); exit 1 + reasons
                                otherwise - run before extracting an archive as root
"""
import base64
import datetime
import fcntl
import json
import os
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import time

SA_HEAD = re.compile(r"^(?P<conn>\S+): #(?P<id>\d+), (?P<state>[A-Z_]+), IKEv(?P<ver>\d)")
REMOTE = re.compile(
    r"^\s*remote '(?P<rid>[^']*)' @ (?P<rip>\S+?)\[(?P<rport>\d+)\]"
    r"(?:\s+EAP: '(?P<eap>[^']*)')?(?:\s+\[(?P<vip>[^\]]+)\])?"
)
ESTAB = re.compile(r"established (?P<secs>\d+)s ago")
BYTES_IN = re.compile(r"^\s+in\s+(?P<spi>\S+),\s+(?P<n>\d+) bytes")
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


def list_sas_checked():
    """(True, text) when swanctl answered, (False, "") when it could not be queried (daemon down, timeout...)."""
    try:
        p = subprocess.run(["swanctl", "--list-sas"], capture_output=True, text=True, timeout=15)
    except Exception:
        return False, ""
    return p.returncode == 0, p.stdout


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
                "secs": 0, "rx": 0, "tx": 0, "children": [],
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
            cur["children"].append({"spi": m.group("spi"), "rx": int(m.group("n")), "tx": 0})
            continue
        m = BYTES_OUT.match(line)
        if m:
            cur["tx"] += int(m.group("n"))
            if cur["children"]:
                cur["children"][-1]["tx"] = int(m.group("n"))
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


# ------------------------------------------------------------------ traffic quota + expiry
# quotas.db (in the config folder, covered by backups), one line per user:
#   name:limit_bytes:expires_epoch:action:used_bytes:state:flags
#   limit 0 = unlimited, expires 0 = never; action = default|disable|delete|notify
#   state = "" (ok) | quota | expired   -> the user was disabled by the quota logic (and may be re-enabled by it)
#   flags = letters of one-shot notifications already sent: w = 80% warning, e = expiry warning, x = limit reached
# usage_seen.json (in the state folder) remembers the last counter of every child SA, so a tick only adds the delta.
QUOTA_ACTIONS = ("default", "disable", "delete", "notify")
QUOTA_WARN_FRACTION = 0.8
EXPIRY_WARN_SECS = 3 * 86400
_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([kmgt]?)(i?b)?$")
_NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")


def etc_dir():
    return os.environ.get("IKEV2_ETC", "/etc/ikev2")


def var_dir():
    return os.environ.get("IKEV2_VAR", "/var/lib/ikev2")


def parse_size(text):
    """'10G', '500M', '1.5T', '0', 'unlimited' -> bytes (0 = unlimited). A bare number means GB; '500b' means bytes."""
    t = str(text).strip().lower().replace(" ", "")
    if t in ("", "0", "unlimited", "none", "off", "never", "no"):
        return 0
    m = _SIZE_RE.match(t)
    if not m:
        raise ValueError(f"invalid size: {text!r} (examples: 500M, 10G, 1.5T, unlimited)")
    num, unit, b = float(m.group(1)), m.group(2), m.group(3)
    power = "kmgt".index(unit) + 1 if unit else (0 if b else 3)
    n = int(num * 1024 ** power)
    if n > 1024 ** 5:
        raise ValueError("size is too large")
    return n


def parse_days(text):
    """'30' / '30d' / '+30' -> 30 (days)."""
    m = re.match(r"^\+?(\d{1,5})d?$", str(text).strip().lower())
    if not m or int(m.group(1)) > 36500:
        raise ValueError(f"invalid number of days: {text!r}")
    return int(m.group(1))


def parse_expiry(text, now=None):
    """'30d' / '30' (days from now), '2026-12-31' (end of that day, local time), 'never' -> epoch (0 = never)."""
    now = time.time() if now is None else now
    t = str(text).strip().lower()
    if t in ("", "0", "never", "none", "off", "unlimited", "no"):
        return 0
    if re.match(r"^\d{4}-\d{2}-\d{2}$", t):
        y, mo, d = (int(x) for x in t.split("-"))
        try:
            return int(datetime.datetime(y, mo, d, 23, 59, 59).timestamp())
        except ValueError:
            raise ValueError(f"invalid date: {text!r} (use YYYY-MM-DD)")
    return int(now) + parse_days(t) * 86400


def _quota_path():
    return os.path.join(etc_dir(), "quotas.db")


def new_record(name, limit=0, expires=0, action="default"):
    return {"name": name, "limit": int(limit), "expires": int(expires), "action": action,
            "used": 0, "state": "", "flags": ""}


def load_quotas(path=None):
    """{name: record}; malformed lines are skipped."""
    out = {}
    try:
        with open(path or _quota_path(), encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split(":")
                if len(p) != 7 or not _NAME_OK.match(p[0]):
                    continue
                try:
                    r = {"name": p[0], "limit": max(0, int(p[1])), "expires": max(0, int(p[2])), "action": p[3],
                         "used": max(0, int(p[4])), "state": p[5], "flags": p[6]}
                except ValueError:
                    continue
                if r["action"] not in QUOTA_ACTIONS or r["state"] not in ("", "quota", "expired"):
                    continue
                out[r["name"]] = r
    except FileNotFoundError:
        pass
    return out


def _atomic_write(path, data):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_quotas(quotas, path=None):
    lines = [f"{r['name']}:{r['limit']}:{r['expires']}:{r['action']}:{r['used']}:{r['state']}:{r['flags']}\n"
             for _, r in sorted(quotas.items())]
    _atomic_write(path or _quota_path(), "".join(lines))


def users_status():
    """{name: 'enabled'|'disabled'} from users.db (only well-formed lines)."""
    out = {}
    try:
        with open(os.path.join(etc_dir(), "users.db"), encoding="utf-8") as f:
            for line in f:
                p = line.rstrip("\n").split(":")
                if len(p) == 4 and _NAME_OK.match(p[0]):
                    out[p[0]] = p[2]
    except FileNotFoundError:
        pass
    return out


def quota_over(r, now):
    """'expired' | 'quota' | '' for a record at time `now` (expiry wins when both apply)."""
    if r["expires"] and now >= r["expires"]:
        return "expired"
    if r["limit"] and r["used"] >= r["limit"]:
        return "quota"
    return ""


def fmt_expiry(epoch, now=None):
    if not epoch:
        return "never"
    now = time.time() if now is None else now
    left = epoch - now
    day = datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d")
    if left <= 0:
        return f"{day} (expired)"
    if left >= 86400:
        return f"{day} ({-(-int(left) // 86400)}d left)"      # whole days, rounded up
    return f"{day} ({fmt_dur(left)} left)"


def quota_label(r, now=None):
    now = time.time() if now is None else now
    over = quota_over(r, now)
    if over == "expired":
        return "expired"
    if over == "quota":
        return "quota reached"
    return "ok"


def _emit_event(kind, user, **extra):
    """Queue an event for the Telegram bot (one JSON object per line). The bot empties the file."""
    path = os.path.join(var_dir(), "quota_events.jsonl")
    os.makedirs(var_dir(), exist_ok=True)
    with open(path + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": int(time.time()), "kind": kind, "user": user, **extra}) + "\n")


def take_events():
    """Return and clear the queued quota events (used by the bot)."""
    path = os.path.join(var_dir(), "quota_events.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    with open(path + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
            os.unlink(path)
        except FileNotFoundError:
            pass
    return out


def _seen_path():
    return os.path.join(var_dir(), "usage_seen.json")


def measure(sas, quotas):
    """Add the traffic since the previous tick to every user's `used` counter. Returns the bytes added in total.

    strongSwan reports cumulative counters per child SA (they restart from 0 on a rekey and vanish on disconnect), so the
    last value of every child SA is remembered and only the difference is counted. The very first run only records the
    current counters as a baseline, so traffic from before the feature existed is not billed."""
    try:
        with open(_seen_path(), encoding="utf-8") as f:
            seen = json.load(f)
        baseline = False
    except (OSError, ValueError):
        seen, baseline = {}, True
    now_seen, added = {}, 0
    for sa in sas:
        user = sa.get("user", "")
        for ch in sa.get("children", []):
            key = f"{user}|{sa['id']}|{ch['spi']}"
            cur = int(ch["rx"]) + int(ch["tx"])
            now_seen[key] = cur
            if baseline or user not in quotas:
                continue
            prev = seen.get(key)
            delta = cur if prev is None or cur < prev else cur - prev
            if delta:
                quotas[user]["used"] += delta
                added += delta
    _atomic_write(_seen_path(), json.dumps(now_seen))
    return added


def quota_tick(global_action="disable", sas=None, now=None, do_measure=True):
    """One pass: count traffic, then decide what to do. Returns the actions for `vpn` to apply, as
    [("disable"|"enable"|"delete", name, reason)]. Notifications for the bot are queued as events."""
    now = time.time() if now is None else now
    status = users_status()
    quotas = load_quotas()
    before = json.dumps(quotas, sort_keys=True)
    for name in list(quotas):
        if name not in status:
            del quotas[name]
    for name in status:
        quotas.setdefault(name, new_record(name))
    if do_measure:
        if sas is None:
            ok, text = list_sas_checked()
            sas = parse_sas(text) if ok else None
        if sas is not None:
            measure(sas, quotas)
    actions = []
    for name, r in sorted(quotas.items()):
        over = quota_over(r, now)
        act = r["action"] if r["action"] != "default" else global_action
        enabled = status[name] == "enabled"
        if over:
            first = "x" not in r["flags"]
            if act == "delete":
                actions.append(("delete", name, over))
            elif act == "disable":
                if enabled:
                    r["state"] = over
                    actions.append(("disable", name, over))
                elif r["state"]:
                    r["state"] = over
            else:                                   # notify only: never touch the user
                r["state"] = ""
            if first:
                r["flags"] += "x"
                if act != "disable" or enabled or r["state"]:
                    _emit_event("expired" if over == "expired" else "limit", name, action=act,
                                used=r["used"], limit=r["limit"])
        else:
            if r["state"]:
                r["state"] = ""
                if not enabled:
                    actions.append(("enable", name, "renewed"))
            r["flags"] = r["flags"].replace("x", "")
            if r["limit"] and r["used"] >= r["limit"] * QUOTA_WARN_FRACTION and "w" not in r["flags"]:
                r["flags"] += "w"
                _emit_event("warn_limit", name, used=r["used"], limit=r["limit"])
            if r["expires"] and 0 < r["expires"] - now <= EXPIRY_WARN_SECS and "e" not in r["flags"]:
                r["flags"] += "e"
                _emit_event("warn_expiry", name, expires=r["expires"])
    if json.dumps(quotas, sort_keys=True) != before:
        save_quotas(quotas)
    return actions


def _quota_get(quotas, name):
    if name not in users_status():
        raise KeyError(f"No such user: {name}")
    return quotas.setdefault(name, new_record(name))


def _apply_args(r, args, relative, now):
    """Apply --limit / --days / --expires / --action to a record. Raises ValueError on bad input."""
    i = 0
    while i < len(args):
        a = args[i]
        if a not in ("--limit", "--days", "--expires", "--action") or i + 1 >= len(args):
            raise ValueError(f"unknown or incomplete option: {a}")
        v = args[i + 1]
        i += 2
        if a == "--limit":
            n = parse_size(v)
            r["limit"] = (r["limit"] + n) if relative and r["limit"] else n
        elif a == "--days":
            if relative:
                base = max(r["expires"], int(now)) if r["expires"] else int(now)
                r["expires"] = base + parse_days(v) * 86400
            else:
                r["expires"] = parse_expiry(v, now)
        elif a == "--expires":
            if relative:
                raise ValueError("use --days with 'add'")
            r["expires"] = parse_expiry(v, now)
        elif a == "--action":
            if v not in QUOTA_ACTIONS:
                raise ValueError("action must be one of: " + ", ".join(QUOTA_ACTIONS))
            r["action"] = v
    r["flags"] = ""          # new limits -> the one-shot warnings may fire again


def quota_summary(r, now=None):
    now = time.time() if now is None else now
    lim = fmt_bytes(r["limit"]) if r["limit"] else "unlimited"
    return (f"{r['name']}: used {fmt_bytes(r['used'])} of {lim}, expires {fmt_expiry(r['expires'], now)}, "
            f"when over: {r['action']}, state: {quota_label(r, now)}")


def quota_cli(argv):
    """`ikev2lib.py quota SUBCOMMAND ...` - called by `vpn` (which holds the global lock for anything that writes)."""
    sub = argv[0] if argv else ""
    rest = argv[1:]
    now = time.time()
    try:
        if sub == "parse-size" and len(rest) == 1:
            print(parse_size(rest[0]))
        elif sub == "parse-expiry" and len(rest) == 1:
            print(parse_expiry(rest[0], now))
        elif sub == "parse-days" and len(rest) == 1:
            print(parse_days(rest[0]))
        elif sub == "init" and len(rest) == 4:
            q = load_quotas()
            if rest[3] not in QUOTA_ACTIONS:
                raise ValueError("bad action")
            q[rest[0]] = new_record(rest[0], int(rest[1]), int(rest[2]), rest[3])
            save_quotas(q)
        elif sub == "forget" and len(rest) == 1:
            q = load_quotas()
            if q.pop(rest[0], None) is not None:
                save_quotas(q)
        elif sub in ("set", "add") and len(rest) >= 2:
            q = load_quotas()
            r = _quota_get(q, rest[0])
            _apply_args(r, rest[1:], sub == "add", now)
            save_quotas(q)
            print(quota_summary(r, now))
        elif sub == "reset" and len(rest) == 1:
            q = load_quotas()
            r = _quota_get(q, rest[0])
            r["used"], r["flags"] = 0, ""
            save_quotas(q)
            print(quota_summary(r, now))
        elif sub == "show" and rest:
            q = load_quotas()
            r = _quota_get(q, rest[0])
            if "--kv" in rest[1:]:
                print(f"limit={r['limit']}\nused={r['used']}\nexpires={r['expires']}\naction={r['action']}\n"
                      f"state={r['state']}\nlabel={quota_label(r, now)}")
            else:
                print(quota_summary(r, now))
        elif sub == "list":
            q = load_quotas()
            names = list(users_status())
            if "--short" in rest:
                for n in names:
                    r = q.get(n) or new_record(n)
                    print(f"{n}|{fmt_bytes(r['used'])}|{fmt_bytes(r['limit']) if r['limit'] else '-'}|"
                          f"{fmt_expiry(r['expires'], now)}|{quota_label(r, now)}")
            elif "--plain" in rest:
                for n in names:
                    r = q.get(n) or new_record(n)
                    print(f"{n}|{r['limit']}|{r['used']}|{r['expires']}|{r['action']}|{r['state']}")
            else:
                print(f"{'USER':<20} {'USED':>10} {'LIMIT':>10}  {'EXPIRES':<24} {'WHEN OVER':<9} STATE")
                for n in names:
                    r = q.get(n) or new_record(n)
                    print(f"{n:<20} {fmt_bytes(r['used']):>10} {(fmt_bytes(r['limit']) if r['limit'] else '-'):>10}  "
                          f"{fmt_expiry(r['expires'], now):<24} {r['action']:<9} {quota_label(r, now)}")
        elif sub == "tick":
            act = "disable"
            if "--action" in rest:
                act = rest[rest.index("--action") + 1]
            for a, n, why in quota_tick(act, now=now, do_measure="--no-measure" not in rest):
                print(f"{a} {n} {why}")
        else:
            print(__doc__, file=sys.stderr)
            return 1
    except (ValueError, KeyError) as exc:
        print(str(exc.args[0]) if exc.args else str(exc), file=sys.stderr)
        return 1
    return 0


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
    if cmd == "quota":
        return quota_cli(argv[2:])
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
