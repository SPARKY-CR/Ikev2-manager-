#!/usr/bin/env python3
"""ikev2-manager Telegram bot - admin only, Persian/English, stdlib only."""
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ikev2lib as L  # noqa: E402

ETC = os.environ.get("IKEV2_ETC", "/etc/ikev2")
VAR = os.environ.get("IKEV2_VAR", "/var/lib/ikev2")
BACKUPS = os.environ.get("IKEV2_BACKUPS", "/var/backups/ikev2")
VPN = os.environ.get("IKEV2_VPN", "/usr/local/bin/vpn")
CONF = f"{ETC}/config.env"
STATE_FILE = f"{VAR}/bot_state.json"
INCOMING = f"{VAR}/incoming"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
PASS_RE = re.compile(r"^[A-Za-z0-9._@+=,!%^*~-]{8,64}$")

# ----------------------------------------------------------------- texts
T = {
    "en": {
        "menu": "🛡 <b>IKEv2 VPN Manager</b>\nVersion {ver}\nServer: <code>{server}</code>",
        "b_users": "👥 Users", "b_add": "➕ Add user", "b_status": "📡 Status",
        "b_online": "🟢 Online now", "b_info": "ℹ️ Server info", "b_restart": "🔁 Restart VPN",
        "b_backup": "📦 Backup", "b_update": "⬆️ Updates", "b_lang": "🌐 فارسی",
        "b_notify": "🔔 Alerts", "b_back": "⬅️ Back", "b_menu": "🏠 Menu",
        "users_title": "👥 <b>Users</b> ({n})\nTap a user to manage.",
        "no_users": "No users yet.",
        "ask_name": "Send the new username (letters, digits, _ . - ; max 32 chars).",
        "bad_name": "❌ Invalid username. Use letters, digits and _ . - only.",
        "exists": "❌ This user already exists.",
        "created": "✅ User <b>{user}</b> created.",
        "conn_info": "🔑 <b>Connection info</b>\nServer: <code>{server}</code>\nUsername: <code>{user}</code>\nPassword: <code>{pw}</code>",
        "sending_files": "📎 Sending profile files…",
        "cap_sswan": "Android: strongSwan app → Import VPN profile (enter the password).",
        "cap_mobile": "iPhone/iPad/Mac: open and install this profile.",
        "cap_win": "Windows: run in PowerShell as Administrator.",
        "cap_ca": "CA certificate (only needed for manual setups).",
        "cap_readme": "Setup instructions.",
        "cap_zed": "ZedSecure: import links (copy from this file or from the message above).",
        "zed_link": "🔗 <b>ZedSecure</b> — copy this link, then import it from the clipboard in the app:\n<code>{link}</code>",
        "user_view": "👤 <b>{user}</b>\nStatus: {state}\nOnline: {online}",
        "st_on": "enabled ✅", "st_off": "disabled ⛔", "yes": "yes", "no": "no",
        "b_profiles": "📲 Get profiles", "b_disable": "⛔ Disable", "b_enable": "✅ Enable",
        "b_passwd": "🔑 Change password", "b_delete": "🗑 Delete",
        "confirm_del": "❓ Delete <b>{user}</b>? This cannot be undone.",
        "b_yes_del": "✅ Yes, delete", "b_cancel": "❌ Cancel",
        "deleted": "🗑 User <b>{user}</b> deleted.",
        "status_set": "✅ User <b>{user}</b> is now {state}.",
        "ask_pw": "Send the new password (8-64 chars: letters, digits, . _ @ + = , ! % ^ * ~ -) or send <code>auto</code> for a random one.",
        "bad_pw": "❌ Invalid password.",
        "pw_changed": "✅ Password changed.",
        "status": "📡 <b>Status</b>\nVPN service: {svc}\nUsers: {users} (enabled {enabled}), online: {online}\nCertificate: {cert} days left\nstrongSwan: {sw}\nTool version: {ver}\nFirewall: {fw}",
        "no_online": "Nobody is online right now.",
        "online_title": "🟢 <b>Online now</b> ({n})",
        "info": "ℹ️ <b>Server info</b>\nAddress: <code>{server}</code>\nMode: {mode}\nVPN pool: {pool}\nDNS: {dns}\nPorts: UDP 500, UDP 4500",
        "restarting": "⏳ Restarting…", "restarted": "✅ VPN service restarted. State: {svc}",
        "backup_menu": "📦 <b>Backup</b>\nLatest: {last}",
        "b_make_backup": "🆕 Create backup", "b_send_backup": "📤 Send latest backup to me",
        "backup_done": "✅ Backup created:\n<code>{path}</code>", "backup_fail": "❌ Backup failed.\n{err}",
        "no_backup": "No backup exists yet.", "none": "none",
        "backup_warn": "⚠️ The backup contains private keys and all user passwords. Send it here only if you are sure.",
        "b_send_ok": "✅ Yes, send it",
        "update_menu": "⬆️ <b>Updates</b>\nTool version: {ver}\nstrongSwan: {sw}",
        "b_upd_sw": "🔄 Update strongSwan (apt)", "b_upd_tool": "📥 Update this tool (send file)",
        "upd_sw_confirm": "Update strongSwan packages via apt now? The service will restart.",
        "b_go": "✅ Go",
        "upd_sw_running": "⏳ Updating strongSwan… this can take a few minutes.",
        "upgraded": "✅ Tool updated to version <b>{ver}</b>.",
        "upgrade_failed": "❌ Update failed and the previous version was restored.\n<code>{log}</code>",
        "notify_menu": "🔔 <b>Alerts</b>\nTap to toggle.",
        "n_service": "VPN service down/up", "n_cert": "Certificate expiry", "n_conn": "Client connect/disconnect",
        "lang_set": "🌐 Language: English",
        "a_down": "🚨 The VPN service stopped!", "a_up": "✅ The VPN service is running again.",
        "a_cert": "⚠️ The server certificate expires in {d} days. Run: vpn cert renew",
        "a_join": "🟢 <b>{user}</b> connected ({ip})", "a_leave": "⚪️ <b>{user}</b> disconnected",
        "err": "❌ Error:\n<code>{err}</code>", "working": "⏳ Working…",
        "b_upd_tool": "📥 Update this tool (GitHub)",
        "b_do_update": "✅ Update now",
        "upgrading": "⏳ Updating the tool… I will message you when it is done.",
        "upd_checking": "⏳ Checking GitHub for a new version…",
        "upd_uptodate": "✅ The tool is up to date (version {ver}).",
        "upd_available": "🆕 New version available.\nInstalled: {cur}\nLatest: {new}\nUsers, certificates and settings are kept; a failed update rolls back automatically.",
        "upd_nosource": "❌ Could not check for updates.\n<code>{err}</code>",
        "a_update": "🆕 A new version of the tool is available: {cur} → {new}. Open Updates to install it.",
        "n_update": "New tool version available",
        "b_dns": "🧭 DNS",
        "dns_menu": "🧭 <b>DNS servers</b>\nCurrent: <code>{dns}</code>\nPick a provider (clients must reconnect):",
        "dns_set": "✅ DNS changed to <code>{dns}</code>. Reconnect clients to apply.",
        "dns_cloudflare": "Cloudflare",
        "dns_google": "Google",
        "dns_quad9": "Quad9",
        "dns_adguard": "AdGuard (blocks ads)",
        "dns_cloudflare-family": "Cloudflare Family",
        "dns_opendns": "OpenDNS",
    },
    "fa": {
        "menu": "🛡 <b>مدیریت VPN (IKEv2)</b>\nنسخه {ver}\nسرور: <code>{server}</code>",
        "b_users": "👥 کاربران", "b_add": "➕ افزودن کاربر", "b_status": "📡 وضعیت",
        "b_online": "🟢 آنلاین‌ها", "b_info": "ℹ️ اطلاعات سرور", "b_restart": "🔁 ری‌استارت VPN",
        "b_backup": "📦 بکاپ", "b_update": "⬆️ آپدیت", "b_lang": "🌐 English",
        "b_notify": "🔔 اعلان‌ها", "b_back": "⬅️ بازگشت", "b_menu": "🏠 منو",
        "users_title": "👥 <b>کاربران</b> ({n})\nبرای مدیریت روی یک کاربر بزنید.",
        "no_users": "هنوز کاربری وجود ندارد.",
        "ask_name": "نام کاربری جدید را بفرستید (حروف انگلیسی، عدد و _ . - حداکثر ۳۲ کاراکتر).",
        "bad_name": "❌ نام کاربری نامعتبر است. فقط حروف انگلیسی، عدد و _ . - مجاز است.",
        "exists": "❌ این کاربر از قبل وجود دارد.",
        "created": "✅ کاربر <b>{user}</b> ساخته شد.",
        "conn_info": "🔑 <b>اطلاعات اتصال</b>\nآدرس سرور: <code>{server}</code>\nنام کاربری: <code>{user}</code>\nرمز عبور: <code>{pw}</code>",
        "sending_files": "📎 در حال ارسال فایل‌های پروفایل…",
        "cap_sswan": "اندروید: اپ strongSwan ← Import VPN profile (رمز را وارد کنید).",
        "cap_mobile": "آیفون/آیپد/مک: این پروفایل را باز و نصب کنید.",
        "cap_win": "ویندوز: در PowerShell با دسترسی Administrator اجرا کنید.",
        "cap_ca": "گواهی CA (فقط برای تنظیم دستی لازم است).",
        "cap_readme": "راهنمای نصب.",
        "cap_zed": "ZedSecure: لینک‌های import (از این فایل یا از پیام بالا کپی کنید).",
        "zed_link": "🔗 <b>ZedSecure</b> — این لینک را کپی کنید و در اپ از کلیپ‌بورد import کنید:\n<code>{link}</code>",
        "user_view": "👤 <b>{user}</b>\nوضعیت: {state}\nآنلاین: {online}",
        "st_on": "فعال ✅", "st_off": "غیرفعال ⛔", "yes": "بله", "no": "خیر",
        "b_profiles": "📲 دریافت پروفایل‌ها", "b_disable": "⛔ غیرفعال‌سازی", "b_enable": "✅ فعال‌سازی",
        "b_passwd": "🔑 تغییر رمز", "b_delete": "🗑 حذف",
        "confirm_del": "❓ کاربر <b>{user}</b> حذف شود؟ این کار قابل بازگشت نیست.",
        "b_yes_del": "✅ بله، حذف کن", "b_cancel": "❌ انصراف",
        "deleted": "🗑 کاربر <b>{user}</b> حذف شد.",
        "status_set": "✅ کاربر <b>{user}</b> اکنون {state} است.",
        "ask_pw": "رمز جدید را بفرستید (۸ تا ۶۴ کاراکتر: حروف انگلیسی، عدد و . _ @ + = , ! % ^ * ~ -) یا بنویسید <code>auto</code> تا رمز تصادفی ساخته شود.",
        "bad_pw": "❌ رمز نامعتبر است.",
        "pw_changed": "✅ رمز تغییر کرد.",
        "status": "📡 <b>وضعیت</b>\nسرویس VPN: {svc}\nکاربران: {users} (فعال {enabled})، آنلاین: {online}\nگواهی: {cert} روز تا انقضا\nstrongSwan: {sw}\nنسخه ابزار: {ver}\nفایروال: {fw}",
        "no_online": "الان کسی آنلاین نیست.",
        "online_title": "🟢 <b>آنلاین‌ها</b> ({n})",
        "info": "ℹ️ <b>اطلاعات سرور</b>\nآدرس: <code>{server}</code>\nحالت: {mode}\nرنج IP کاربران: {pool}\nDNS: {dns}\nپورت‌ها: UDP 500 و UDP 4500",
        "restarting": "⏳ در حال ری‌استارت…", "restarted": "✅ سرویس VPN ری‌استارت شد. وضعیت: {svc}",
        "backup_menu": "📦 <b>بکاپ</b>\nآخرین بکاپ: {last}",
        "b_make_backup": "🆕 ساخت بکاپ جدید", "b_send_backup": "📤 ارسال آخرین بکاپ به من",
        "backup_done": "✅ بکاپ ساخته شد:\n<code>{path}</code>", "backup_fail": "❌ ساخت بکاپ ناموفق بود.\n{err}",
        "no_backup": "هنوز بکاپی وجود ندارد.", "none": "ندارد",
        "backup_warn": "⚠️ فایل بکاپ شامل کلیدهای خصوصی و رمز همه کاربران است. فقط اگر مطمئن هستید ارسال کنید.",
        "b_send_ok": "✅ بله، ارسال کن",
        "update_menu": "⬆️ <b>آپدیت</b>\nنسخه ابزار: {ver}\nstrongSwan: {sw}",
        "b_upd_sw": "🔄 آپدیت strongSwan (apt)", "b_upd_tool": "📥 آپدیت ابزار (ارسال فایل)",
        "upd_sw_confirm": "پکیج‌های strongSwan الان با apt آپدیت شوند؟ سرویس ری‌استارت می‌شود.",
        "b_go": "✅ انجام بده",
        "upd_sw_running": "⏳ در حال آپدیت strongSwan… ممکن است چند دقیقه طول بکشد.",
        "upgraded": "✅ ابزار به نسخه <b>{ver}</b> آپدیت شد.",
        "upgrade_failed": "❌ آپدیت ناموفق بود و نسخه قبلی برگردانده شد.\n<code>{log}</code>",
        "notify_menu": "🔔 <b>اعلان‌ها</b>\nبرای روشن/خاموش کردن بزنید.",
        "n_service": "قطع/وصل شدن سرویس VPN", "n_cert": "نزدیک شدن انقضای گواهی", "n_conn": "اتصال/قطع کاربران",
        "lang_set": "🌐 زبان: فارسی",
        "a_down": "🚨 سرویس VPN از کار افتاد!", "a_up": "✅ سرویس VPN دوباره فعال شد.",
        "a_cert": "⚠️ گواهی سرور {d} روز دیگر منقضی می‌شود. دستور: vpn cert renew",
        "a_join": "🟢 <b>{user}</b> وصل شد ({ip})", "a_leave": "⚪️ <b>{user}</b> قطع شد",
        "err": "❌ خطا:\n<code>{err}</code>", "working": "⏳ در حال انجام…",
        "b_upd_tool": "📥 آپدیت ابزار (از GitHub)",
        "b_do_update": "✅ آپدیت کن",
        "upgrading": "⏳ در حال آپدیت ابزار… بعد از اتمام پیام می‌دهم.",
        "upd_checking": "⏳ در حال بررسی نسخه جدید در GitHub…",
        "upd_uptodate": "✅ ابزار به‌روز است (نسخه {ver}).",
        "upd_available": "🆕 نسخه جدید موجود است.\nنسخه فعلی: {cur}\nنسخه جدید: {new}\nکاربران، گواهی‌ها و تنظیمات حفظ می‌شوند و اگر آپدیت خراب شود خودکار برمی‌گردد.",
        "upd_nosource": "❌ بررسی آپدیت ممکن نشد.\n<code>{err}</code>",
        "a_update": "🆕 نسخه جدید ابزار موجود است: {cur} ← {new}. از بخش آپدیت نصبش کنید.",
        "n_update": "نسخه جدید ابزار",
        "b_dns": "🧭 DNS",
        "dns_menu": "🧭 <b>سرورهای DNS</b>\nفعلی: <code>{dns}</code>\nیک ارائه‌دهنده انتخاب کنید (کاربران باید دوباره وصل شوند):",
        "dns_set": "✅ DNS به <code>{dns}</code> تغییر کرد. برای اعمال، کاربران دوباره وصل شوند.",
        "dns_cloudflare": "Cloudflare",
        "dns_google": "Google",
        "dns_quad9": "Quad9",
        "dns_adguard": "AdGuard (حذف تبلیغات)",
        "dns_cloudflare-family": "Cloudflare Family",
        "dns_opendns": "OpenDNS",
    },
}

# ----------------------------------------------------------------- config / state
def read_conf():
    cfg = {}
    try:
        with open(CONF, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"^([A-Z_][A-Z0-9_]*)='(.*)'\s*$", line.rstrip("\n"))
                if m:
                    cfg[m.group(1)] = m.group(2).replace("'\\''", "'")
    except FileNotFoundError:
        pass
    return cfg


_state_lock = threading.Lock()


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            st = json.load(f)
    except Exception:
        st = {}
    st.setdefault("lang", "fa")
    st.setdefault("notify", {})
    for k, default in (("service", True), ("cert", True), ("conn", False), ("update", True)):
        st["notify"].setdefault(k, default)
    return st


def save_state(st):
    with _state_lock:
        os.makedirs(VAR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f)
        os.replace(tmp, STATE_FILE)


def tr(key, **kw):
    lang = load_state()["lang"]
    s = T.get(lang, T["en"]).get(key) or T["en"][key]
    return s.format(**kw) if kw else s


def esc(x):
    return html.escape(str(x), quote=False)


# ----------------------------------------------------------------- vpn CLI
def vpn(*args, timeout=180):
    try:
        p = subprocess.run([VPN, *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def kv_status():
    rc, out = vpn("status", "--kv", timeout=60)
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def list_users():
    rc, out = vpn("user", "list", "--plain")
    users = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[0]:
                users.append((parts[0], parts[1]))
    return users


def latest_backup():
    try:
        files = [os.path.join(BACKUPS, f) for f in os.listdir(BACKUPS) if f.startswith("ikev2-backup-")]
        return max(files, key=os.path.getmtime) if files else None
    except Exception:
        return None


# ----------------------------------------------------------------- telegram API
class TG:
    def __init__(self, token):
        self.token = token
        self.base = f"https://api.telegram.org/bot{token}/"
        self.fbase = f"https://api.telegram.org/file/bot{token}/"

    def call(self, method, data=None, timeout=40):
        req = urllib.request.Request(
            self.base + method, data=json.dumps(data or {}).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            try:
                return json.load(e)
            except Exception:
                return {"ok": False, "description": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "description": str(e)}

    def send_document(self, chat_id, path, caption=None):
        boundary = uuid.uuid4().hex
        body = bytearray()

        def field(k, v):
            body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())

        field("chat_id", chat_id)
        if caption:
            field("caption", caption)
        with open(path, "rb") as f:
            content = f.read()
        body.extend((f'--{boundary}\r\nContent-Disposition: form-data; name="document"; '
                     f'filename="{os.path.basename(path)}"\r\n'
                     f'Content-Type: application/octet-stream\r\n\r\n').encode())
        body.extend(content)
        body.extend(f"\r\n--{boundary}--\r\n".encode())
        req = urllib.request.Request(
            self.base + "sendDocument", data=bytes(body),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "description": str(e)}

    def download(self, file_id, dest):
        r = self.call("getFile", {"file_id": file_id})
        if not r.get("ok"):
            return False
        url = self.fbase + r["result"]["file_path"]
        try:
            with urllib.request.urlopen(url, timeout=120) as resp, open(dest, "wb") as out:
                shutil.copyfileobj(resp, out)
            return True
        except Exception:
            return False


tg = None
ADMIN = 0
awaiting = {}  # chat_id -> dict(kind=..., user=...)


def kb(rows):
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]}


def send(text, markup=None):
    data = {"chat_id": ADMIN, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if markup:
        data["reply_markup"] = markup
    return tg.call("sendMessage", data)


def edit(msg, text, markup=None):
    if not msg:
        return send(text, markup)
    data = {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"], "text": text,
            "parse_mode": "HTML", "disable_web_page_preview": True}
    if markup:
        data["reply_markup"] = markup
    r = tg.call("editMessageText", data)
    if not r.get("ok") and "not modified" not in str(r.get("description", "")):
        return send(text, markup)
    return r


# ----------------------------------------------------------------- screens
def main_menu_markup():
    return kb([
        [(tr("b_users"), "u:l"), (tr("b_add"), "a:add")],
        [(tr("b_status"), "s:st"), (tr("b_online"), "s:on")],
        [(tr("b_info"), "s:info"), (tr("b_restart"), "s:rs")],
        [(tr("b_backup"), "b:m"), (tr("b_update"), "up:m")],
        [(tr("b_dns"), "d:m"), (tr("b_notify"), "n:m")],
        [(tr("b_lang"), "l:t")],
    ])


def show_main(msg=None):
    kv = kv_status()
    edit(msg, tr("menu", ver=esc(kv.get("version", "?")), server=esc(kv.get("server", "?"))), main_menu_markup())


def back_row():
    return [(tr("b_menu"), "m:main")]


def show_users(msg=None):
    users = list_users()
    if not users:
        edit(msg, tr("no_users"), kb([back_row()]))
        return
    rows, row = [], []
    for name, st in users[:80]:
        row.append((("✅ " if st == "enabled" else "⛔ ") + name, f"u:v:{name}"))
        if len(row) == 2:
            rows.append(row); row = []
    if row:
        rows.append(row)
    rows.append(back_row())
    edit(msg, tr("users_title", n=len(users)), kb(rows))


def show_user(msg, name):
    users = dict(list_users())
    if name not in users:
        show_users(msg); return
    enabled = users[name] == "enabled"
    sas = [s for s in L.online() if s["user"] == name]
    online = tr("yes") + f" ({len(sas)})" if sas else tr("no")
    text = tr("user_view", user=esc(name), state=tr("st_on" if enabled else "st_off"), online=online)
    rows = [
        [(tr("b_profiles"), f"u:p:{name}")],
        [(tr("b_disable") if enabled else tr("b_enable"), f"u:t:{name}"), (tr("b_passwd"), f"u:w:{name}")],
        [(tr("b_delete"), f"u:d:{name}")],
        [(tr("b_back"), "u:l")],
    ]
    edit(msg, text, kb(rows))


def send_profiles(name, with_info=True):
    kv = kv_status()
    rc, pw = vpn("user", "show", name)
    password = ""
    for line in pw.splitlines():
        if line.startswith("Password:"):
            password = line.split(":", 1)[1].strip()
    tmp = tempfile.mkdtemp(prefix="ikev2-prof-")
    try:
        rc, out = vpn("profile", name, tmp)
        if rc != 0:
            send(tr("err", err=esc(out[-800:]))); return
        if with_info:
            send(tr("conn_info", server=esc(kv.get("server", "")), user=esc(name), pw=esc(password)))
        rcz, zl = vpn("zed", name)
        if rcz == 0 and zl.startswith("zedsecure://"):
            send(tr("zed_link", link=esc(zl)))
        send(tr("sending_files"))
        caps = {
            f"{name}.sswan": "cap_sswan", f"{name}.mobileconfig": "cap_mobile",
            f"{name}-windows.ps1": "cap_win", f"zedsecure-{name}.txt": "cap_zed", "ca.crt": "cap_ca",
            f"README-{name}.txt": "cap_readme",
        }
        for fname, key in caps.items():
            path = os.path.join(tmp, fname)
            if os.path.exists(path):
                tg.send_document(ADMIN, path, tr(key))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    send(tr("menu", ver=esc(kv.get("version", "?")), server=esc(kv.get("server", "?"))), main_menu_markup())


def do_create_user(name):
    rc, out = vpn("user", "add", name, "--plain")
    if rc != 0:
        send(tr("err", err=esc(out[-800:]))); return
    send(tr("created", user=esc(name)))
    send_profiles(name)


def show_status(msg):
    kv = kv_status()
    svc = kv.get("service", "?")
    edit(msg, tr("status", svc=("✅ " if svc == "active" else "🚨 ") + esc(svc), users=kv.get("users", "?"),
                 enabled=kv.get("enabled", "?"), online=kv.get("online", "?"), cert=kv.get("cert_days", "?"),
                 sw=esc(kv.get("sw_version", "?")), ver=esc(kv.get("version", "?")), fw=esc(kv.get("firewall", "?"))),
         kb([[(tr("b_status"), "s:st")], back_row()]))


def show_online(msg):
    sas = L.online()
    if not sas:
        edit(msg, tr("no_online"), kb([[(tr("b_online"), "s:on")], back_row()])); return
    lines = [tr("online_title", n=len(sas))]
    for s in sas:
        lines.append(f"• <b>{esc(s['user'])}</b> — {esc(s['ip'])} — {L.fmt_dur(s['secs'])} — "
                     f"⬇️{L.fmt_bytes(s['rx'])} ⬆️{L.fmt_bytes(s['tx'])}")
    edit(msg, "\n".join(lines), kb([[(tr("b_online"), "s:on")], back_row()]))


def show_info(msg):
    kv = kv_status()
    edit(msg, tr("info", server=esc(kv.get("server", "?")), mode=esc(kv.get("mode", "?")),
                 pool=esc(kv.get("pool", "?")), dns=esc(kv.get("dns", "?"))), kb([back_row()]))


def show_backup(msg):
    last = latest_backup()
    edit(msg, tr("backup_menu", last=esc(os.path.basename(last)) if last else tr("none")),
         kb([[(tr("b_make_backup"), "b:make")], [(tr("b_send_backup"), "b:send")], back_row()]))


def show_update(msg):
    kv = kv_status()
    edit(msg, tr("update_menu", ver=esc(kv.get("version", "?")), sw=esc(kv.get("sw_version", "?"))),
         kb([[(tr("b_upd_sw"), "up:sw")], [(tr("b_upd_tool"), "up:tool")], back_row()]))


def show_notify(msg):
    st = load_state()["notify"]
    mark = lambda v: "✅" if v else "⬜"  # noqa: E731
    edit(msg, tr("notify_menu"), kb([
        [(f"{mark(st['service'])} {tr('n_service')}", "n:t:service")],
        [(f"{mark(st['cert'])} {tr('n_cert')}", "n:t:cert")],
        [(f"{mark(st['conn'])} {tr('n_conn')}", "n:t:conn")],
        [(f"{mark(st['update'])} {tr('n_update')}", "n:t:update")],
        back_row(),
    ]))


# ----------------------------------------------------------------- long-running jobs
def job_strongswan():
    send(tr("upd_sw_running"))
    rc, out = vpn("upgrade-strongswan", timeout=1800)
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    send(("✅ " if rc == 0 else "❌ ") + f"<code>{esc(out[-1500:])}</code>", kb([back_row()]))


def job_backup():
    send(tr("working"))
    rc, out = vpn("backup")
    m = re.search(r"(/\S+\.tar\.gz)", out)
    if rc == 0 and m:
        send(tr("backup_done", path=esc(m.group(1))), kb([back_row()]))
    else:
        send(tr("backup_fail", err=esc(out[-600:])), kb([back_row()]))


def start_tool_upgrade():
    unit = f"ikev2-upgrade-{int(time.time())}"
    cmd = [VPN, "update", "--yes", "--notify"]
    try:
        subprocess.Popen(["systemd-run", f"--unit={unit}", "--collect", "--no-block", *cmd],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def job_check_update(msg):
    edit(msg, tr("upd_checking"))
    rc, out = vpn("update", "--check", timeout=60)
    kv = dict(l.split("=", 1) for l in out.splitlines() if re.match(r"^(installed|latest)=", l))
    if rc != 0 or "latest" not in kv:
        edit(msg, tr("upd_nosource", err=esc(re.sub(r"\x1b\[[0-9;]*m", "", out)[-500:])), kb([[(tr("b_back"), "up:m")]]))
        return
    if kv["latest"] == kv.get("installed"):
        edit(msg, tr("upd_uptodate", ver=esc(kv["latest"])), kb([[(tr("b_back"), "up:m")]]))
        return
    edit(msg, tr("upd_available", cur=esc(kv.get("installed", "?")), new=esc(kv["latest"])),
         kb([[(tr("b_do_update"), "up:go"), (tr("b_cancel"), "up:m")]]))


def show_dns(msg):
    kv = kv_status()
    names = ["cloudflare", "google", "quad9", "adguard", "cloudflare-family", "opendns"]
    rows, row = [], []
    for n in names:
        row.append((tr("dns_" + n), f"d:s:{n}"))
        if len(row) == 2:
            rows.append(row); row = []
    if row:
        rows.append(row)
    rows.append(back_row())
    edit(msg, tr("dns_menu", dns=esc(kv.get("dns", "?"))), kb(rows))


# ----------------------------------------------------------------- update dispatch
def on_message(msg):
    text = (msg.get("text") or "").strip()
    if text.startswith("/start") or text.startswith("/menu"):
        awaiting.pop(ADMIN, None)
        show_main(None); return
    aw = awaiting.get(ADMIN)
    if not aw:
        show_main(None); return
    if aw["kind"] == "add":
        awaiting.pop(ADMIN, None)
        if not NAME_RE.match(text):
            send(tr("bad_name"), kb([back_row()])); return
        if text in dict(list_users()):
            send(tr("exists"), kb([back_row()])); return
        do_create_user(text)
    elif aw["kind"] == "passwd":
        name = aw["user"]
        if text.lower() != "auto" and not PASS_RE.match(text):
            send(tr("bad_pw")); return
        awaiting.pop(ADMIN, None)
        rc, out = vpn("user", "passwd", name, text if text.lower() != "auto" else "auto", "--plain")
        if rc != 0:
            send(tr("err", err=esc(out[-800:]))); return
        send(tr("pw_changed"))
        send_profiles(name)


def on_callback(cq):
    msg = cq.get("message")
    data = cq.get("data", "")
    tg.call("answerCallbackQuery", {"callback_query_id": cq["id"]})
    parts = data.split(":", 2)
    k = parts[0]
    awaiting.pop(ADMIN, None) if k != "a" else None
    if data == "m:main":
        show_main(msg)
    elif data == "u:l":
        show_users(msg)
    elif k == "u" and parts[1] == "v":
        show_user(msg, parts[2])
    elif k == "u" and parts[1] == "p":
        threading.Thread(target=send_profiles, args=(parts[2],), daemon=True).start()
    elif k == "u" and parts[1] == "t":
        name = parts[2]
        cur = dict(list_users()).get(name)
        new = "disable" if cur == "enabled" else "enable"
        rc, out = vpn("user", new, name)
        if rc != 0:
            send(tr("err", err=esc(out[-800:])))
        show_user(msg, name)
    elif k == "u" and parts[1] == "w":
        awaiting[ADMIN] = {"kind": "passwd", "user": parts[2]}
        edit(msg, tr("ask_pw"), kb([[(tr("b_cancel"), f"u:v:{parts[2]}")]]))
    elif k == "u" and parts[1] == "d":
        edit(msg, tr("confirm_del", user=esc(parts[2])),
             kb([[(tr("b_yes_del"), f"u:x:{parts[2]}"), (tr("b_cancel"), f"u:v:{parts[2]}")]]))
    elif k == "u" and parts[1] == "x":
        rc, out = vpn("user", "del", parts[2])
        if rc == 0:
            edit(msg, tr("deleted", user=esc(parts[2])), kb([[(tr("b_users"), "u:l")], back_row()]))
        else:
            send(tr("err", err=esc(out[-800:])))
    elif data == "a:add":
        awaiting[ADMIN] = {"kind": "add"}
        edit(msg, tr("ask_name"), kb([back_row()]))
    elif data == "s:st":
        show_status(msg)
    elif data == "s:on":
        show_online(msg)
    elif data == "s:info":
        show_info(msg)
    elif data == "s:rs":
        edit(msg, tr("restarting"))
        rc, out = vpn("restart", timeout=120)
        svc = kv_status().get("service", "?")
        edit(msg, tr("restarted", svc=esc(svc)), kb([back_row()]))
    elif data == "b:m":
        show_backup(msg)
    elif data == "b:make":
        threading.Thread(target=job_backup, daemon=True).start()
    elif data == "b:send":
        if latest_backup():
            edit(msg, tr("backup_warn"), kb([[(tr("b_send_ok"), "b:sendok"), (tr("b_cancel"), "b:m")]]))
        else:
            edit(msg, tr("no_backup"), kb([back_row()]))
    elif data == "b:sendok":
        p = latest_backup()
        if p:
            tg.send_document(ADMIN, p, os.path.basename(p))
    elif data == "up:m":
        show_update(msg)
    elif data == "up:sw":
        edit(msg, tr("upd_sw_confirm"), kb([[(tr("b_go"), "up:swgo"), (tr("b_cancel"), "up:m")]]))
    elif data == "up:swgo":
        threading.Thread(target=job_strongswan, daemon=True).start()
    elif data == "up:tool":
        threading.Thread(target=job_check_update, args=(msg,), daemon=True).start()
    elif data == "up:go":
        edit(msg, tr("upgrading"))
        start_tool_upgrade()
    elif data == "d:m":
        show_dns(msg)
    elif k == "d" and parts[1] == "s":
        rc, out = vpn("preset", "dns", parts[2], timeout=120)
        kv = kv_status()
        if rc == 0:
            edit(msg, tr("dns_set", dns=esc(kv.get("dns", "?"))), kb([[(tr("b_dns"), "d:m")], back_row()]))
        else:
            send(tr("err", err=esc(re.sub(r"\x1b\[[0-9;]*m", "", out)[-600:])))
    elif data == "n:m":
        show_notify(msg)
    elif k == "n" and parts[1] == "t":
        st = load_state()
        st["notify"][parts[2]] = not st["notify"].get(parts[2], False)
        save_state(st)
        show_notify(msg)
    elif data == "l:t":
        st = load_state()
        st["lang"] = "en" if st["lang"] == "fa" else "fa"
        save_state(st)
        show_main(msg)


def handle(update):
    if "callback_query" in update:
        cq = update["callback_query"]
        m = cq.get("message") or {}
        if cq.get("from", {}).get("id") != ADMIN or m.get("chat", {}).get("type") != "private":
            return
        on_callback(cq)
    elif "message" in update:
        m = update["message"]
        if m.get("from", {}).get("id") != ADMIN or m.get("chat", {}).get("type") != "private":
            return
        on_message(m)


# ----------------------------------------------------------------- monitor thread
def service_name():
    for u in ("strongswan-swanctl", "strongswan"):
        try:
            p = subprocess.run(["systemctl", "cat", f"{u}.service"], capture_output=True, text=True)
            if p.returncode == 0 and "charon-systemd" in p.stdout:
                return u
        except Exception:
            pass
    return "strongswan"


def service_active(name):
    p = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
    return p.stdout.strip() == "active"


def monitor():
    svc = service_name()
    last_active = None
    last_sessions = None
    last_cert = 0
    last_warn_day = ""
    last_upd = 0
    last_upd_ver = ""
    while True:
        time.sleep(30)
        try:
            st = load_state()
            active = service_active(svc)
            if last_active is not None and active != last_active and st["notify"]["service"]:
                send(tr("a_up" if active else "a_down"))
            last_active = active

            if active and st["notify"]["conn"]:
                cur = {(s["user"], s["id"]): s for s in L.online()}
                if last_sessions is not None:
                    for key, s in cur.items():
                        if key not in last_sessions:
                            send(tr("a_join", user=esc(s["user"]), ip=esc(s["ip"])))
                    for key, s in last_sessions.items():
                        if key not in cur:
                            send(tr("a_leave", user=esc(s["user"])))
                last_sessions = cur
            else:
                last_sessions = None

            if st["notify"]["cert"] and time.time() - last_cert > 12 * 3600:
                last_cert = time.time()
                days = int(kv_status().get("cert_days", "999") or 999)
                today = time.strftime("%Y-%m-%d")
                if 0 <= days <= 14 and last_warn_day != today:
                    last_warn_day = today
                    send(tr("a_cert", d=days))

            if st["notify"]["update"] and time.time() - last_upd > 24 * 3600:
                last_upd = time.time()
                rc, out = vpn("update", "--check", timeout=60)
                kv = dict(l.split("=", 1) for l in out.splitlines() if re.match(r"^(installed|latest)=", l))
                if rc == 0 and kv.get("latest") and kv["latest"] != kv.get("installed") and kv["latest"] != last_upd_ver:
                    last_upd_ver = kv["latest"]
                    send(tr("a_update", cur=esc(kv.get("installed", "?")), new=esc(kv["latest"])))
        except Exception:
            traceback.print_exc()


def notify_upgrade_result():
    path = f"{VAR}/upgrade_result"
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            res = json.load(f)
        os.remove(path)
        if res.get("ok"):
            send(tr("upgraded", ver=esc(res.get("version", "?"))), main_menu_markup())
        else:
            send(tr("upgrade_failed", log=esc(res.get("log", "")[-1200:])), main_menu_markup())
    except Exception:
        traceback.print_exc()


# ----------------------------------------------------------------- main
def main():
    global tg, ADMIN
    cfg = read_conf()
    token = cfg.get("BOT_TOKEN", "")
    try:
        ADMIN = int(cfg.get("ADMIN_ID", "0"))
    except ValueError:
        ADMIN = 0
    if not token or not ADMIN:
        print("Bot is not configured (BOT_TOKEN / ADMIN_ID missing).", file=sys.stderr)
        sys.exit(2)
    tg = TG(token)
    me = tg.call("getMe")
    print("Bot started:", me.get("result", {}).get("username", "?"), flush=True)
    threading.Thread(target=monitor, daemon=True).start()
    notify_upgrade_result()
    offset = 0
    while True:
        r = tg.call("getUpdates", {"offset": offset, "timeout": 30,
                                   "allowed_updates": ["message", "callback_query"]}, timeout=45)
        if not r.get("ok"):
            time.sleep(5)
            continue
        for u in r.get("result", []):
            offset = u["update_id"] + 1
            try:
                handle(u)
            except Exception:
                traceback.print_exc()


if __name__ == "__main__":
    main()
