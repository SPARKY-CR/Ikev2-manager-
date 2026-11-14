#!/usr/bin/env python3
"""ikev2-manager Telegram bot - admin only, Persian/English, stdlib only. Messages are sent as Telegram MarkdownV2."""
import html
import http.client
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
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ikev2lib as L  # noqa: E402

ETC = os.environ.get("IKEV2_ETC", "/etc/ikev2")
VAR = os.environ.get("IKEV2_VAR", "/var/lib/ikev2")
BACKUPS = os.environ.get("IKEV2_BACKUPS", "/var/backups/ikev2")
VPN = os.environ.get("IKEV2_VPN", "/usr/local/bin/vpn")
CONF = f"{ETC}/config.env"
STATE_FILE = f"{VAR}/bot_state.json"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
PASS_RE = re.compile(r"^[A-Za-z0-9._@+=,!%^*~-]{12,64}$")
WIPE_MINUTES = 30   # credentials sent to the chat are deleted again after this long (toggle in Alerts)

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
        "ask_pw": "Send the new password (12-64 chars: letters, digits, . _ @ + = , ! % ^ * ~ -) or send <code>auto</code> for a random one. Your message is deleted right after I read it.",
        "bad_pw": "❌ Invalid password.",
        "pw_changed": "✅ Password changed.",
        "status": "📡 <b>Status</b>\nVPN service: {svc}\nUsers: {users} (enabled {enabled}), online: {online}\nCertificate: {cert}\nstrongSwan: {sw}\nTool version: {ver}\nFirewall: {fw}",
        "cert_ok": "{d} days left", "cert_expired": "🚨 EXPIRED {d} day(s) ago", "cert_missing": "🚨 missing",
        "no_online": "Nobody is online right now.",
        "online_title": "🟢 <b>Online now</b> ({n})",
        "info": "ℹ️ <b>Server info</b>\nAddress: <code>{server}</code>\nMode: {mode}\nVPN pool: {pool}\nDNS: {dns}\nPorts: UDP 500, UDP 4500",
        "restarting": "⏳ Restarting…", "restarted": "✅ VPN service restarted. State: {svc}",
        "backup_menu": "📦 <b>Backup</b>\nLatest: {last}\nEncryption: {enc}",
        "enc_on": "🔐 on", "enc_off": "off (set up: sudo vpn backup key init)",
        "b_make_backup": "🆕 Create backup", "b_send_backup": "📤 Send an ENCRYPTED backup to me",
        "backup_done": "✅ Backup created:\n<code>{path}</code>", "backup_fail": "❌ Backup failed.\n{err}",
        "no_backup": "No backup exists yet.", "none": "none",
        "backup_nokey": "⚠️ A backup contains private keys and every user's password, so the bot only ever sends ENCRYPTED backups. On the server run <code>sudo vpn backup key init</code> (the private key is shown once - keep it safe) or <code>sudo vpn backup key set cert.pem</code>.",
        "cap_backup": "Encrypted backup. Open it on your computer with your private key:\nopenssl cms -decrypt -binary -inform DER -in FILE -inkey backup.key -out backup.tar.gz",
        "wipe_note": "🧹 These credentials will be deleted from this chat in {m} minutes - save them now.",
        "n_wipe": "Auto-delete credentials from this chat ({m} min)",
        "a_cert_expired": "🚨 The server certificate has EXPIRED. Run: vpn cert renew",
        "a_cert_missing": "🚨 The server certificate is missing. Run: vpn cert renew",
        "update_menu": "⬆️ <b>Updates</b>\nTool version: {ver}\nstrongSwan: {sw}",
        "b_upd_sw": "🔄 Update strongSwan (apt)",
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
        "ask_pw": "رمز جدید را بفرستید (۱۲ تا ۶۴ کاراکتر: حروف انگلیسی، عدد و . _ @ + = , ! % ^ * ~ -) یا بنویسید <code>auto</code> تا رمز تصادفی ساخته شود. پیام شما بلافاصله بعد از خواندن حذف می‌شود.",
        "bad_pw": "❌ رمز نامعتبر است.",
        "pw_changed": "✅ رمز تغییر کرد.",
        "status": "📡 <b>وضعیت</b>\nسرویس VPN: {svc}\nکاربران: {users} (فعال {enabled})، آنلاین: {online}\nگواهی: {cert}\nstrongSwan: {sw}\nنسخه ابزار: {ver}\nفایروال: {fw}",
        "cert_ok": "{d} روز تا انقضا", "cert_expired": "🚨 {d} روز است منقضی شده", "cert_missing": "🚨 وجود ندارد",
        "no_online": "الان کسی آنلاین نیست.",
        "online_title": "🟢 <b>آنلاین‌ها</b> ({n})",
        "info": "ℹ️ <b>اطلاعات سرور</b>\nآدرس: <code>{server}</code>\nحالت: {mode}\nرنج IP کاربران: {pool}\nDNS: {dns}\nپورت‌ها: UDP 500 و UDP 4500",
        "restarting": "⏳ در حال ری‌استارت…", "restarted": "✅ سرویس VPN ری‌استارت شد. وضعیت: {svc}",
        "backup_menu": "📦 <b>بکاپ</b>\nآخرین بکاپ: {last}\nرمزنگاری: {enc}",
        "enc_on": "🔐 فعال", "enc_off": "غیرفعال (فعال‌سازی: sudo vpn backup key init)",
        "b_make_backup": "🆕 ساخت بکاپ جدید", "b_send_backup": "📤 ارسال بکاپ رمزنگاری‌شده به من",
        "backup_done": "✅ بکاپ ساخته شد:\n<code>{path}</code>", "backup_fail": "❌ ساخت بکاپ ناموفق بود.\n{err}",
        "no_backup": "هنوز بکاپی وجود ندارد.", "none": "ندارد",
        "backup_nokey": "⚠️ بکاپ شامل کلیدهای خصوصی و رمز همه‌ی کاربران است؛ به همین دلیل بات فقط بکاپ <b>رمزنگاری‌شده</b> می‌فرستد. روی سرور این دستور را بزنید: <code>sudo vpn backup key init</code> (کلید خصوصی فقط یک بار نمایش داده می‌شود؛ جای امن نگه دارید) یا <code>sudo vpn backup key set cert.pem</code>.",
        "cap_backup": "بکاپ رمزنگاری‌شده. روی کامپیوتر خودتان با کلید خصوصی باز کنید:\nopenssl cms -decrypt -binary -inform DER -in FILE -inkey backup.key -out backup.tar.gz",
        "wipe_note": "🧹 این اطلاعات ورود تا {m} دقیقه‌ی دیگر از این چت پاک می‌شود؛ همین حالا ذخیره‌شان کنید.",
        "n_wipe": "حذف خودکار اطلاعات ورود از چت ({m} دقیقه)",
        "a_cert_expired": "🚨 گواهی سرور منقضی شده است! دستور: vpn cert renew",
        "a_cert_missing": "🚨 گواهی سرور پیدا نشد! دستور: vpn cert renew",
        "update_menu": "⬆️ <b>آپدیت</b>\nنسخه ابزار: {ver}\nstrongSwan: {sw}",
        "b_upd_sw": "🔄 آپدیت strongSwan (apt)",
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

# Texts of the features added in 1.4.0 (English). tr() falls back to this table when a key is not in T[lang].
TX = {
    # main menu
    "b_quota": "📊 Traffic & expiry", "b_server": "🖥 Server", "b_settings": "⚙️ Settings", "b_security": "🔒 Security",
    "b_kick": "🔌 Disconnect", "b_refresh": "🔄 Refresh", "b_logs": "📜 Logs", "b_cert": "🔐 Certificate",
    "b_address": "🌍 Address / domain", "b_selftest": "🩺 Self-test", "b_raw": "🧩 Raw snippets",
    "b_conf": "📄 Show config", "b_apply": "♻️ Re-apply config", "b_resetall": "↩️ Reset all settings",
    "b_ike": "🔑 IKE preset", "b_default": "↩️ Default", "b_enter": "✏️ Enter a value", "b_clear": "🧹 Clear",
    "b_restore": "♻️ Restore", "b_listbak": "📋 Backups", "n_quota": "Traffic / expiry warnings",
    # quota
    "q_title": "📊 <b>Traffic &amp; expiry</b>\nUsers: {n}   Total used: {total}\n{lines}",
    "q_empty": "No users yet.",
    "q_line": "• <b>{user}</b> {bar} {pct}%  {used} / {limit}\n   ⏳ {expires}{flag}",
    "q_line_nolimit": "• <b>{user}</b> {used} (no limit)\n   ⏳ {expires}{flag}",
    "q_user": "{note}👤 <b>{user}</b>  {state}\n{block}",
    "q_block": "📦 Traffic: {traffic}\n⏳ Expires: {expires}\n🎯 When over: {action}{blocked}",
    "q_blocked": "  (blocked: {why})",
    "q_ask_limit": "Send the traffic limit for <b>{user}</b>: for example <code>10G</code>, <code>500M</code>, <code>1.5T</code> "
                   "or <code>unlimited</code> (a bare number means GB).",
    "q_ask_expiry": "Send the expiry for <b>{user}</b>: a number of days from now (<code>30</code>), a date "
                    "(<code>2026-12-31</code>) or <code>never</code>.",
    "q_g": "➕ {v} GB", "q_y": "➕ {v} days", "q_unl": "♾ No traffic limit", "q_never": "♾ Never expires",
    "q_setlimit": "✏️ Set limit", "q_setexp": "📅 Set expiry", "q_action": "🎯 When over: {a}", "q_reset": "🔄 Reset usage",
    "q_done": "✅ {text}\n\n", "q_fail": "❌ {text}\n\n",
    "q_help_action": "disable = block the user, delete = remove the user, notify = only warn you",
    # alerts from the quota check
    "ev_warn_limit": "⚠️ <b>{user}</b> has used {pct}% of the traffic limit ({used} / {limit}).",
    "ev_warn_expiry": "⏰ <b>{user}</b> expires soon: {expires}.",
    "ev_limit_disable": "⛔ <b>{user}</b> reached the traffic limit ({used} / {limit}) and was <b>disabled</b>.",
    "ev_limit_delete": "🗑 <b>{user}</b> reached the traffic limit ({used} / {limit}) and was <b>deleted</b>.",
    "ev_limit_notify": "🚨 <b>{user}</b> reached the traffic limit ({used} / {limit}). The user is still active (notify only).",
    "ev_expired_disable": "⛔ <b>{user}</b> has expired and was <b>disabled</b>.",
    "ev_expired_delete": "🗑 <b>{user}</b> has expired and was <b>deleted</b>.",
    "ev_expired_notify": "🚨 <b>{user}</b> has expired. The user is still active (notify only).",
    # add-user wizard
    "w_title": "➕ <b>New user</b> <code>{user}</code>\n📦 Traffic: <b>{limit}</b>\n📅 Valid for: <b>{days}</b>\n"
               "🎯 When over: <b>{action}</b>\n\nPick the values, then press Create.",
    "w_custom_limit": "Send the traffic limit, for example <code>10G</code>, <code>500M</code> or <code>unlimited</code>.",
    "w_custom_days": "Send the number of days (<code>30</code>), a date (<code>2026-12-31</code>) or <code>never</code>.",
    "w_create": "✅ Create", "w_custom": "✏️ Custom", "w_unl": "♾",
    "w_bad": "❌ {err}",
    "unlimited": "unlimited", "never": "never", "w_days_fmt": "{d} days", "default_action": "default ({a})",
    # kick
    "kicked": "🔌 Disconnected <b>{user}</b> ({n} session(s)).",
    # server
    "sv_menu": "🖥 <b>Server</b>\nService: {svc}\nMode: {mode}\nAddress: <code>{server}</code>\nCertificate: {cert}\nBot: {bot}",
    "sv_logs": "📜 <b>VPN service log</b> (last lines)\n{out}",
    "sv_botlogs": "📜 <b>Bot log</b> (last lines)\n{out}",
    "sv_cert": "🔐 <b>Certificate</b>\n{out}",
    "b_renew": "🔄 Renew now", "b_renew_force": "⚡ Force renew",
    "sv_addr": "🌍 <b>Address</b>\nMode: <b>{mode}</b>\nServer address: <code>{server}</code>\n\n"
               "Changing the address means every client must import a new profile.",
    "b_setdomain": "🌐 Use a domain", "b_ipmode": "📍 Switch to IP mode", "b_refreship": "🔄 Refresh public IP",
    "sv_ask_domain": "Send the domain, optionally followed by an email for Let's Encrypt, for example:\n"
                     "<code>vpn.example.com me@example.com</code>\nIts DNS A record must already point to this server and TCP 80 must be free.",
    "sv_domain_confirm": "Switch to domain mode with <b>{domain}</b>? Clients must import new profiles.",
    "sv_ip_confirm": "Switch back to IP mode? Clients must import new profiles and trust the CA again.",
    "sv_bad_domain": "❌ That does not look like a domain.",
    # security
    "se_menu": "🔒 <b>Security</b>\nFirewall: <b>{fw}</b>\nSSH ports kept open: {ports}\nFail2ban: {f2b}   Auto-updates: {au}\n\n"
               "Client isolation and private-network blocking are in Settings.",
    "b_fw_on": "🔥 Firewall ON", "b_fw_off": "🔥 Firewall OFF", "b_fw_status": "📋 Firewall rules", "b_fw_ports": "🔌 SSH ports",
    "b_f2b": "🛡 Install fail2ban", "b_autoupd": "♻️ Enable auto security updates",
    "se_fw_confirm": "Turn the firewall on? Only SSH ({ports}), UDP 500 and UDP 4500 stay open. If your SSH port is "
                     "different you will lock yourself out - check Firewall SSH ports first.",
    "se_ask_ports": "Send the SSH port(s) to keep open, separated by spaces, for example <code>22 2222</code>.",
    "se_f2b_confirm": "Install fail2ban for SSH now (apt)?", "se_au_confirm": "Enable unattended security updates now (apt)?",
    # settings
    "st_menu": "⚙️ <b>Settings</b>\nTap a setting to read what it does and change it.\n{lines}",
    "st_detail": "⚙️ <b>{key}</b>\n{out}",
    "st_ask": "Send the new value for <b>{key}</b>.\n{hint}",
    "st_set": "✅ <b>{key}</b> updated.\n{out}", "st_fail": "❌ <b>{key}</b> was not changed.\n{out}",
    "st_reset_confirm": "Reset ALL advanced settings to their defaults? (Users, certificates and raw snippets are kept.)",
    "st_conf": "📄 Current swanctl.conf (secrets hidden).", "st_applied": "✅ Configuration regenerated and applied.",
    "st_ike_done": "✅ IKE preset applied.\n{out}",
    # raw
    "rw_menu": "🧩 <b>Raw snippets</b>\nAdd any strongSwan option. Tap a section.\n{out}",
    "rw_view": "🧩 <b>{name}</b>\n{out}", "rw_ask": "Send the new content for <b>{name}</b> (it replaces the old one). Lines go into the section as written.",
    "rw_clear_confirm": "Clear the <b>{name}</b> snippet?", "rw_saved": "✅ <b>{name}</b> saved and applied.\n{out}",
    "rw_failed": "❌ Rejected, the previous content was restored.\n{out}",
    # backup extras
    "bk_list": "📋 <b>Backups on the server</b>\n{out}", "bk_pick": "♻️ Pick a PLAIN backup to restore. Encrypted backups need your private key, "
                "so restore them from SSH: <code>vpn restore FILE.enc --key KEY.pem</code>.",
    "bk_confirm": "Restore <b>{name}</b>? The current state is saved first (undo copy), then services restart.",
    "bk_none": "No plain backups on the server.", "bk_done": "✅ Restore finished.\n{out}", "bk_fail": "❌ Restore failed.\n{out}",
    # generic
    "op_running": "⏳ {label}…", "op_ok": "✅ {label}\n{out}", "op_fail": "❌ {label}\n{out}",
    "selftest": "🩺 <b>Self-test</b>\n{out}", "unknown": "?",
    # labels, expiry and action names
    "lb_cert_renew": "Renew certificate", "lb_cert_force": "Force renew certificate", "lb_domain": "Switch to domain {domain}",
    "lb_ipmode": "Switch to IP mode", "lb_ip_refresh": "Refresh public IP", "lb_selftest": "Self-test", "lb_fw_on": "Firewall on",
    "lb_fw_off": "Firewall off", "lb_fw_rules": "Firewall rules", "lb_f2b": "Install fail2ban", "lb_autoupd": "Auto security updates",
    "lb_ports": "SSH ports", "lb_reset": "Reset settings", "lb_apply": "Re-apply configuration", "lb_ike": "IKE preset",
    "lb_restore": "Restore", "lb_raw": "Raw snippet {name}",
    "exp_expired": "expired", "exp_days_left": "{d}d left", "exp_time_left": "{t} left",
    "act_default": "default", "act_disable": "disable", "act_delete": "delete", "act_notify": "notify",
    "why_quota": "traffic limit", "why_expired": "expired", "q_nolimit_traffic": "{used} used (no limit)",
    "st_ike_help": "IKE_PROPOSALS: compat = default list, strict-sha2 = SHA-2 only", "st_conf_caption": "swanctl.conf (secrets hidden)",
}


# Persian version of TX (same keys, same placeholders).
TX_FA = {
    "b_quota": "📊 حجم و زمان", "b_server": "🖥 سرور", "b_settings": "⚙️ تنظیمات", "b_security": "🔒 امنیت",
    "b_kick": "🔌 قطع اتصال", "b_refresh": "🔄 تازه‌سازی", "b_logs": "📜 لاگ‌ها", "b_cert": "🔐 گواهی",
    "b_address": "🌍 آدرس / دامنه", "b_selftest": "🩺 خودآزمایی", "b_raw": "🧩 تنظیمات خام",
    "b_conf": "📄 نمایش پیکربندی", "b_apply": "♻️ اعمال دوباره‌ی پیکربندی", "b_resetall": "↩️ ریست همه‌ی تنظیمات",
    "b_ike": "🔑 پریست IKE", "b_default": "↩️ پیش‌فرض", "b_enter": "✏️ وارد کردن مقدار", "b_clear": "🧹 پاک کردن",
    "b_restore": "♻️ بازیابی", "b_listbak": "📋 بکاپ‌ها", "n_quota": "هشدارهای حجم و زمان",
    "q_title": "📊 <b>حجم و زمان</b>\nکاربران: {n}   مصرف کل: {total}\n{lines}",
    "q_empty": "هنوز کاربری وجود ندارد.",
    "q_line": "• <b>{user}</b> {bar} {pct}%  {used} / {limit}\n   ⏳ {expires}{flag}",
    "q_line_nolimit": "• <b>{user}</b> {used} (بدون محدودیت)\n   ⏳ {expires}{flag}",
    "q_user": "{note}👤 <b>{user}</b>  {state}\n{block}",
    "q_block": "📦 حجم: {traffic}\n⏳ انقضا: {expires}\n🎯 پس از اتمام: {action}{blocked}",
    "q_blocked": "  (مسدود شده: {why})",
    "q_ask_limit": "سقف حجم <b>{user}</b> را بفرستید: مثلاً <code>10G</code>، <code>500M</code>، <code>1.5T</code> "
                   "یا <code>unlimited</code> (عدد بدون واحد یعنی گیگابایت).",
    "q_ask_expiry": "زمان انقضای <b>{user}</b> را بفرستید: تعداد روز از امروز (<code>30</code>)، یک تاریخ "
                    "(<code>2026-12-31</code>) یا <code>never</code>.",
    "q_g": "➕ {v} گیگ", "q_y": "➕ {v} روز", "q_unl": "♾ بدون محدودیت حجم", "q_never": "♾ بدون انقضا",
    "q_setlimit": "✏️ تعیین سقف حجم", "q_setexp": "📅 تعیین انقضا", "q_action": "🎯 پس از اتمام: {a}", "q_reset": "🔄 صفر کردن مصرف",
    "q_done": "✅ {text}\n\n", "q_fail": "❌ {text}\n\n",
    "q_help_action": "disable = مسدود کردن کاربر، delete = حذف کاربر، notify = فقط هشدار به شما",
    "ev_warn_limit": "⚠️ <b>{user}</b> به {pct}٪ سقف حجم رسید ({used} / {limit}).",
    "ev_warn_expiry": "⏰ انقضای <b>{user}</b> نزدیک است: {expires}.",
    "ev_limit_disable": "⛔ <b>{user}</b> به سقف حجم رسید ({used} / {limit}) و <b>غیرفعال</b> شد.",
    "ev_limit_delete": "🗑 <b>{user}</b> به سقف حجم رسید ({used} / {limit}) و <b>حذف</b> شد.",
    "ev_limit_notify": "🚨 <b>{user}</b> به سقف حجم رسید ({used} / {limit}). کاربر هنوز فعال است (فقط هشدار).",
    "ev_expired_disable": "⛔ مدت <b>{user}</b> تمام شد و <b>غیرفعال</b> شد.",
    "ev_expired_delete": "🗑 مدت <b>{user}</b> تمام شد و <b>حذف</b> شد.",
    "ev_expired_notify": "🚨 مدت <b>{user}</b> تمام شد. کاربر هنوز فعال است (فقط هشدار).",
    "w_title": "➕ <b>کاربر جدید</b> <code>{user}</code>\n📦 حجم: <b>{limit}</b>\n📅 مدت اعتبار: <b>{days}</b>\n"
               "🎯 پس از اتمام: <b>{action}</b>\n\nمقادیر را انتخاب کنید، سپس «ساخت» را بزنید.",
    "w_custom_limit": "سقف حجم را بفرستید، مثلاً <code>10G</code>، <code>500M</code> یا <code>unlimited</code>.",
    "w_custom_days": "تعداد روز (<code>30</code>)، یک تاریخ (<code>2026-12-31</code>) یا <code>never</code> را بفرستید.",
    "w_create": "✅ ساخت", "w_custom": "✏️ دلخواه", "w_unl": "♾",
    "w_bad": "❌ {err}",
    "unlimited": "نامحدود", "never": "هرگز", "w_days_fmt": "{d} روز", "default_action": "پیش‌فرض ({a})",
    "kicked": "🔌 اتصال <b>{user}</b> قطع شد ({n} نشست).",
    "sv_menu": "🖥 <b>سرور</b>\nسرویس: {svc}\nحالت: {mode}\nآدرس: <code>{server}</code>\nگواهی: {cert}\nربات: {bot}",
    "sv_logs": "📜 <b>لاگ سرویس VPN</b> (آخرین خطوط)\n{out}",
    "sv_botlogs": "📜 <b>لاگ ربات</b> (آخرین خطوط)\n{out}",
    "sv_cert": "🔐 <b>گواهی</b>\n{out}",
    "b_renew": "🔄 تمدید همین حالا", "b_renew_force": "⚡ تمدید اجباری",
    "sv_addr": "🌍 <b>آدرس</b>\nحالت: <b>{mode}</b>\nآدرس سرور: <code>{server}</code>\n\n"
               "با تغییر آدرس، همه‌ی کاربران باید پروفایل جدید وارد کنند.",
    "b_setdomain": "🌐 استفاده از دامنه", "b_ipmode": "📍 برگشت به حالت IP", "b_refreship": "🔄 به‌روزرسانی IP عمومی",
    "sv_ask_domain": "دامنه را بفرستید و در صورت تمایل بعدش یک ایمیل برای Let's Encrypt، مثلاً:\n"
                     "<code>vpn.example.com me@example.com</code>\nرکورد A دامنه باید از قبل به این سرور اشاره کند و پورت TCP 80 باید آزاد باشد.",
    "sv_domain_confirm": "به حالت دامنه با <b>{domain}</b> تغییر کند؟ کاربران باید پروفایل جدید وارد کنند.",
    "sv_ip_confirm": "به حالت IP برگردد؟ کاربران باید پروفایل جدید وارد کنند و دوباره به CA اعتماد کنند.",
    "sv_bad_domain": "❌ این شبیه یک دامنه نیست.",
    "se_menu": "🔒 <b>امنیت</b>\nفایروال: <b>{fw}</b>\nپورت‌های SSH باز: {ports}\nFail2ban: {f2b}   آپدیت خودکار: {au}\n\n"
               "ایزوله‌سازی کاربران و مسدودسازی شبکه‌های خصوصی در بخش تنظیمات هستند.",
    "b_fw_on": "🔥 روشن کردن فایروال", "b_fw_off": "🔥 خاموش کردن فایروال", "b_fw_status": "📋 قوانین فایروال", "b_fw_ports": "🔌 پورت‌های SSH",
    "b_f2b": "🛡 نصب fail2ban", "b_autoupd": "♻️ فعال‌سازی آپدیت امنیتی خودکار",
    "se_fw_confirm": "فایروال روشن شود؟ فقط SSH ({ports})، UDP 500 و UDP 4500 باز می‌مانند. اگر پورت SSH شما "
                     "متفاوت است خودتان را قفل می‌کنید؛ اول پورت‌های SSH فایروال را بررسی کنید.",
    "se_ask_ports": "پورت(های) SSH که باید باز بماند را با فاصله بفرستید، مثلاً <code>22 2222</code>.",
    "se_f2b_confirm": "fail2ban برای SSH الان نصب شود (apt)؟", "se_au_confirm": "آپدیت امنیتی خودکار الان فعال شود (apt)؟",
    "st_menu": "⚙️ <b>تنظیمات</b>\nروی یک تنظیم بزنید تا توضیحش را ببینید و تغییرش دهید.\n{lines}",
    "st_detail": "⚙️ <b>{key}</b>\n{out}",
    "st_ask": "مقدار جدید <b>{key}</b> را بفرستید.\n{hint}",
    "st_set": "✅ <b>{key}</b> تغییر کرد.\n{out}", "st_fail": "❌ <b>{key}</b> تغییر نکرد.\n{out}",
    "st_reset_confirm": "همه‌ی تنظیمات پیشرفته به پیش‌فرض برگردند؟ (کاربران، گواهی‌ها و تنظیمات خام حفظ می‌شوند.)",
    "st_conf": "📄 swanctl.conf فعلی (رمزها پنهان‌اند).", "st_applied": "✅ پیکربندی دوباره ساخته و اعمال شد.",
    "st_ike_done": "✅ پریست IKE اعمال شد.\n{out}",
    "rw_menu": "🧩 <b>تنظیمات خام</b>\nهر گزینه‌ی strongSwan را می‌توانید اضافه کنید. یک بخش را انتخاب کنید.\n{out}",
    "rw_view": "🧩 <b>{name}</b>\n{out}", "rw_ask": "محتوای جدید <b>{name}</b> را بفرستید (جایگزین محتوای قبلی می‌شود). خطوط همان‌طور که نوشته شده‌اند در بخش قرار می‌گیرند.",
    "rw_clear_confirm": "تنظیم خام <b>{name}</b> پاک شود؟", "rw_saved": "✅ <b>{name}</b> ذخیره و اعمال شد.\n{out}",
    "rw_failed": "❌ رد شد و محتوای قبلی برگردانده شد.\n{out}",
    "bk_list": "📋 <b>بکاپ‌های روی سرور</b>\n{out}", "bk_pick": "♻️ یک بکاپ غیررمزنگاری‌شده برای بازیابی انتخاب کنید. بکاپ‌های رمزنگاری‌شده "
                "کلید خصوصی شما را لازم دارند؛ آن‌ها را از SSH بازیابی کنید: <code>vpn restore FILE.enc --key KEY.pem</code>.",
    "bk_confirm": "<b>{name}</b> بازیابی شود؟ ابتدا وضعیت فعلی ذخیره می‌شود (نسخه‌ی بازگشت) و بعد سرویس‌ها ری‌استارت می‌شوند.",
    "bk_none": "هیچ بکاپ غیررمزنگاری‌شده‌ای روی سرور نیست.", "bk_done": "✅ بازیابی انجام شد.\n{out}", "bk_fail": "❌ بازیابی ناموفق بود.\n{out}",
    "op_running": "⏳ {label}…", "op_ok": "✅ {label}\n{out}", "op_fail": "❌ {label}\n{out}",
    "selftest": "🩺 <b>خودآزمایی</b>\n{out}", "unknown": "؟",
    "lb_cert_renew": "تمدید گواهی", "lb_cert_force": "تمدید اجباری گواهی", "lb_domain": "تغییر به دامنه {domain}",
    "lb_ipmode": "تغییر به حالت IP", "lb_ip_refresh": "به‌روزرسانی IP عمومی", "lb_selftest": "خودآزمایی", "lb_fw_on": "روشن کردن فایروال",
    "lb_fw_off": "خاموش کردن فایروال", "lb_fw_rules": "قوانین فایروال", "lb_f2b": "نصب fail2ban", "lb_autoupd": "آپدیت امنیتی خودکار",
    "lb_ports": "پورت‌های SSH", "lb_reset": "ریست تنظیمات", "lb_apply": "اعمال دوباره‌ی پیکربندی", "lb_ike": "پریست IKE",
    "lb_restore": "بازیابی", "lb_raw": "تنظیم خام {name}",
    "exp_expired": "منقضی شده", "exp_days_left": "{d} روز مانده", "exp_time_left": "{t} مانده",
    "act_default": "پیش‌فرض", "act_disable": "غیرفعال‌سازی", "act_delete": "حذف", "act_notify": "فقط هشدار",
    "why_quota": "سقف حجم", "why_expired": "پایان زمان", "q_nolimit_traffic": "{used} مصرف شده (بدون محدودیت)",
    "st_ike_help": "IKE_PROPOSALS: compat = فهرست پیش‌فرض، strict-sha2 = فقط SHA-2", "st_conf_caption": "swanctl.conf (رمزها پنهان‌اند)",
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
    for k, default in (("service", True), ("cert", True), ("conn", False), ("update", True), ("quota", True)):
        st["notify"].setdefault(k, default)
    w = st.setdefault("wipe", {})
    w.setdefault("on", True)
    w.setdefault("pending", [])
    return st


def save_state(st):
    with _state_lock:
        os.makedirs(VAR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f)
        os.replace(tmp, STATE_FILE)


_rmw = threading.RLock()


def update_state(fn):
    """Atomic read-modify-write of the state file (the bot has several threads)."""
    with _rmw:
        st = load_state()
        fn(st)
        save_state(st)
        return st


def tr(_key, /, **kw):
    lang = load_state()["lang"]
    s = T.get(lang, T["en"]).get(_key)
    if not s and lang == "fa":
        s = TX_FA.get(_key)
    s = s or T["en"].get(_key) or TX[_key]
    return s.format(**kw) if kw else s


def esc(x):
    return html.escape(str(x), quote=False)


# ----------------------------------------------------------------- Telegram MarkdownV2 rendering
# Texts are written with a tiny tag markup (<b> <i> <code> <pre> <blockquote> <tg-spoiler> <a href>) whose dynamic parts
# go through esc(). Everything is converted to Telegram MarkdownV2 right before sending, so the reserved characters
# of MarkdownV2 never have to be escaped by hand in the texts.
_TAG_RE = re.compile(r"<(/?)(b|i|s|code|pre|blockquote|tg-spoiler|a)(\s[^>]*)?>")
_MD_ESC = re.compile(r"([_*\[\]()~`>#+\-=|{}.!\\])")
_CODE_ESC = re.compile(r"([`\\])")
_URL_ESC = re.compile(r"([)\\])")
_MD_MARK = {"b": "*", "i": "_", "s": "~", "code": "`", "tg-spoiler": "||"}


def to_mdv2(src):
    out, stack, pos = [], [], 0          # stack items: (tag, index in out, attrs)

    def text(seg):
        seg = html.unescape(seg)
        in_code = any(t in ("code", "pre") for t, _, _ in stack)
        out.append((_CODE_ESC if in_code else _MD_ESC).sub(r"\\\1", seg))

    def close(tag, idx, attrs):
        if tag in _MD_MARK:
            out.append(_MD_MARK[tag])
        elif tag == "pre":
            out.append("\n```")
        elif tag == "a":
            m = re.search(r'href="([^"]*)"', attrs)
            out.append("](" + _URL_ESC.sub(r"\\\1", html.unescape(m.group(1)) if m else "") + ")")
        elif tag == "blockquote":
            lines = "".join(out[idx:]).split("\n")
            del out[idx:]
            if "expandable" in attrs:
                lines = ["**>" + lines[0]] + [">" + ln for ln in lines[1:]]
                lines[-1] += "||"
            else:
                lines = [">" + ln for ln in lines]
            out.append("\n".join(lines))

    for m in _TAG_RE.finditer(src):
        text(src[pos:m.start()])
        pos = m.end()
        closing, tag, attrs = m.group(1), m.group(2), m.group(3) or ""
        if not closing:
            stack.append((tag, len(out), attrs))
            if tag in _MD_MARK:
                out.append(_MD_MARK[tag])
            elif tag == "pre":
                out.append("```\n")
            elif tag == "a":
                out.append("[")
        elif stack and stack[-1][0] == tag:
            close(*stack.pop())
    text(src[pos:])
    while stack:
        close(*stack.pop())
    return "".join(out)


def plain_text(src):
    return html.unescape(_TAG_RE.sub("", src))



# ----------------------------------------------------------------- vpn CLI
def vpn(*args, timeout=180, input_text=None):
    """Run the vpn CLI. Secrets are passed through input_text (stdin), never as arguments (visible in `ps`)."""
    try:
        p = subprocess.run([VPN, *args], capture_output=True, text=True, timeout=timeout, input=input_text)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


_KV_TTL = 10          # `vpn status` spawns ~8 processes (systemctl, python, swanctl, openssl...);
_kv_cache = {"at": 0.0, "data": {}}   # every menu screen re-reads it, so cache it briefly
_kv_lock = threading.Lock()


def kv_status(force=False):
    """Server status as a dict. Cached for _KV_TTL seconds; force=True re-reads
    (used right after an operation whose result the screen shows)."""
    with _kv_lock:
        if not force and _kv_cache["data"] and time.time() - _kv_cache["at"] < _KV_TTL:
            return dict(_kv_cache["data"])
    rc, out = vpn("status", "--kv", timeout=60)
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    with _kv_lock:
        _kv_cache["at"] = time.time()
        _kv_cache["data"] = d
    return dict(d)


_ONLINE_TTL = 5       # `swanctl --list-sas` on every tap; 5 s is fresh enough for a screen
_online_cache = {"at": 0.0, "data": None}
_online_lock = threading.Lock()


def online_cached():
    """Online sessions, cached briefly. Display paths only; kick() still
    queries swanctl directly so it always terminates the current sessions."""
    with _online_lock:
        if _online_cache["data"] is not None and time.time() - _online_cache["at"] < _ONLINE_TTL:
            return list(_online_cache["data"])
    sas = L.online()
    with _online_lock:
        _online_cache["at"] = time.time()
        _online_cache["data"] = sas
    return list(sas)


def drop_caches():
    """Forget the cached status/sessions after an operation that changes them
    (user add/del/toggle, restart, preset, restore, upgrade...)."""
    with _kv_lock:
        _kv_cache["at"] = 0.0
        _kv_cache["data"] = {}
    with _online_lock:
        _online_cache["at"] = 0.0
        _online_cache["data"] = None


def list_users():
    rc, out = vpn("user", "list", "--plain")
    users = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[0]:
                users.append((parts[0], parts[1]))
    return users


def latest_backup(encrypted=False):
    """Newest backup file: the plain *.tar.gz (stays on the server) or the encrypted *.tar.gz.enc."""
    suffix = ".tar.gz.enc" if encrypted else ".tar.gz"
    try:
        files = [os.path.join(BACKUPS, f) for f in os.listdir(BACKUPS)
                 if f.startswith("ikev2-backup-") and f.endswith(suffix)]
        return max(files, key=os.path.getmtime) if files else None
    except Exception:
        return None


def backup_key_on():
    # A decision, not a display value (it picks encrypted vs plain backup),
    # so it always reads fresh instead of using the cached status.
    return kv_status(force=True).get("backup_key") == "yes"


# ----------------------------------------------------------------- telegram API
class TG:
    """Telegram API client. Short calls share one keep-alive HTTPS connection.

    Every call used to open a fresh TLS connection; on a slow route to
    api.telegram.org that handshake dominated each tap. Short calls (send,
    edit, answer, delete) now reuse one connection, guarded by a lock because
    the monitor and worker threads call it too. A dead connection (the server
    closed it while idle) is retried once on a fresh one. getUpdates keeps its
    own connection: a 30 s long poll must never block the other calls.
    """

    def __init__(self, token, base=None):
        self.token = token
        self.base = base or f"https://api.telegram.org/bot{token}/"
        u = urlparse(self.base)
        self._host = u.hostname
        self._port = u.port or (443 if u.scheme == "https" else 80)
        self._secure = u.scheme == "https"
        self._prefix = u.path.rstrip("/") + "/"
        self._conn = None
        self._lock = threading.Lock()

    def _new_conn(self, timeout):
        cls = http.client.HTTPSConnection if self._secure else http.client.HTTPConnection
        return cls(self._host, self._port, timeout=timeout)

    def _drop_conn(self):
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:  # noqa: BLE001
            pass
        self._conn = None

    def _post(self, path, body, headers, timeout):
        """One POST over the shared connection; retries once on a fresh one."""
        last = None
        for _ in range(2):
            try:
                if self._conn is None:
                    self._conn = self._new_conn(timeout)
                elif self._conn.sock is not None:
                    self._conn.sock.settimeout(timeout)
                self._conn.request("POST", path, body=body, headers=headers)
                r = self._conn.getresponse()
                data = r.read()
                try:
                    return json.loads(data)
                except ValueError:
                    return {"ok": False, "description": "bad Telegram response"}
            except (http.client.HTTPException, OSError) as e:
                # The connection broke before we got an answer (typically the
                # server closed an idle one): drop it and try once more.
                last = e
                self._drop_conn()
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "description": str(e)}
        return {"ok": False, "description": str(last)}

    def call(self, method, data=None, timeout=40):
        if method == "getUpdates":
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
        body = json.dumps(data or {}).encode()
        with self._lock:
            return self._post(self._prefix + method, body,
                              {"Content-Type": "application/json"}, timeout)

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
        with self._lock:
            return self._post(self._prefix + "sendDocument", bytes(body),
                              {"Content-Type": f"multipart/form-data; boundary={boundary}"}, 120)


tg = None
ADMIN = 0
awaiting = {}  # chat_id -> dict(kind=..., user=...)


def kb(rows):
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]}


def _is_parse_error(r):
    return not r.get("ok") and "parse entities" in str(r.get("description", ""))


def send(text, markup=None):
    data = {"chat_id": ADMIN, "text": to_mdv2(text), "parse_mode": "MarkdownV2", "disable_web_page_preview": True}
    if markup:
        data["reply_markup"] = markup
    r = tg.call("sendMessage", data)
    if _is_parse_error(r):                       # never lose a message because of a formatting problem
        data.pop("parse_mode")
        data["text"] = plain_text(text)
        r = tg.call("sendMessage", data)
    return r


def track_secret(res):
    """A message that contains credentials: remember it so it is deleted again after WIPE_MINUTES."""
    try:
        if not isinstance(res, dict) or not res.get("ok"):
            return res
        mid = res["result"]["message_id"]
        due = time.time() + WIPE_MINUTES * 60

        def fn(st):
            if st["wipe"]["on"]:
                st["wipe"]["pending"].append([ADMIN, mid, due])
        update_state(fn)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
    return res


def send_secret(text, markup=None):
    return track_secret(send(text, markup))


def send_doc_secret(path, caption=None):
    return track_secret(tg.send_document(ADMIN, path, caption))


def wipe_due():
    """Delete the tracked credential messages whose time has come (called by the monitor thread)."""
    now = time.time()
    with _rmw:
        pending = load_state()["wipe"]["pending"]
    done = []
    for item in pending:
        chat, mid, due = item
        if due > now:
            continue
        r = tg.call("deleteMessage", {"chat_id": chat, "message_id": mid})
        # Telegram answered (ok, already gone, too old...) -> forget it; a network error -> retry for up to 6 h
        if r.get("ok") or r.get("error_code") or now - due > 6 * 3600:
            done.append(item)
    if done:
        def fn(st):
            st["wipe"]["pending"] = [x for x in st["wipe"]["pending"] if x not in done]
        update_state(fn)


def edit(msg, text, markup=None):
    if not msg:
        return send(text, markup)
    data = {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"], "text": to_mdv2(text),
            "parse_mode": "MarkdownV2", "disable_web_page_preview": True}
    if markup:
        data["reply_markup"] = markup
    r = tg.call("editMessageText", data)
    if _is_parse_error(r):
        data.pop("parse_mode")
        data["text"] = plain_text(text)
        r = tg.call("editMessageText", data)
    if not r.get("ok") and "not modified" not in str(r.get("description", "")):
        return send(text, markup)
    return r


# ----------------------------------------------------------------- screens
def main_menu_markup():
    return kb([
        [(tr("b_users"), "u:l"), (tr("b_add"), "a:add")],
        [(tr("b_quota"), "q:l"), (tr("b_online"), "s:on")],
        [(tr("b_status"), "s:st"), (tr("b_info"), "s:info")],
        [(tr("b_server"), "sv:m"), (tr("b_settings"), "st:m")],
        [(tr("b_security"), "se:m"), (tr("b_backup"), "b:m")],
        [(tr("b_update"), "up:m"), (tr("b_dns"), "d:m")],
        [(tr("b_notify"), "n:m"), (tr("b_lang"), "l:t")],
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
    sas = [s for s in online_cached() if s["user"] == name]
    online = tr("yes") + f" ({len(sas)})" if sas else tr("no")
    text = tr("user_view", user=esc(name), state=tr("st_on" if enabled else "st_off"), online=online)
    text += "\n" + quota_block(qrec(name))
    rows = [
        [(tr("b_profiles"), f"u:p:{name}"), (tr("b_quota"), f"q:v:{name}")],
        [(tr("b_disable") if enabled else tr("b_enable"), f"u:t:{name}"), (tr("b_passwd"), f"u:w:{name}")],
        [(tr("b_kick"), f"u:k:{name}"), (tr("b_delete"), f"u:d:{name}")],
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
            send_secret(tr("conn_info", server=esc(kv.get("server", "")), user=esc(name), pw=esc(password)))
        rcz, zl = vpn("zed", name)
        if rcz == 0 and zl.startswith("zedsecure://"):
            send_secret(tr("zed_link", link=esc(zl)))
        send(tr("sending_files"))
        if load_state()["wipe"]["on"]:
            send(tr("wipe_note", m=WIPE_MINUTES))
        caps = {
            f"{name}.sswan": "cap_sswan", f"{name}.mobileconfig": "cap_mobile",
            f"{name}-windows.ps1": "cap_win", f"zedsecure-{name}.txt": "cap_zed", "ca.crt": "cap_ca",
            f"README-{name}.txt": "cap_readme",
        }
        for fname, key in caps.items():
            path = os.path.join(tmp, fname)
            if os.path.exists(path):
                send_doc_secret(path, tr(key))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    send(tr("menu", ver=esc(kv.get("version", "?")), server=esc(kv.get("server", "?"))), main_menu_markup())


def do_create_user(name, limit=None, days=None, action=None):
    args = ["user", "add", name, "--plain"]
    if limit:
        args += ["--limit", limit]
    if days:
        args += ["--days", days]
    if action and action != "default":
        args += ["--action", action]
    rc, out = vpn(*args)
    if rc != 0:
        send(tr("err", err=esc(out[-800:]))); return
    drop_caches()
    send(tr("created", user=esc(name)) + "\n" + quota_block(qrec(name)))
    send_profiles(name)


def cert_text(kv):
    state = kv.get("cert_state", "")
    try:
        days = int(kv.get("cert_days", ""))
    except ValueError:
        days = None
    if state == "missing" or (days is None and not state):
        return tr("cert_missing") if state == "missing" else "?"
    if state == "expired" or (days is not None and days < 0):
        return tr("cert_expired", d=-(days if days is not None else 0))
    return tr("cert_ok", d=days)


def show_status(msg):
    kv = kv_status()
    svc = kv.get("service", "?")
    edit(msg, tr("status", svc=("✅ " if svc == "active" else "🚨 ") + esc(svc), users=kv.get("users", "?"),
                 enabled=kv.get("enabled", "?"), online=kv.get("online", "?"), cert=cert_text(kv),
                 sw=esc(kv.get("sw_version", "?")), ver=esc(kv.get("version", "?")), fw=esc(kv.get("firewall", "?"))),
         kb([[(tr("b_status"), "s:st")], back_row()]))


def show_online(msg):
    sas = online_cached()
    if not sas:
        edit(msg, tr("no_online"), kb([[(tr("b_online"), "s:on")], back_row()])); return
    lines = [tr("online_title", n=len(sas))]
    for s in sas:
        lines.append(f"• <b>{esc(s['user'])}</b> — {esc(s['ip'])} — {L.fmt_dur(s['secs'])} — "
                     f"⬇️{L.fmt_bytes(s['rx'])} ⬆️{L.fmt_bytes(s['tx'])}")
    rows = [[(f"{tr('b_kick')} {s['user']}", f"u:k:{s['user']}")] for s in sas[:8] if valid_name(s["user"])]
    edit(msg, "\n".join(lines), kb(rows + [[(tr("b_online"), "s:on")], back_row()]))


def show_info(msg):
    kv = kv_status()
    edit(msg, tr("info", server=esc(kv.get("server", "?")), mode=esc(kv.get("mode", "?")),
                 pool=esc(kv.get("pool", "?")), dns=esc(kv.get("dns", "?"))), kb([back_row()]))


def show_backup(msg):
    last = latest_backup()
    edit(msg, tr("backup_menu", last=esc(os.path.basename(last)) if last else tr("none"),
                 enc=tr("enc_on") if backup_key_on() else tr("enc_off")),
         kb([[(tr("b_make_backup"), "b:make")], [(tr("b_send_backup"), "b:send")], back_row()]))


def show_update(msg):
    kv = kv_status()
    edit(msg, tr("update_menu", ver=esc(kv.get("version", "?")), sw=esc(kv.get("sw_version", "?"))),
         kb([[(tr("b_upd_sw"), "up:sw")], [(tr("b_upd_tool"), "up:tool")], back_row()]))


def show_notify(msg):
    st = load_state()["notify"]
    mark = lambda v: "✅" if v else "⬜"  # noqa: E731
    wipe = load_state()["wipe"]["on"]
    edit(msg, tr("notify_menu"), kb([
        [(f"{mark(st['service'])} {tr('n_service')}", "n:t:service")],
        [(f"{mark(st['cert'])} {tr('n_cert')}", "n:t:cert")],
        [(f"{mark(st['conn'])} {tr('n_conn')}", "n:t:conn")],
        [(f"{mark(st['update'])} {tr('n_update')}", "n:t:update")],
        [(f"{mark(st['quota'])} {tr('n_quota')}", "n:t:quota")],
        [(f"{mark(wipe)} {tr('n_wipe', m=WIPE_MINUTES)}", "n:t:wipe")],
        back_row(),
    ]))


# ----------------------------------------------------------------- long-running jobs
def job_strongswan():
    send(tr("upd_sw_running"))
    rc, out = vpn("upgrade-strongswan", timeout=1800)
    if rc == 0:
        drop_caches()
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    send(("✅ " if rc == 0 else "❌ ") + f"<code>{esc(out[-1500:])}</code>", kb([back_row()]))


def job_backup():
    send(tr("working"))
    rc, out = vpn("backup", "--encrypt") if backup_key_on() else vpn("backup")
    m = re.search(r"(/\S+\.tar\.gz)", out)
    if rc == 0 and m:
        send(tr("backup_done", path=esc(m.group(1))), kb([back_row()]))
    else:
        send(tr("backup_fail", err=esc(out[-600:])), kb([back_row()]))


def job_send_backup(msg):
    """Create a fresh ENCRYPTED backup and send it. A plain archive is never uploaded to Telegram."""
    if not backup_key_on():
        edit(msg, tr("backup_nokey"), kb([back_row()]))
        return
    edit(msg, tr("working"))
    rc, out = vpn("backup", "--encrypt")
    path = latest_backup(encrypted=True)
    if rc != 0 or not path or not path.endswith(".enc"):
        send(tr("backup_fail", err=esc(re.sub(r"\x1b\[[0-9;]*m", "", out)[-600:])), kb([back_row()]))
        return
    tg.send_document(ADMIN, path, tr("cap_backup"))
    show_backup(None)


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


# ----------------------------------------------------------------- 1.4.0 screens: traffic & expiry, wizard, server, security, settings
wizard = {}      # chat_id -> draft of the user being created: {name, limit, days, action}
pending = {}     # chat_id -> data a confirmation screen needs (e.g. the domain to switch to)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
ACTIONS = ("default", "disable", "delete", "notify")
SETTING_CHOICES = {
    "FRAGMENTATION": ["yes", "no", "force", "accept"], "MOBIKE": ["yes", "no"], "UNIQUE": ["no", "never", "keep", "replace"],
    "SEND_CERT": ["always", "ifasked", "never"], "NAT": ["yes", "no"], "LOG_LEVEL": ["default", "0", "1", "2", "3", "4"],
    "CLIENT_ISOLATION": ["yes", "no"], "BLOCK_PRIVATE": ["yes", "no"], "IPV6_BLOCK": ["yes", "no"],
    "QUOTA_ACTION": ["disable", "delete", "notify"], "MSS_CLAMP": ["pmtu", "off", "1360"], "IKE_RATE_LIMIT": ["off", "60", "120", "300"],
}
RAW_NAMES = ("connection", "local", "remote", "child", "pools", "extra", "charon")


def clean(out):
    return ANSI_RE.sub("", out or "").strip()


def pre(out, n=3000):
    out = clean(out)
    return "<pre>" + esc(out[-n:] if out else "(no output)") + "</pre>"


def valid_name(x):
    return bool(NAME_RE.match(x or ""))


def bar(p, width=10):
    f = round(width * p / 100)
    return "▓" * f + "░" * (width - f)


def qrec(name):
    return L.load_quotas().get(name) or L.new_record(name)


def qpct(r):
    return min(100, int(r["used"] * 100 / r["limit"])) if r["limit"] else 0


def exp_text(epoch, now=None):
    """Expiry as text in the bot language: '2026-12-31 (30d left)'."""
    if not epoch:
        return tr("never")
    now = time.time() if now is None else now
    day = time.strftime("%Y-%m-%d", time.localtime(epoch))
    left = epoch - now
    if left <= 0:
        return f"{day} ({tr('exp_expired')})"
    if left >= 86400:
        return f"{day} ({tr('exp_days_left', d=-(-int(left) // 86400))})"
    return f"{day} ({tr('exp_time_left', t=L.fmt_dur(left))})"


def act_name(a):
    return tr("act_" + a)


def quota_block(r):
    if r["limit"]:
        p = qpct(r)
        traffic = f"{bar(p)} {p}%  {L.fmt_bytes(r['used'])} / {L.fmt_bytes(r['limit'])}"
    else:
        traffic = tr("q_nolimit_traffic", used=L.fmt_bytes(r["used"]))
    blocked = tr("q_blocked", why=tr("why_" + r["state"])) if r["state"] else ""
    return tr("q_block", traffic=esc(traffic), expires=esc(exp_text(r["expires"])), action=act_name(r["action"]), blocked=blocked)


def action_label(a, kv=None):
    if a != "default":
        return act_name(a)
    return tr("default_action", a=act_name((kv or kv_status()).get("quota_action", "disable")))


def run_thread(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


def run_op(msg, label, args, back_cb, timeout=180, input_text=None):
    """Run one vpn command with a progress note, then show its output. Meant to run in a worker thread."""
    if msg:
        edit(msg, tr("op_running", label=label))
    rc, out = vpn(*args, timeout=timeout, input_text=input_text)
    if rc == 0:
        drop_caches()
    edit(msg, tr("op_ok" if rc == 0 else "op_fail", label=label, out=pre(out)),
         kb([[(tr("b_back"), back_cb)], back_row()]))
    return rc


def confirm(msg, text, yes_cb, no_cb):
    edit(msg, text, kb([[(tr("b_go"), yes_cb), (tr("b_cancel"), no_cb)]]))


# ---- traffic & expiry
def show_quotas(msg):
    users = [u for u, _ in list_users()]
    quotas = L.load_quotas()
    if not users:
        edit(msg, tr("q_empty"), kb([back_row()])); return
    recs = [quotas.get(u) or L.new_record(u) for u in users]
    recs.sort(key=lambda r: (-qpct(r), -r["used"], r["name"]))
    now = time.time()
    lines = []
    for r in recs[:25]:
        flag = " 🔴" if L.quota_over(r, now) else (" 🟡" if r["limit"] and qpct(r) >= 80 else "")
        if r["limit"]:
            lines.append(tr("q_line", user=esc(r["name"]), bar=bar(qpct(r)), pct=qpct(r), used=L.fmt_bytes(r["used"]),
                            limit=L.fmt_bytes(r["limit"]), expires=esc(exp_text(r["expires"], now)), flag=flag))
        else:
            lines.append(tr("q_line_nolimit", user=esc(r["name"]), used=L.fmt_bytes(r["used"]),
                            expires=esc(exp_text(r["expires"], now)), flag=flag))
    if len(recs) > 25:
        lines.append(f"… +{len(recs) - 25}")
    rows, row = [], []
    for r in recs[:24]:
        row.append((r["name"], f"q:v:{r['name']}"))
        if len(row) == 2:
            rows.append(row); row = []
    if row:
        rows.append(row)
    rows.append([(tr("b_refresh"), "q:l")])
    rows.append(back_row())
    total = L.fmt_bytes(sum(r["used"] for r in recs))
    edit(msg, tr("q_title", n=len(recs), total=total, lines="<blockquote expandable>" + "\n".join(lines) + "</blockquote>"), kb(rows))


def show_quota_user(msg, name, note=""):
    users = dict(list_users())
    if name not in users:
        show_quotas(msg); return
    r = qrec(name)
    state = tr("st_on" if users[name] == "enabled" else "st_off")
    rows = [
        [(tr("q_g", v=5), f"q:g:{name}:5G"), (tr("q_g", v=10), f"q:g:{name}:10G"), (tr("q_g", v=50), f"q:g:{name}:50G")],
        [(tr("q_y", v=7), f"q:y:{name}:7"), (tr("q_y", v=30), f"q:y:{name}:30"), (tr("q_y", v=90), f"q:y:{name}:90")],
        [(tr("q_setlimit"), f"q:sl:{name}"), (tr("q_setexp"), f"q:se:{name}")],
        [(tr("q_unl"), f"q:g0:{name}"), (tr("q_never"), f"q:y0:{name}")],
        [(tr("q_action", a=action_label(r["action"])), f"q:a:{name}")],
        [(tr("q_reset"), f"q:r:{name}")],
        [(tr("b_back"), f"u:v:{name}"), (tr("b_menu"), "m:main")],
    ]
    edit(msg, tr("q_user", note=note, user=esc(name), state=state, block=quota_block(r)), kb(rows))


def quota_cmd(msg, name, *args):
    rc, out = vpn("quota", *args)
    out = clean(out)
    note = tr("q_done" if rc == 0 else "q_fail", text=esc(out.splitlines()[0] if out else ""))
    show_quota_user(msg, name, note)


def cb_quota(msg, p):
    sub = p[1] if len(p) > 1 else "l"
    name = p[2] if len(p) > 2 else ""
    if sub == "l":
        show_quotas(msg); return True
    if not valid_name(name):
        show_quotas(msg); return True
    if sub == "v":
        show_quota_user(msg, name)
    elif sub == "g" and len(p) > 3:
        run_thread(quota_cmd, msg, name, "add", name, "--limit", p[3])
    elif sub == "y" and len(p) > 3:
        run_thread(quota_cmd, msg, name, "add", name, "--days", p[3])
    elif sub == "g0":
        run_thread(quota_cmd, msg, name, "set", name, "--limit", "unlimited")
    elif sub == "y0":
        run_thread(quota_cmd, msg, name, "set", name, "--days", "never")
    elif sub == "a":
        cur = qrec(name)["action"]
        run_thread(quota_cmd, msg, name, "set", name, "--action", ACTIONS[(ACTIONS.index(cur) + 1) % len(ACTIONS)])
    elif sub == "r":
        run_thread(quota_cmd, msg, name, "reset", name)
    elif sub == "sl":
        awaiting[ADMIN] = {"kind": "q_limit", "user": name}
        edit(msg, tr("q_ask_limit", user=esc(name)), kb([[(tr("b_cancel"), f"q:v:{name}")]]))
    elif sub == "se":
        awaiting[ADMIN] = {"kind": "q_exp", "user": name}
        edit(msg, tr("q_ask_expiry", user=esc(name)), kb([[(tr("b_cancel"), f"q:v:{name}")]]))
    else:
        show_quota_user(msg, name)
    return True


def send_quota_event(ev):
    user, kind = esc(ev.get("user", "?")), ev.get("kind", "")
    act = ev.get("action", "disable")
    used, limit = L.fmt_bytes(ev.get("used", 0)), L.fmt_bytes(ev.get("limit", 0))
    if kind == "warn_limit":
        pct = int(ev.get("used", 0) * 100 / ev["limit"]) if ev.get("limit") else 0
        text = tr("ev_warn_limit", user=user, pct=pct, used=used, limit=limit)
    elif kind == "warn_expiry":
        text = tr("ev_warn_expiry", user=user, expires=esc(exp_text(ev.get("expires", 0))))
    elif kind in ("limit", "expired") and act in ("disable", "delete", "notify"):
        text = tr(f"ev_{kind}_{act}", user=user, used=used, limit=limit)
    else:
        return
    gone = kind in ("limit", "expired") and act == "delete"
    send(text, None if gone else kb([[(tr("b_quota"), f"q:v:{ev.get('user', '')}")]]))


# ---- add-user wizard (name -> traffic -> days -> create)
def wiz_limit_text(v):
    return tr("unlimited") if v in ("unlimited", "0") else v


def wiz_days_text(v):
    return tr("never") if v in ("never", "0") else tr("w_days_fmt", d=esc(v)) if v.isdigit() else esc(v)


def start_wizard(name):
    kv = kv_status()
    wizard[ADMIN] = {"name": name, "limit": kv.get("default_limit") or "unlimited",
                     "days": kv.get("default_days") or "never", "action": "default"}
    show_wizard(None)


def show_wizard(msg):
    d = wizard.get(ADMIN)
    if not d:
        show_main(msg); return
    rows = [
        [(f"{v} GB" if v.isdigit() else v, f"w:l:{v}") for v in ("5G", "10G", "20G", "50G")],
        [(v, f"w:l:{v}") for v in ("100G", "200G")] + [(tr("w_unl"), "w:l:0"), (tr("w_custom"), "w:l:c")],
        [(f"{v}d", f"w:d:{v}") for v in ("7", "30", "90", "180")],
        [("365d", "w:d:365"), (tr("w_unl"), "w:d:0"), (tr("w_custom"), "w:d:c")],
        [(tr("q_action", a=action_label(d["action"])), "w:a")],
        [(tr("w_create"), "w:go"), (tr("b_cancel"), "m:main")],
    ]
    edit(msg, tr("w_title", user=esc(d["name"]), limit=esc(wiz_limit_text(d["limit"])), days=wiz_days_text(d["days"]),
                 action=action_label(d["action"])), kb(rows))


def cb_wizard(msg, p):
    d = wizard.get(ADMIN)
    if not d:
        show_main(msg); return True
    sub = p[1] if len(p) > 1 else ""
    val = p[2] if len(p) > 2 else ""
    if sub == "l" and val == "c":
        awaiting[ADMIN] = {"kind": "w_limit"}
        edit(msg, tr("w_custom_limit"), kb([[(tr("b_cancel"), "w:back")]])); return True
    if sub == "d" and val == "c":
        awaiting[ADMIN] = {"kind": "w_days"}
        edit(msg, tr("w_custom_days"), kb([[(tr("b_cancel"), "w:back")]])); return True
    if sub == "l" and re.match(r"^(0|\d{1,4}[MGT])$", val):
        d["limit"] = "unlimited" if val == "0" else val
    elif sub == "d" and re.match(r"^\d{1,4}$", val):
        d["days"] = "never" if val == "0" else val
    elif sub == "a":
        d["action"] = ACTIONS[(ACTIONS.index(d["action"]) + 1) % len(ACTIONS)]
    elif sub == "go":
        wizard.pop(ADMIN, None)
        run_thread(do_create_user, d["name"], d["limit"], d["days"], d["action"])
        return True
    show_wizard(msg)
    return True


# ---- disconnect
def kick_user(msg, name):
    n = L.kick(name)
    drop_caches()
    send(tr("kicked", user=esc(name), n=n))
    show_user(msg, name)


# ---- server
def show_server(msg):
    kv = kv_status()
    svc = kv.get("service", "?")
    edit(msg, tr("sv_menu", svc=("✅ " if svc == "active" else "🚨 ") + esc(svc), mode=esc(kv.get("mode", "?")),
                 server=esc(kv.get("server", "?")), cert=cert_text(kv), bot=esc(kv.get("bot", "?"))),
         kb([[(tr("b_restart"), "s:rs"), (tr("b_logs"), "sv:lg")],
             [(tr("b_cert"), "sv:ce"), (tr("b_address"), "sv:dm")],
             [(tr("b_selftest"), "sv:st"), (tr("b_update"), "up:m")],
             back_row()]))


def show_logs(msg, which="vpn"):
    if which == "bot":
        rc, out = vpn("bot", "logs", "40")
        text = tr("sv_botlogs", out=pre(out))
    else:
        rc, out = vpn("logs", "40")
        text = tr("sv_logs", out=pre(out))
    edit(msg, text, kb([[(tr("b_refresh"), "sv:lg" if which == "vpn" else "sv:bl"),
                         ("Bot" if which == "vpn" else "VPN", "sv:bl" if which == "vpn" else "sv:lg")],
                        [(tr("b_back"), "sv:m")]]))


def show_cert(msg):
    rc, out = vpn("cert", "info", timeout=60)
    edit(msg, tr("sv_cert", out=pre(out)),
         kb([[(tr("b_renew"), "sv:cr"), (tr("b_renew_force"), "sv:cf")], [(tr("b_back"), "sv:m")]]))


def show_address(msg):
    kv = kv_status()
    rows = [[(tr("b_setdomain"), "sv:ds")]]
    if kv.get("mode") == "domain":
        rows.append([(tr("b_ipmode"), "sv:du")])
    else:
        rows.append([(tr("b_refreship"), "sv:ir")])
    rows.append([(tr("b_back"), "sv:m")])
    edit(msg, tr("sv_addr", mode=esc(kv.get("mode", "?")), server=esc(kv.get("server", "?"))), kb(rows))


def cb_server(msg, p):
    sub = p[1] if len(p) > 1 else "m"
    if sub == "lg":
        show_logs(msg, "vpn")
    elif sub == "bl":
        show_logs(msg, "bot")
    elif sub == "ce":
        show_cert(msg)
    elif sub == "cr":
        run_thread(run_op, msg, tr("lb_cert_renew"), ("cert", "renew"), "sv:ce", 900)
    elif sub == "cf":
        run_thread(run_op, msg, tr("lb_cert_force"), ("cert", "renew", "--force"), "sv:ce", 900)
    elif sub == "dm":
        show_address(msg)
    elif sub == "ds":
        awaiting[ADMIN] = {"kind": "domain"}
        edit(msg, tr("sv_ask_domain"), kb([[(tr("b_cancel"), "sv:dm")]]))
    elif sub == "dgo" and pending.get(ADMIN, {}).get("domain"):
        dom = pending.pop(ADMIN)["domain"]
        run_thread(run_op, msg, tr("lb_domain", domain=esc(dom[0])), ("domain", "set", *dom), "sv:dm", 900)
    elif sub == "du":
        confirm(msg, tr("sv_ip_confirm"), "sv:dugo", "sv:dm")
    elif sub == "dugo":
        run_thread(run_op, msg, tr("lb_ipmode"), ("domain", "unset"), "sv:dm", 300)
    elif sub == "ir":
        run_thread(run_op, msg, tr("lb_ip_refresh"), ("ip", "refresh"), "sv:dm", 120)
    elif sub == "st":
        def job():
            edit(msg, tr("op_running", label=tr("lb_selftest")))
            rc, out = vpn("selftest", timeout=120)
            edit(msg, tr("selftest", out=pre(out)), kb([[(tr("b_back"), "sv:m")]]))
        run_thread(job)
    else:
        show_server(msg)
    return True


# ---- security
def show_security(msg):
    kv = kv_status()
    yn = lambda v: "✅" if v == "yes" else "⬜"  # noqa: E731
    edit(msg, tr("se_menu", fw=esc(kv.get("firewall", "?")), ports=esc(kv.get("fw_ports", "?")),
                 f2b=yn(kv.get("fail2ban")), au=yn(kv.get("autoupdate"))),
         kb([[(tr("b_fw_on"), "se:fon"), (tr("b_fw_off"), "se:foff")],
             [(tr("b_fw_status"), "se:fs"), (tr("b_fw_ports"), "se:fp")],
             [(tr("b_f2b"), "se:f2b")], [(tr("b_autoupd"), "se:au")], back_row()]))


def cb_security(msg, p):
    sub = p[1] if len(p) > 1 else "m"
    if sub == "fon":
        kv = kv_status()
        confirm(msg, tr("se_fw_confirm", ports=esc(kv.get("fw_ports", "22"))), "se:fongo", "se:m")
    elif sub == "fongo":
        run_thread(run_op, msg, tr("lb_fw_on"), ("fw", "on"), "se:m", 120)
    elif sub == "foff":
        run_thread(run_op, msg, tr("lb_fw_off"), ("fw", "off"), "se:m", 120)
    elif sub == "fs":
        run_thread(run_op, msg, tr("lb_fw_rules"), ("fw", "status"), "se:m", 60)
    elif sub == "fp":
        awaiting[ADMIN] = {"kind": "fwports"}
        edit(msg, tr("se_ask_ports"), kb([[(tr("b_cancel"), "se:m")]]))
    elif sub == "f2b":
        confirm(msg, tr("se_f2b_confirm"), "se:f2bgo", "se:m")
    elif sub == "f2bgo":
        run_thread(run_op, msg, tr("lb_f2b"), ("security", "fail2ban"), "se:m", 900)
    elif sub == "au":
        confirm(msg, tr("se_au_confirm"), "se:augo", "se:m")
    elif sub == "augo":
        run_thread(run_op, msg, tr("lb_autoupd"), ("security", "autoupdate"), "se:m", 900)
    else:
        show_security(msg)
    return True


# ---- advanced settings
def get_settings():
    rc, out = vpn("get", timeout=60)
    items = []
    for line in clean(out).splitlines()[1:]:
        m = re.match(r"^([A-Z][A-Z0-9_]*)\s+(.*)$", line)
        if m:
            items.append((m.group(1), m.group(2).replace("  [default]", "")))
    return items


def show_settings(msg):
    items = get_settings()
    lines = "\n".join(f"{k}: {v[:40]}" for k, v in items)
    rows, row = [], []
    for k, _ in items:
        row.append((k, f"st:k:{k}"))
        if len(row) == 2:
            rows.append(row); row = []
    if row:
        rows.append(row)
    rows += [[(tr("b_dns"), "d:m"), (tr("b_ike"), "st:ike")], [(tr("b_raw"), "rw:m"), (tr("b_conf"), "st:conf")],
             [(tr("b_apply"), "st:apply"), (tr("b_resetall"), "st:reset")], back_row()]
    edit(msg, tr("st_menu", lines="<pre>" + esc(lines[-2800:]) + "</pre>"), kb(rows))


def show_setting(msg, key):
    rc, out = vpn("get", key, timeout=60)
    rows, row = [], []
    for v in SETTING_CHOICES.get(key, []):
        row.append((v, f"st:v:{key}:{v}"))
        if len(row) == 3:
            rows.append(row); row = []
    if row:
        rows.append(row)
    rows.append([(tr("b_enter"), f"st:e:{key}"), (tr("b_default"), f"st:d:{key}")])
    rows.append([(tr("b_back"), "st:m")])
    edit(msg, tr("st_detail", key=esc(key), out=pre(out)), kb(rows))


def apply_setting(msg, key, value):
    if msg:
        edit(msg, tr("op_running", label=esc(key)))
    rc, out = vpn("set", key, value, timeout=300)
    if rc == 0:
        drop_caches()
    edit(msg, tr("st_set" if rc == 0 else "st_fail", key=esc(key), out=pre(out)),
         kb([[(tr("b_back"), f"st:k:{key}")], [(tr("b_settings"), "st:m")]]))


def send_config(msg):
    rc, out = vpn("conf", "show", timeout=60)
    out = clean(out)
    send(tr("st_conf"))
    if len(out) < 3000:
        send(pre(out))
    else:
        fd, path = tempfile.mkstemp(prefix="swanctl-", suffix=".conf")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(out + "\n")
            tg.send_document(ADMIN, path, tr("st_conf_caption"))
        finally:
            os.unlink(path)


def cb_settings(msg, p):
    sub = p[1] if len(p) > 1 else "m"
    key = p[2] if len(p) > 2 else ""
    keys = [k for k, _ in get_settings()] if sub in ("k", "e", "d", "v") else []
    if sub in ("k", "e", "d", "v") and key not in keys:
        show_settings(msg); return True
    if sub == "k":
        show_setting(msg, key)
    elif sub == "e":
        awaiting[ADMIN] = {"kind": "set", "key": key}
        rc, out = vpn("get", key, timeout=60)
        hint = next((ln.strip() for ln in clean(out).splitlines() if ln.strip().startswith("accepts:")), "")
        edit(msg, tr("st_ask", key=esc(key), hint=esc(hint)), kb([[(tr("b_cancel"), f"st:k:{key}")]]))
    elif sub == "d":
        run_thread(apply_setting, msg, key, "default")
    elif sub == "v" and len(p) > 3:
        run_thread(apply_setting, msg, key, p[3])
    elif sub == "ike":
        rows = [[("compat", "st:pi:compat"), ("strict-sha2", "st:pi:strict-sha2")], [(tr("b_back"), "st:m")]]
        edit(msg, tr("st_menu", lines=tr("st_ike_help")), kb(rows))
    elif sub == "pi" and key in ("compat", "strict-sha2"):
        def job():
            rc, out = vpn("preset", "ike", key, timeout=300)
            if rc == 0:
                drop_caches()
            edit(msg, tr("st_ike_done", out=pre(out)) if rc == 0 else tr("op_fail", label=tr("lb_ike"), out=pre(out)),
                 kb([[(tr("b_back"), "st:m")]]))
        run_thread(job)
    elif sub == "conf":
        run_thread(send_config, msg)
    elif sub == "apply":
        run_thread(run_op, msg, tr("lb_apply"), ("conf", "apply"), "st:m", 300)
    elif sub == "reset":
        confirm(msg, tr("st_reset_confirm"), "st:resetgo", "st:m")
    elif sub == "resetgo":
        run_thread(run_op, msg, tr("lb_reset"), ("reset", "--yes"), "st:m", 300)
    else:
        show_settings(msg)
    return True


def cb_raw(msg, p):
    sub = p[1] if len(p) > 1 else "m"
    name = p[2] if len(p) > 2 else ""
    if sub != "m" and name not in RAW_NAMES:
        sub = "m"
    if sub == "m":
        rc, out = vpn("raw", "list", timeout=30)
        rows, row = [], []
        for n in RAW_NAMES:
            row.append((n, f"rw:v:{n}"))
            if len(row) == 3:
                rows.append(row); row = []
        if row:
            rows.append(row)
        rows.append([(tr("b_back"), "st:m")])
        edit(msg, tr("rw_menu", out=pre(out)), kb(rows))
    elif sub == "v":
        rc, out = vpn("raw", "show", name, timeout=30)
        edit(msg, tr("rw_view", name=esc(name), out=pre(out)),
             kb([[(tr("b_enter"), f"rw:e:{name}"), (tr("b_clear"), f"rw:c:{name}")], [(tr("b_back"), "rw:m")]]))
    elif sub == "e":
        awaiting[ADMIN] = {"kind": "raw", "name": name}
        edit(msg, tr("rw_ask", name=esc(name)), kb([[(tr("b_cancel"), f"rw:v:{name}")]]))
    elif sub == "c":
        confirm(msg, tr("rw_clear_confirm", name=esc(name)), f"rw:cgo:{name}", f"rw:v:{name}")
    elif sub == "cgo":
        def job():
            edit(msg, tr("op_running", label=tr("lb_raw", name=esc(name))))
            rc, out = vpn("raw", "clear", name, timeout=300)
            edit(msg, tr("rw_saved" if rc == 0 else "rw_failed", name=esc(name), out=pre(out)), kb([[(tr("b_back"), "rw:m")]]))
        run_thread(job)
    return True


# ---- backups: list + restore of plain archives
def plain_backups():
    try:
        files = [os.path.join(BACKUPS, f) for f in os.listdir(BACKUPS)
                 if f.startswith("ikev2-") and f.endswith(".tar.gz")]
        return sorted(files, key=os.path.getmtime, reverse=True)[:8]
    except OSError:
        return []


def cb_backup_ext(msg, p):
    sub = p[1]
    files = plain_backups()
    if sub == "ls":
        rc, out = vpn("backups", timeout=30)
        edit(msg, tr("bk_list", out=pre(out)), kb([[(tr("b_restore"), "b:rs")], [(tr("b_back"), "b:m")]]))
    elif sub == "rs":
        if not files:
            edit(msg, tr("bk_none"), kb([[(tr("b_back"), "b:m")]])); return True
        rows = [[(os.path.basename(f).replace("ikev2-", "").replace(".tar.gz", ""), f"b:r:{i}")] for i, f in enumerate(files)]
        rows.append([(tr("b_back"), "b:m")])
        edit(msg, tr("bk_pick"), kb(rows))
    elif sub == "r" and len(p) > 2 and p[2].isdigit() and int(p[2]) < len(files):
        confirm(msg, tr("bk_confirm", name=esc(os.path.basename(files[int(p[2])]))), f"b:rgo:{p[2]}", "b:rs")
    elif sub == "rgo" and len(p) > 2 and p[2].isdigit() and int(p[2]) < len(files):
        path = files[int(p[2])]

        def job():
            edit(msg, tr("op_running", label=tr("lb_restore")))
            rc, out = vpn("restore", path, timeout=900)
            if rc == 0:
                drop_caches()
            edit(msg, tr("bk_done" if rc == 0 else "bk_fail", out=pre(out)), kb([back_row()]))
        run_thread(job)
    else:
        return False
    return True


def on_callback_ext(msg, data):
    """Handlers added in 1.4.0. Returns True when the callback was handled here."""
    p = data.split(":")
    k = p[0]
    if k == "q":
        return cb_quota(msg, p)
    if data == "w:back":
        show_wizard(msg); return True
    if k == "w":
        return cb_wizard(msg, p)
    if k == "sv":
        return cb_server(msg, p)
    if k == "se":
        return cb_security(msg, p)
    if k == "st":
        return cb_settings(msg, p)
    if k == "rw":
        return cb_raw(msg, p)
    if k == "b" and len(p) > 1 and p[1] in ("ls", "rs", "r", "rgo"):
        return cb_backup_ext(msg, p)
    if k == "u" and len(p) > 2 and p[1] == "k" and valid_name(p[2]):
        kick_user(msg, p[2]); return True
    return False


def on_text_ext(aw, text, msg):
    """Free-text answers added in 1.4.0. Returns True when the awaited input was handled."""
    kind = aw["kind"]
    if kind == "add":
        awaiting.pop(ADMIN, None)
        if not valid_name(text):
            send(tr("bad_name"), kb([back_row()])); return True
        if text in dict(list_users()):
            send(tr("exists"), kb([back_row()])); return True
        start_wizard(text)
    elif kind in ("w_limit", "w_days"):
        try:
            L.parse_size(text) if kind == "w_limit" else L.parse_expiry(text)
        except ValueError as exc:
            send(tr("w_bad", err=esc(str(exc)))); return True
        awaiting.pop(ADMIN, None)
        d = wizard.get(ADMIN)
        if d:
            d["limit" if kind == "w_limit" else "days"] = text.strip().lower()
        show_wizard(None)
    elif kind in ("q_limit", "q_exp"):
        awaiting.pop(ADMIN, None)
        flag = "--limit" if kind == "q_limit" else "--expires"
        run_thread(quota_cmd, None, aw["user"], "set", aw["user"], flag, text)
    elif kind == "set":
        awaiting.pop(ADMIN, None)
        run_thread(apply_setting, None, aw["key"], text)
    elif kind == "domain":
        awaiting.pop(ADMIN, None)
        parts = text.split()
        if not parts or len(parts) > 2 or not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", parts[0]):
            send(tr("sv_bad_domain"), kb([[(tr("b_back"), "sv:dm")]])); return True
        pending[ADMIN] = {"domain": tuple(parts)}
        send(tr("sv_domain_confirm", domain=esc(parts[0])), kb([[(tr("b_go"), "sv:dgo"), (tr("b_cancel"), "sv:dm")]]))
    elif kind == "fwports":
        awaiting.pop(ADMIN, None)
        run_thread(run_op, None, tr("lb_ports"), ("fw", "ports", text), "se:m", 120)
    elif kind == "raw":
        awaiting.pop(ADMIN, None)
        run_thread(run_op, None, tr("lb_raw", name=esc(aw["name"])), ("raw", "set", aw["name"]), "rw:m", 300, text + "\n")
    else:
        return False
    return True


# ----------------------------------------------------------------- update dispatch
def on_message(msg):
    text = (msg.get("text") or "").strip()
    if text.startswith("/start") or text.startswith("/menu"):
        awaiting.pop(ADMIN, None)
        show_main(None); return
    aw = awaiting.get(ADMIN)
    if not aw:
        show_main(None); return
    if on_text_ext(aw, text, msg):
        return
    if aw["kind"] == "passwd":
        name = aw["user"]
        auto = text.lower() == "auto"
        if not auto and msg.get("message_id"):      # the admin's own message holds a password: remove it right away
            tg.call("deleteMessage", {"chat_id": msg["chat"]["id"], "message_id": msg["message_id"]})
        if not auto and not PASS_RE.match(text):
            send(tr("bad_pw")); return
        awaiting.pop(ADMIN, None)
        if auto:
            rc, out = vpn("user", "passwd", name, "auto", "--plain")
        else:
            rc, out = vpn("user", "passwd", name, "--stdin", "--plain", input_text=text + "\n")
        if rc != 0:
            send(tr("err", err=esc(out[-800:]))); return
        send(tr("pw_changed"))
        run_thread(send_profiles, name)


def on_callback(cq):
    msg = cq.get("message")
    data = cq.get("data", "")
    tg.call("answerCallbackQuery", {"callback_query_id": cq["id"]})
    parts = data.split(":", 2)
    k = parts[0]
    awaiting.pop(ADMIN, None) if k != "a" else None
    if on_callback_ext(msg, data):
        return
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

        def job_toggle():
            cur = dict(list_users()).get(name)
            new = "disable" if cur == "enabled" else "enable"
            rc, out = vpn("user", new, name)
            if rc != 0:
                send(tr("err", err=esc(out[-800:])))
            else:
                drop_caches()
            show_user(msg, name)
        run_thread(job_toggle)
    elif k == "u" and parts[1] == "w":
        awaiting[ADMIN] = {"kind": "passwd", "user": parts[2]}
        edit(msg, tr("ask_pw"), kb([[(tr("b_cancel"), f"u:v:{parts[2]}")]]))
    elif k == "u" and parts[1] == "d":
        edit(msg, tr("confirm_del", user=esc(parts[2])),
             kb([[(tr("b_yes_del"), f"u:x:{parts[2]}"), (tr("b_cancel"), f"u:v:{parts[2]}")]]))
    elif k == "u" and parts[1] == "x":
        name = parts[2]

        def job_delete():
            rc, out = vpn("user", "del", name)
            if rc == 0:
                drop_caches()
                edit(msg, tr("deleted", user=esc(name)), kb([[(tr("b_users"), "u:l")], back_row()]))
            else:
                send(tr("err", err=esc(out[-800:])))
        run_thread(job_delete)
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
        def job_restart():
            edit(msg, tr("restarting"))
            rc, out = vpn("restart", timeout=120)
            drop_caches()
            svc = kv_status(force=True).get("service", "?")
            edit(msg, tr("restarted", svc=esc(svc)), kb([back_row()]))
        run_thread(job_restart)
    elif data == "b:m":
        show_backup(msg)
    elif data == "b:make":
        threading.Thread(target=job_backup, daemon=True).start()
    elif data == "b:send":
        threading.Thread(target=job_send_backup, args=(msg,), daemon=True).start()
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
        preset = parts[2]

        def job_dns():
            rc, out = vpn("preset", "dns", preset, timeout=120)
            if rc == 0:
                drop_caches()
            kv = kv_status(force=True)
            if rc == 0:
                edit(msg, tr("dns_set", dns=esc(kv.get("dns", "?"))), kb([[(tr("b_dns"), "d:m")], back_row()]))
            else:
                send(tr("err", err=esc(re.sub(r"\x1b\[[0-9;]*m", "", out)[-600:])))
        run_thread(job_dns)
    elif data == "n:m":
        show_notify(msg)
    elif k == "n" and parts[1] == "t":
        key = parts[2]

        def toggle(st):
            if key == "wipe":
                st["wipe"]["on"] = not st["wipe"]["on"]
                if not st["wipe"]["on"]:
                    st["wipe"]["pending"] = []      # switched off: stop deleting what is already tracked
            elif key in st["notify"]:
                st["notify"][key] = not st["notify"][key]
        update_state(toggle)
        show_notify(msg)
    elif data == "l:t":
        update_state(lambda st: st.__setitem__("lang", "en" if st["lang"] == "fa" else "fa"))
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


def cert_alert(kv):
    """Text of the certificate alert for this status, or None when nothing is wrong."""
    state = kv.get("cert_state", "")
    try:
        days = int(kv.get("cert_days", ""))
    except ValueError:
        days = None
    if state == "missing":
        return tr("a_cert_missing")
    if state == "expired" or (days is not None and days < 0):
        return tr("a_cert_expired")
    if days is not None and days <= 14:
        return tr("a_cert", d=days)
    return None


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
                cur = {(s["user"], s["id"]): s for s in online_cached()}
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
                kv = kv_status()
                today = time.strftime("%Y-%m-%d")
                alert = cert_alert(kv)
                if alert and last_warn_day != today:
                    last_warn_day = today
                    send(alert)

            wipe_due()

            for ev in L.take_events():
                if st["notify"].get("quota", True):
                    send_quota_event(ev)

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
