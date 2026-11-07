# ikev2-manager

One-command **IKEv2/IPsec VPN server** (strongSwan) for Ubuntu/Debian, with a text menu,
client profiles for Android / iPhone / Windows, full strongSwan tuning, and an
**admin-only Telegram bot** (English + Persian).

## Install

On a fresh Ubuntu/Debian server (as a sudo user):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh)"
```

A text wizard asks: IP-only or domain (Let's Encrypt), first user, firewall, fail2ban,
automatic security updates, Telegram bot. Afterwards run `sudo vpn` for the menu.

Non-interactive example:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh)" -- \
  --yes --user alice --firewall --fail2ban --autoupdate
```

Or from a clone: `git clone https://github.com/YOUR_USER/YOUR_REPO && sudo bash YOUR_REPO/install.sh --from YOUR_REPO`

> Open **UDP 500** and **UDP 4500** (and TCP 80 for domain mode) in your cloud firewall / security group.

## What you get

| Area | Features |
|---|---|
| Users | add / delete / enable / disable / change password, random strong passwords |
| Profiles | `.sswan` (Android strongSwan app), `.mobileconfig` (iPhone/iPad/Mac), PowerShell script (Windows) |
| Modes | **IP mode** (own CA, no domain needed) or **domain mode** (Let's Encrypt, auto-renew) |
| Tuning | DNS, client IP pool, split-tunnel routes, IKE/ESP proposals, DPD, MOBIKE, rekey/reauth timers, devices per user, MSS clamp, NAT, extra firewall ports, log level |
| Raw access | add **any** strongSwan option via snippets (`vpn raw edit connection\|local\|remote\|child\|pools\|extra\|charon`) - validated, auto-rollback |
| Security | optional firewall (SSH + VPN only), fail2ban, unattended security upgrades |
| Bot | users, profiles, online clients, status, backup, DNS presets, alerts (service down, cert expiry, new version) |
| Maintenance | backup/restore, update from GitHub with automatic rollback, uninstall |

## Commands

```
sudo vpn                          text menu
vpn user add|del|list|enable|disable|passwd NAME
vpn profile NAME                  write profile files
vpn get [KEY] / vpn set KEY VALUE / vpn reset
vpn preset dns cloudflare|google|quad9|adguard|cloudflare-family|opendns
vpn raw list|show|edit|set|clear NAME
vpn conf show                     final swanctl.conf (secrets masked)
vpn status | online | restart | logs
vpn domain set DOMAIN | unset     vpn cert info|renew
vpn fw on|off|ports "22"          vpn security fail2ban|autoupdate
vpn backup | restore FILE
vpn update [--check]              update from GitHub
vpn uninstall [--purge]
```

## Telegram bot

1. Talk to **@BotFather**, `/newbot`, copy the token.
2. Talk to **@userinfobot** to get *your* numeric id.
3. `sudo vpn` → Telegram bot → set token + admin id (or answer the wizard).

The bot only answers that single admin id, only in a private chat.

## Updating

`sudo vpn update` downloads the latest files from this repo, verifies `SHA256SUMS`, installs,
runs a self-test and **rolls back automatically** if it fails. Users, certificates and settings are kept.
Maintainers: bump `VERSION`, regenerate `SHA256SUMS` (`sha256sum vpn bot.py ikev2lib.py VERSION > SHA256SUMS`), push.

## Notes

- Self-signed (IP mode) setups need the CA on each client; the generated profiles embed it.
  For apps that use Android's built-in IKEv2 client, **domain mode** (public certificate) is simplest.
- Passwords are stored in plain text in `/etc/ikev2/users.db` (root-only) because EAP-MSCHAPv2 requires it.
- Only IPv4 is routed through the VPN; the Android profile blocks IPv6 to avoid leaks.

---

## فارسی (خلاصه)

نصب با یک دستور (جای `YOUR_USER/YOUR_REPO` را عوض کنید):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/install.sh)"
```

بعد از نصب `sudo vpn` منوی مدیریت را باز می‌کند: کاربران، پروفایل‌ها (اندروید/آیفون/ویندوز)، تنظیمات
کامل strongSwan (DNS، رنج IP، پروپوزال‌ها، تایمرها و ...)، ربات تلگرام فقط برای ادمین، بکاپ، آپدیت از GitHub
با برگشت خودکار. پورت‌های UDP 500 و 4500 را در فایروال سرویس‌دهنده باز کنید.
