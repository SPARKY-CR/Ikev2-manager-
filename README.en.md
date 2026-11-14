# Ikev2-manager

**One-command IKEv2/IPsec VPN server (strongSwan) for Ubuntu/Debian** - plain-text menu, ready-made client
profiles for Android / iPhone / Windows / Mac, full strongSwan tuning, and an admin-only Telegram bot.

🇮🇷 [نسخه‌ی فارسی کامل](README.md)

> ⚠️ **Status:** first public release. Please report problems in Issues (include the error text and
> `vpn version`; **never** post passwords or bot tokens).

## Features

| Area | What you get |
|---|---|
| Install | One command, text wizard (numbers + Enter) or fully non-interactive with `--yes` |
| Users | add / delete / enable / disable / change password, strong random passwords |
| Profiles | Android (`.sswan` for the strongSwan app), **ZedSecure** (`zedsecure://` link), iPhone/iPad/Mac (`.mobileconfig`), Windows (PowerShell script) |
| Modes | **IP mode** (no domain, own CA) or **domain mode** (Let's Encrypt, auto-renew) |
| Tuning | DNS, client IP pool, split-tunnel routes, IKE/ESP proposals, DPD, MOBIKE, timers, devices per user, MSS clamp, NAT, extra firewall ports, log level |
| Full access | "Raw snippets" add **any** strongSwan option (validated, automatic rollback) |
| Security | optional firewall (SSH + VPN only), **client isolation + cloud-metadata/private-network blocking**, fail2ban, unattended security updates, optional IKE brute-force brake, optional IPv6 leak guard |
| Bot | users, profiles, online clients, status, **encrypted** backups, DNS, alerts; credentials auto-deleted from the chat; Persian + English; admin only |
| Maintenance | **encrypted backups**, restore with archive validation, **verified (checksums + signature) updates** with automatic rollback, clean uninstall |

## Requirements

- Ubuntu or Debian (systemd), public IP, root/sudo. Developed and tested mainly on Ubuntu; Debian should work but is less tested.
- A real VPS (KVM) is recommended; some OpenVZ/LXC hosts do not allow IPsec.
- Open **UDP 500** and **UDP 4500** in your provider's firewall (plus **TCP 80** in domain mode for Let's Encrypt).
- A domain is optional.

## Install

Copy this as-is (nothing to edit):

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh)"
```

The wizard asks for: IP or domain mode, first username (a strong password is generated), firewall,
fail2ban, automatic security updates, optional Telegram bot. Afterwards `sudo vpn` opens the menu.

Non-interactive:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh)" -- \
  --yes --user alice --firewall --fail2ban --autoupdate
```

| Option | Meaning |
|---|---|
| `--yes` | no questions; use given options and defaults |
| `--domain example.com`, `--email you@example.com` | domain mode (Let's Encrypt) |
| `--ip 1.2.3.4` | give the public IP yourself (skips the IP lookup) |
| `--user NAME`, `--pass PASS` | first user (default `user1`, random password) |
| `--firewall` / `--no-firewall`, `--fail2ban` / `--no-fail2ban`, `--autoupdate` / `--no-autoupdate` | security extras |
| `--bot-token TOKEN --admin-id ID` | enable the Telegram bot |
| `--from DIR` | use a local clone instead of downloading |
| `--upgrade` | upgrade an existing install |

> `--pass` is visible in the process list while the installer runs; omit it to get a random password, or set the
> `IKEV2MGR_PASS` environment variable instead. Passwords need **12+ characters**. The bot token may be given as
> `IKEV2MGR_BOT_TOKEN`. Everything is validated before anything is installed.

From a clone (read the code first):

```bash
git clone https://github.com/SPARKY-CR/Ikev2-manager-.git && cd $(basename SPARKY-CR/Ikev2-manager-) && sudo bash install.sh --from .
```

**Pin a version:** pass both a tag/commit in the URL and `IKEV2MGR_BRANCH`:

```bash
sudo IKEV2MGR_BRANCH=v1.3.0 bash -c "$(curl -fsSL https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/v1.3.0/install.sh)"
```

**Check the installer before running it** (the installer cannot verify itself; everything it downloads afterwards is verified):

```bash
curl -fsSLO https://raw.githubusercontent.com/SPARKY-CR/Ikev2-manager-/main/install.sh
sha256sum install.sh        # compare with the install.sh line of SHA256SUMS in the repository / release notes
sudo bash install.sh
```

An existing manual `/etc/swanctl` setup is backed up to `/var/backups/ikev2/pre-install-*` before being replaced.

## After install: open the ports

The installer only manages the **server's own** firewall. Your provider's firewall (e.g. AWS Security Group) is separate:
**UDP 500**, **UDP 4500**, **TCP 80** (domain mode only), and your SSH port.

## IP mode vs domain mode

| | IP mode | Domain mode |
|---|---|---|
| Domain needed | no | yes (A record -> server IP) |
| Server certificate | own CA (self-signed) | Let's Encrypt (public, auto-renew) |
| CA on the device | required (embedded in generated profiles) | not needed |
| Best for | quick personal use | apps using Android's built-in IKEv2, many users |

Switch later: `sudo vpn domain set example.com` / `sudo vpn domain unset` (then re-send profiles).

## Menu and commands

`sudo vpn` opens a numbered text menu: Users & profiles, Status, Server/certs/domain, Advanced settings,
Telegram bot, Security, Backup, Updates, Uninstall. **Run all `vpn` commands with `sudo`** (the config is root-only).

```
vpn user list | add NAME [PASS|--stdin] | del | enable | disable | passwd NAME [PASS|auto|--stdin] | show
vpn profile NAME [DIR]    vpn zed NAME [--nopw]    vpn ca
vpn get [KEY]    vpn set KEY VALUE    vpn reset [--yes]
vpn preset dns NAME|list    vpn preset ike compat|strict-sha2
vpn raw list | show | edit | set | clear NAME
vpn conf show | apply
vpn status | online | restart | logs [N]    vpn cert info | renew [--force]
vpn domain set DOMAIN [EMAIL] | unset    vpn ip refresh
vpn fw on | off | status | ports "22 2222"    vpn security fail2ban | autoupdate
vpn bot setup TOKEN|- ADMIN_ID | on | off | status | test | logs      ("-" reads the token from stdin)
vpn backup [--encrypt] | backups | restore FILE [--key PRIVATE_KEY]
vpn backup key init | set CERT.pem | show | remove      vpn backup decrypt FILE.enc KEY [OUT]
vpn update [--check] [--yes] [--force] [--base https://...]    vpn upgrade-strongswan
vpn uninstall [--purge] [--yes]
```

## Client setup

Connection type: **IKEv2 with EAP-MSCHAPv2** (username + password); server = IP or domain.

- **Android (strongSwan app):** install *strongSwan VPN Client* -> menu -> *Import VPN profile* -> `NAME.sswan` -> enter the password.
- **Android (ZedSecure):** copy the `zedsecure://...` link (bot, `zedsecure-NAME.txt`, or `vpn zed NAME`) and import it from the clipboard. If the password inside the link is not accepted, import the second (no-password) link and type it. The link format was derived from the app's own export and may change; domain mode is usually smoother because ZedSecure uses Android's built-in IKEv2.
- **iPhone / iPad / Mac:** open `NAME.mobileconfig`, install it (Settings -> Profile Downloaded). In IP mode also enable full trust for the CA: Settings -> General -> About -> Certificate Trust Settings.
- **Windows:** run `NAME-windows.ps1` in PowerShell **as Administrator**, then connect from Settings -> Network & Internet -> VPN.

## Telegram bot

Only **one numeric admin id** is served, and only in a **private chat**; everyone else is ignored.

1. @BotFather -> `/newbot` -> copy the token. 2. @userinfobot -> your numeric id. 3. Open your bot and press Start.
4. Enter both in the install wizard (or `sudo vpn` -> Telegram bot). 5. Send `/start`.

It can create users and send all profile files + the ZedSecure link, enable/disable/delete users, show status and
online clients, restart the VPN, create and send **encrypted** backups, change DNS, update strongSwan and the tool, and
send alerts (service down/up, certificate expired/expiring, client connect/disconnect, new tool version). Persian and English.

> ⚠️ Telegram chats are not end-to-end encrypted. The bot sends **user passwords** into your chat. To limit the damage:
> messages and files that contain credentials are **deleted from the chat after 30 minutes** (switchable under *Alerts*),
> a password you type into the chat is deleted immediately after the bot reads it, and passwords are never passed to
> commands as arguments. Backups (private keys + every password) are only ever sent **encrypted** to a key whose
> private half you keep (`sudo vpn backup key init`); without a key the bot refuses to send a backup.
> Use the bot only on an account/device you trust; keep the token secret (stored in `/etc/ikev2/config.env`, mode 600).
> The bot service runs with systemd sandboxing options (`NoNewPrivileges`, `PrivateTmp`, ...).

## Advanced strongSwan settings

`sudo vpn` -> *Advanced*, or `sudo vpn get` / `sudo vpn set KEY VALUE` (`default` resets). Every change is validated,
applied, and **rolled back automatically** if strongSwan rejects it. Clients must reconnect after DNS/pool/route changes.

| Setting | Meaning | Default |
|---|---|---|
| `DNS` | DNS servers pushed to clients | `1.1.1.1,8.8.8.8` |
| `POOL` | virtual IP range for clients (CIDR /8../30) | `10.30.0.0/16` |
| `LOCAL_TS` | routes pushed; `0.0.0.0/0` = everything, otherwise split tunnel | `0.0.0.0/0` |
| `IKE_PROPOSALS` / `ESP_PROPOSALS` | accepted proposals | `default,aes256-sha256-modp2048,...` |
| `DPD_DELAY` | dead-peer detection interval | `30s` |
| `FRAGMENTATION` | `yes/no/force/accept` | `yes` |
| `MOBIKE` | survive network changes (wifi <-> mobile) | `yes` |
| `UNIQUE` | duplicate sessions: `no` (allow), `never`, `keep`, `replace` | `no` |
| `REKEY_TIME`, `REAUTH_TIME`, `CHILD_REKEY_TIME`, `CHILD_LIFE_TIME` | timers | strongSwan defaults |
| `SEND_CERT` | `always/ifasked/never` | `always` |
| `MSS_CLAMP` | `pmtu`, `off`, or 536-1460 | `pmtu` |
| `NAT` | masquerade VPN traffic | `yes` |
| `FW_EXTRA_TCP` / `FW_EXTRA_UDP` | extra ports allowed when the firewall is on | empty |
| `LOG_LEVEL` | `default` or `-1`..`4` | `default` |
| `CLIENT_ISOLATION` | clients cannot reach each other (device-to-device) | `yes` |
| `BLOCK_PRIVATE` | clients cannot reach private networks (10/8, 172.16/12, 192.168/16, 100.64/10) behind the server; the pushed DNS servers and `LOCAL_TS` routes stay reachable | `yes` |
| `IKE_RATE_LIMIT` | `off` or a number: max new IKE handshakes per minute per source IP on UDP/500 (password-guessing brake; e.g. `60`) | `off` |
| `IPV6_BLOCK` | `yes` = also route `::/0` into the tunnel and drop it, so IPv6 cannot leak around the VPN (**experimental**, needs `LOCAL_TS` with `0.0.0.0/0`) | `no` |

DNS presets: `cloudflare`, `google`, `quad9`, `adguard`, `cloudflare-family`, `opendns` (`vpn preset dns NAME`).

**Raw snippets** add any other strongSwan option: `vpn raw edit connection|local|remote|child|pools|extra|charon`
(`extra` = whole extra sections appended to `swanctl.conf`; `charon` = a `strongswan.conf` fragment). Reference:
<https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html>. View the final config with `sudo vpn conf show` (secrets masked).
IKE ports 500/4500 are intentionally not configurable: phone built-in clients only accept those.
`strict-sha2` (preset) is an explicit SHA-2-only list **without** strongSwan's built-in `default` list; old clients may fail with it.

## Security

- **Firewall** (`vpn fw on`): chain `IKEV2_FW`; inbound limited to SSH ports, UDP 500/4500 and `FW_EXTRA_*`. Your current SSH session survives, but a wrong SSH port can block *new* sessions (use your provider's console and `sudo vpn fw off`).
- **What VPN clients may reach** (chain `IKEV2_FWD`, see `vpn fw status`): never link-local space (this blocks the cloud **metadata service** `169.254.169.254`), by default not each other (`CLIENT_ISOLATION`) and not private networks behind the server (`BLOCK_PRIVATE`). Everything else is forwarded and NATed.
- **IPv6 is not tunnelled.** If a client network also has IPv6, some traffic can leave outside the VPN. The Android profile blocks IPv6; elsewhere disable IPv6 on the network, or try `IPV6_BLOCK=yes` (experimental).
- **Passwords:** 12+ characters (generated ones: 16 random), weak/common ones are refused, and a failed apply never leaves a user half-created or half-deleted. There is no lock-out for wrong passwords: use strong passwords and, if you see guessing in `vpn logs`, set `IKE_RATE_LIMIT`. (fail2ban only guards SSH.)
- **fail2ban** for SSH (5 failures in 10 min -> 1 h ban); **unattended-upgrades** for security updates.
- EAP-MSCHAPv2 requires plaintext secrets, so passwords live in `/etc/ikev2/users.db` (root-only, mode 600). State-changing commands are serialised with a lock and written atomically; `config.env` is parsed, never executed.
- **IP mode CA:** the CA (`/etc/ikev2/pki/ca.key`, mode 600) is created with `pathlen:0` (it can only sign end-entity certificates) but, like any self-made root, it has **no name constraints**. Anyone who steals `ca.key` can impersonate sites to devices that trust this CA. Treat the key like a root password, never copy it off the server unencrypted (see backups) and prefer **domain mode** (public CA, nothing to install on devices) for more than a few personal devices.

## Backup, update, uninstall

- `sudo vpn backup` -> `/var/backups/ikev2` (mode 700; last 10 kept; contains **private keys and all passwords**, files are `0600`). A backup is also taken before every update, restore and uninstall.
- **Encrypted backups** are the only kind that should leave the server: `sudo vpn backup key init` creates a key pair, prints the **private key once** (save it in a password manager - it is *not* stored on the server) and keeps only the certificate. Then `sudo vpn backup --encrypt` writes `*.tar.gz.enc`. Or bring your own: create `backup.crt`/`backup.key` on your computer and run `sudo vpn backup key set backup.crt`. Decrypt anywhere with
  `openssl cms -decrypt -binary -inform DER -in FILE.enc -inkey backup.key -out backup.tar.gz`.
- `sudo vpn restore FILE [--key PRIVATE_KEY]` first **validates the archive** (only the tool's own folders, no absolute/`..` paths, no links that leave them, no setuid or device files), saves a safety copy of the current state, restores, and re-applies the configuration.
- `sudo vpn update` downloads the release into a private folder, **verifies it (SHA256SUMS and, once a release key is pinned, its signature) before anything is executed**, backs up, installs, runs a **self-test** and **rolls back automatically** if it fails. Users, certificates and settings are kept. Only `https://` sources are accepted. The bot only *notifies* about new versions; nothing is installed without your confirmation. Offline: `sudo vpn update /path/to/clone`.
- `sudo vpn uninstall` (type `YES`) removes the tool, bot, firewall/NAT rules and VPN config (final backup first); `--purge` also removes strongSwan packages, `/etc/ikev2` and the exported profiles (they contain passwords).

## Troubleshooting

- **Cannot connect:** UDP 500/4500 open in the provider firewall (most common); `sudo vpn status`; `sudo vpn logs 100`; user is `enabled`; iPhone in IP mode needs CA trust enabled; IP changed -> `sudo vpn ip refresh`; check clocks.
- **Connected but no internet:** `sudo vpn get NAT` = yes; try `sudo vpn preset dns cloudflare`; `sysctl net.ipv4.ip_forward` = 1.
- **Some sites slow/stuck:** `sudo vpn set MSS_CLAMP 1360`.
- **Windows:** run the script as Administrator.
- **Bot silent:** `sudo vpn bot status`, `sudo vpn bot logs`; correct token/id; press Start in the bot chat once.

## What the installer changes

| Item | Where |
|---|---|
| apt packages | `strongswan`, `strongswan-swanctl`, `strongswan-pki`, `charon-systemd`, `libcharon-extra-plugins`, `libcharon-extauth-plugins`, `iptables`, `curl`, `openssl`, `python3`; domain mode: `certbot`; optional: `fail2ban`, `unattended-upgrades` |
| tool files | `/usr/local/bin/vpn`, `/opt/ikev2/` |
| config & data | `/etc/ikev2/`, `/var/lib/ikev2/`, `/var/backups/ikev2/` |
| strongSwan | `/etc/swanctl/`, `/etc/strongswan.d/ikev2-manager.conf` |
| systemd | `ikev2-net`, `ikev2-bot`, `ikev2-certcheck.timer` |
| network | `/etc/sysctl.d/99-ikev2.conf`; iptables rules tagged `ikev2-mgr` and chain `IKEV2_FW` (if firewall on) |
| optional | `/etc/fail2ban/jail.d/ikev2.local`, `/etc/apt/apt.conf.d/20auto-upgrades` |
| exported profiles | `/root/ikev2-profiles/` |

## Privacy and trust

**No telemetry.** External services it may contact: GitHub raw (install/update/version check), `ifconfig.me` /
`api.ipify.org` / `ipv4.icanhazip.com` (public IP detection; skipped with `--ip`), Let's Encrypt (domain mode),
Telegram API (only if the bot is enabled), apt mirrors, and the DNS servers you choose (given to clients).

**Trust:** the code runs as root, so you trust the project maintainer. Releases are protected in layers:
`SHA256SUMS` catches corrupted or tampered downloads; when the maintainer has published a **signing key**
(`release.pub` + `SHA256SUMS.sig`, see *Maintainers*), the first install pins that key in `/etc/ikev2/release.pub` and
**every later update must be signed by it** - a stolen GitHub token or a hijacked mirror then cannot push code to
existing servers (the key is pinned on first use: if you install an unsigned release first, only checksums apply
until a signed one arrives). Update downloads are verified *before* they are executed, never over plain `http://`,
and never without your confirmation. If that is not enough for you: read the code first (`git clone` + `--from .`)
and pin a tag/commit.

## Repository layout and maintenance

`install.sh` (installer) - `vpn` (main tool, one bash file) - `bot.py` (Telegram bot, Python stdlib only) -
`ikev2lib.py` (shared helpers) - `VERSION` - `SHA256SUMS` (+ `SHA256SUMS.sig`, `release.pub` once you sign) -
`tools/release.sh` (signing) - `tests/` (see below) - `.github/workflows/ci.yml`.

**Tests:** `bash tests/run_all.sh` (no root, network or strongSwan needed: `iptables`, `swanctl`, `pki`, `curl`... are
stubbed; the systemd units are checked with `systemd-analyze verify`). It covers users/locking, settings, certificates,
profiles, firewall rules, backups, restore safety, the verified-update path, the installer and the bot. What it cannot
cover is the real kernel/strongSwan/Telegram and real client devices: **test a release on a throw-away VPS with your
phones before publishing it.**

**Maintainers - releasing (once per release):**

```bash
bash tools/release.sh init      # first time only: creates your signing key (~/.ikev2mgr/release.key) and writes release.pub
# change code, bump VERSION, run: bash tests/run_all.sh
bash tools/release.sh sign      # regenerates SHA256SUMS (install.sh, vpn, bot.py, ikev2lib.py, VERSION, release.pub) + SHA256SUMS.sig
git add -A && git commit && git tag vX.Y.Z && git push --follow-tags     # ONE commit with everything
```

Keep the private key offline and **back it up**: installs that pinned its public key accept only releases signed by it
(a new key can be introduced by a release signed with the old one). Forks: set `IKEV2MGR_REPO=user/repo` (and
optionally `IKEV2MGR_BRANCH`) when installing, and sign with your own key.

## Contributing, license, disclaimer

Issues and PRs are welcome (test on a throw-away server first). Security issues: see [SECURITY.md](SECURITY.md).
License: MIT ([LICENSE](LICENSE)); strongSwan is installed separately from your distribution under its own license.
The software is provided "as is", without warranty. You are responsible for lawful use and for following the rules of your
country and server provider.


## Traffic limit and expiry (1.4.0)

```
vpn user add alice --limit 20G --days 30        # 20 GB, valid for 30 days
vpn quota list                                   # usage / limit / expiry for everyone
vpn quota set alice --limit 50G --expires 2026-12-31 --action delete
vpn quota add alice --limit 10G --days 30        # renew / extend (re-enables a user the quota disabled)
vpn quota reset alice                            # usage back to 0
vpn set DEFAULT_LIMIT 20G; vpn set DEFAULT_DAYS 30; vpn set QUOTA_ACTION disable|delete|notify
```
Sizes: `500M`, `10G`, `1.5T` (a bare number means GB), `unlimited`. Expiry: days from now, `YYYY-MM-DD` or `never`.
A timer checks every 20 s, so enforcement can lag by that much. The Telegram bot offers all of this with buttons.
