# Changelog

## 1.4.1 - faster Telegram bot

### Fixed
- **The Telegram bot felt slow.** Every tap re-ran `vpn status` (which spawns ~8 processes) and every
  Telegram call opened a fresh TLS connection, and several buttons (restart, DNS preset, user
  enable/disable/delete, quota buttons) ran their slow command on the poll thread, blocking every
  other tap behind them. The bot now: reuses one keep-alive HTTPS connection to Telegram (with one
  retry when the server closed it while idle), caches the server status for 10 s and the online
  sessions for 5 s, and runs the slow buttons in worker threads. Screens stay correct: the cache is
  dropped after any operation that changes the status (user, settings, certificate, firewall,
  domain, restore, upgrade), and the backup-key check always reads fresh because it decides
  encrypted vs plain backup.

## 1.4.0 - traffic limit, expiry and a full-featured Telegram bot

### Added
- **Traffic limit and expiry per user.** `vpn user add NAME --limit 10G --days 30`, `vpn quota list|show|set|add|reset`.
  Usage is counted by `ikev2-quota.timer` (every 20 s) from the strongSwan counters, correctly across rekeys and
  reconnects. When a user runs out of traffic or time the configured action runs: `disable` (default; renewing
  re-enables the user), `delete` or `notify` (only warn). The action can be set globally (`vpn set QUOTA_ACTION`)
  and per user (`--action`). Defaults for new users: `vpn set DEFAULT_LIMIT 20G`, `vpn set DEFAULT_DAYS 30`.
  Data lives in `quotas.db` (covered by backups). Enforcement lags by up to ~20 seconds.
- **Telegram bot**: messages now use Telegram MarkdownV2 (bold, code, expandable quotes, usage bars) with an automatic
  plain-text fallback. New: add-user wizard (traffic, days, action), per-user usage screen with quick renew buttons, traffic
  overview, disconnect button, warnings at 80% usage / 3 days before expiry and when a limit is reached, and menus for
  server (logs, certificate, domain/IP, self-test), security (firewall, SSH ports, fail2ban, auto-updates), all advanced
  settings, DNS/IKE presets, raw snippets, config view, backup list and restore of plain backups. Destructive actions ask
  for a second tap. Not in the bot on purpose: uninstall and backup-key handling.
- Text menu: Users -> Traffic limit & expiry. `vpn user list` shows usage and expiry.
- Tests: `tests/t_quota.sh` and new bot/library tests.

### Notes
- The bot is fully bilingual: every new text exists in English and Persian (`TX` / `TX_FA`), with a test that keeps both tables identical.
- Existing users are unlimited; traffic from before the upgrade is not counted.
- Manually enabling a user that is over its limit disables it again at the next check (renew it instead).

## 1.3.0 - security and reliability release (first public release candidate)

### Fixed bugs
- **`vpn user del / disable / enable / passwd / add` reported success when strongSwan rejected the new configuration**, so a
  "deleted" or "disabled" user could still connect. The users database is now rolled back, the command fails with a clear
  message, and the live configuration always matches the database.
- **Lost updates and corrupt `users.db` under concurrency** (CLI + bot, or two commands at once): every state-changing
  command now runs under one lock and every write (users, config, settings) is atomic.
- **`vpn set` exited 1 on success** for most keys (and `vpn preset ike ...`), breaking scripts.
- **Line breaks in values** were accepted for `DNS` / `LOCAL_TS` (validators only looked at the first line) and corrupted
  `config.env`, which made every later command fail. Values with control characters are refused everywhere, and `config.env`
  is now parsed instead of being executed as shell code.
- **An expired certificate was never renewed and never alerted** (negative day counts were treated like "missing"). Missing
  and expired certificates are now renewed by `vpn cert auto` and reported by `vpn status` and the bot.
- **`vpn profile NAME DIR` changed the permissions of every file in `DIR`.** Only the generated files are touched, they are
  created `0600` from the first byte, and a new folder is `0700`.
- Smaller: `vpn net` printed a misleading usage error when the firewall step failed; `strict-sha2` still contained strongSwan's
  built-in `default` list (it is now an explicit SHA-2-only list); the `certbot` deploy hook errored after leaving domain mode;
  the TUI could uninstall with a single `y`; `vpn reset` had no confirmation; uninstall left `/etc/strongswan.d/ikev2-manager.conf`
  and (with `--purge`) the exported profiles that contain passwords; temp key material was left behind when certificate
  generation failed; `vpn logs` accepted arbitrary options; dead code and a duplicate text key in the bot.

### Security hardening
- **Updates**: downloaded into a private folder and verified (SHA256SUMS, and - once a release key is pinned - a signature)
  **before anything is executed**; `https://` only (no `http://`, redirects cannot downgrade); older releases refused without
  `--force`; the unverified "update from installer file / URL" mode was removed. New `tools/release.sh` (init / sign / verify).
- **Backups**: `vpn backup --encrypt` encrypts to a certificate whose private key you keep (`vpn backup key init|set`); the
  Telegram bot **only sends encrypted backups** and refuses without a key. `vpn restore` validates the archive (no paths
  outside the tool's folders, no `..`, links leaving them, hard links, devices, setuid/world-writable entries), keeps an undo
  copy and re-applies the configuration. The backup folder is `0700`.
- **Client isolation / network policy** (chain `IKEV2_FWD`): VPN clients can no longer reach link-local space (cloud
  metadata `169.254.169.254`), each other (`CLIENT_ISOLATION`) or private networks behind the server (`BLOCK_PRIVATE`);
  pushed DNS servers and split-tunnel routes stay reachable. With NAT only replies can come back to clients.
- **Passwords**: 12+ characters, weak/common/sequential/contains-username refused, generated ones always pass; legacy 8-11
  character passwords keep working. Passwords and the bot token are never passed as command-line arguments
  (`--stdin`, `IKEV2MGR_PASS`, `IKEV2MGR_BOT_TOKEN`, `vpn bot setup -`, curl config on stdin).
- **Brute-force / leaks**: optional `IKE_RATE_LIMIT` (per-source brake on new IKE handshakes), optional `IPV6_BLOCK`
  (experimental IPv6 leak guard), IPv6 privacy note in every client README.
- **CA**: created with `pathlen:0` (falls back gracefully on old `pki`). Documented: no name constraints.
- **Bot**: credentials sent to the chat are deleted after 30 minutes (switchable) and the password you type is deleted at
  once; systemd sandboxing for the service (`NoNewPrivileges`, `PrivateTmp`, `UMask=0077`, ...); admin-only gating unchanged.
- **Installer**: every option validated before anything is installed; secrets passed through the environment.
- `ikev2lib.py zedsecure` reads the password from `IKEV2_ZED_PASS` instead of a command-line argument.

### Added
- `tests/` - 670+ automated checks (`bash tests/run_all.sh`): bash suites with stubbed system tools (stateful `iptables`,
  `pki` via openssl, `curl`, ...), a pseudo-terminal driver for the text UI, Python unit tests for the library and the bot,
  `systemd-analyze verify` of the unit files. GitHub Actions workflow (`.github/workflows/ci.yml`).
- Settings: `CLIENT_ISOLATION`, `BLOCK_PRIVATE`, `IKE_RATE_LIMIT`, `IPV6_BLOCK`.
- Commands: `vpn backup --encrypt`, `vpn backup key ...`, `vpn backup decrypt`, `vpn restore FILE --key KEY`,
  `vpn user add|passwd ... --stdin`, `vpn reset --yes`, `vpn bot setup - ID`, `vpn update --base https://...`.

### Behaviour changes to know about
- New default network policy (`CLIENT_ISOLATION=yes`, `BLOCK_PRIVATE=yes`) applies to upgraded installs as well. If you
  rely on devices talking to each other or on reaching a private network through the VPN: `sudo vpn set CLIENT_ISOLATION no`
  / `sudo vpn set BLOCK_PRIVATE no` (routes listed in `LOCAL_TS` and the pushed DNS servers are always reachable).
- New passwords need 12+ characters (existing ones are not touched).
- The bot no longer sends plain backups; run `sudo vpn backup key init` once to enable encrypted sending.
- `vpn update FILE.sh` / installer-URL updates were removed (use a cloned folder or `--base https://...`).

### Not verified here (needs a real server and real devices)
Real strongSwan/iptables/kernel behaviour, Telegram, and the client apps (iOS, Windows, Android, ZedSecure) were not available
in the test environment. Test a release on a throw-away VPS with your own devices before publishing it.

## 1.2.1
Initial public snapshot.
