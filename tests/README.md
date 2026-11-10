# Tests

```bash
bash tests/run_all.sh        # everything (about a minute); add -v to see every check
ROOT=/path/to/other/checkout bash tests/run_all.sh   # run these tests against another copy (e.g. an older release)
```

No root, network or strongSwan is needed. System tools are replaced by stubs in `tests/stubs/`
(a *stateful* `iptables`/`ip6tables`, `pki` implemented with openssl, `curl` with a fake https mirror, `swanctl`,
`systemctl`, `certbot`, ...), and the scripts run with `IKEV2_TEST=1` plus scratch folders (`IKEV2_ETC`, `IKEV2_SWAN`, ...).

| Suite | Covers |
|---|---|
| `t_config_users.sh` | config parsing/writing, users DB, password policy, rollback when swanctl rejects a change, concurrency |
| `t_settings.sh` | `vpn set/get/reset/preset/raw`: validation, exit codes, config integrity, IPv6 guard in swanctl.conf |
| `t_certs_profiles.sh` | certificate expiry maths and auto-renewal, CA creation, client profiles (permissions, content), systemd units, bot token handling |
| `t_network.sh` | NAT, client-forwarding policy, firewall chain, IPv6 guard, IKE rate limit, idempotency, cleanup |
| `t_backup.sh` | backups, encryption keys, encrypted backups, restore, hostile archives |
| `t_update.sh` | verified updates (https only, checksums, signatures, key pinning/rotation, rollback), `install.sh`, `tools/release.sh` |
| `t_domain_tui.sh` | domain mode (Let's Encrypt stubbed) and the text UI driven through a pseudo-terminal |
| `t_misc.sh` | everyday commands, locking, selftest/migrate, uninstall |
| `test_lib.py`, `test_bot.py` | `ikev2lib.py` (SA parsing, ZedSecure links, backup validation) and `bot.py` (fake Telegram + fake `vpn`) |

## What these tests cannot tell you

They do not run the real kernel, strongSwan, Telegram or any VPN client. Before publishing a release, install it on a
throw-away VPS and connect with your own devices (Android strongSwan / ZedSecure, iPhone, Windows, macOS), check that
traffic flows, that clients cannot reach `169.254.169.254` or each other, and that `vpn update` works end to end.
