# Security policy / سیاست امنیتی

## Reporting a vulnerability / گزارش آسیب‌پذیری

Please **do not open a public issue** for security problems.
Use GitHub's private reporting: **Security → Report a vulnerability** on this repository.
Include the version (`vpn version`), what you did, and what happened. You will get a reply as soon as possible.

لطفاً مشکلات امنیتی را **در Issue عمومی** مطرح نکنید. از بخش **Security ← Report a vulnerability**
همین ریپو استفاده کنید و نسخه (`vpn version`)، مراحل و نتیجه را بنویسید.

## Supported versions

Only the latest release (`main`) receives fixes. Update with `sudo vpn update`.

## What this project touches on your server

See the "What the installer changes" section of the README.

## Security model (short) / مدل امنیتی (خلاصه)

- **Trust:** the tool runs as root. Updates are verified (SHA256SUMS, and a signature once a release key is pinned in
  `/etc/ikev2/release.pub`) *before* anything is executed, and only over `https://`. A pinned install refuses unsigned
  or wrongly signed releases. See README → "Privacy and trust".
- **Secrets at rest:** `/etc/ikev2/users.db` (VPN passwords, plaintext because EAP-MSCHAPv2 needs it), `config.env`
  (bot token), the CA/server keys - all root-only (0600/0700). `config.env` is parsed, never executed.
- **Secrets in motion:** passwords and the bot token never travel on a command line (stdin / environment / curl config).
  Backups that leave the server must be encrypted to a key you hold (`vpn backup key`); the Telegram bot refuses to send
  anything else. Credentials sent to the chat are deleted after 30 minutes.
- **VPN clients** cannot reach link-local space (cloud metadata), other clients or private networks behind the server by
  default (`vpn get CLIENT_ISOLATION BLOCK_PRIVATE`).
- **Known limits:** IPv6 is not tunnelled by default (leaks possible; `IPV6_BLOCK` is experimental); the IP-mode CA has no
  name constraints; there is no lock-out for wrong VPN passwords (use strong passwords; `IKE_RATE_LIMIT` slows guessing);
  Telegram is not end-to-end encrypted.

Reports of problems in any of these areas are very welcome.

Maintainers: sign every release (`bash tools/release.sh sign`) and keep the signing key offline and backed up.
