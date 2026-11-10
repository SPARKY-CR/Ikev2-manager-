#!/usr/bin/env bash
# IKEV2MGR-INSTALLER
# ikev2-manager: IKEv2/strongSwan VPN installer + text-menu manager + Telegram bot.
# Downloads the tool files from GitHub (or --from DIR), verifies SHA256SUMS (and the release
# signature when a release key is known), then installs.
set -uo pipefail

# Official source of this project - nothing to edit, just run the installer.
# Forks / mirrors can override: IKEV2MGR_REPO=user/repo, IKEV2MGR_BRANCH=<branch|tag|commit>,
# or IKEV2MGR_BASE=<raw base url>  (must be https://).
IKEV2MGR_REPO="${IKEV2MGR_REPO:-SPARKY-CR/Ikev2-manager-}"
IKEV2MGR_BRANCH="${IKEV2MGR_BRANCH:-main}"
BASE="${IKEV2MGR_BASE:-https://raw.githubusercontent.com/$IKEV2MGR_REPO/$IKEV2MGR_BRANCH}"
FILES=(vpn bot.py ikev2lib.py VERSION)

# paths (overridable so the test-suite can run in a scratch folder)
ETC="${IKEV2_ETC:-/etc/ikev2}"
VAR="${IKEV2_VAR:-/var/lib/ikev2}"
OPT="${IKEV2_OPT:-/opt/ikev2}"
BIN="${IKEV2_BIN:-/usr/local/bin/vpn}"
TESTMODE="${IKEV2_TEST:-0}"
RELEASE_PIN="$ETC/release.pub"       # signing key pinned at the first install; later updates must match it

usage() {
  cat <<EOF
ikev2-manager installer

Install (interactive wizard):
  sudo bash -c "\$(curl -fsSL $BASE/install.sh)"

Options:
  --upgrade              upgrade an existing install (keeps users/certs/settings)
  --yes                  non-interactive, use defaults / given options
  --from DIR             use files from a local folder (cloned repo) instead of downloading
  --domain DOMAIN        use a domain + Let's Encrypt (default: IP + own CA)
  --email EMAIL          email for Let's Encrypt (optional)
  --ip IP                override detected public IP
  --user NAME            first VPN user (default: user1)
  --pass PASSWORD        its password (default: random; 12+ chars). Visible in 'ps' while the
                         installer runs - prefer the IKEV2MGR_PASS environment variable
  --firewall | --no-firewall       allow only SSH + VPN inbound
  --fail2ban | --no-fail2ban       protect SSH with fail2ban
  --autoupdate | --no-autoupdate   automatic security updates
  --bot-token TOKEN --admin-id ID  enable the admin-only Telegram bot
                                   (token: or set IKEV2MGR_BOT_TOKEN)
EOF
}

# ---------------------------------------------------------------- download + verification
dl() { # URL OUTFILE : https or file only; redirects may never downgrade to http
  case "$1" in
    https://*) curl -fsSL --max-time 60 --proto '=https' --proto-redir '=https' "$1" -o "$2" ;;
    file://*)  curl -fsSL --max-time 60 --proto '=file' "$1" -o "$2" ;;
    *) return 1 ;;
  esac
}

# verify_payload DIR : every payload file must match SHA256SUMS; the SHA256SUMS file must carry a valid
# signature when a release key is pinned (or, on a first install, when the release ships key + signature).
verify_payload() {
  local d="$1" f exp got key=""
  for f in "${FILES[@]}" $([[ -f $d/release.pub ]] && echo release.pub); do
    exp=$(awk -v f="$f" '{n=$2; sub(/^\*/,"",n)} n==f{print $1; exit}' "$d/SHA256SUMS" 2>/dev/null)
    [[ $exp =~ ^[0-9a-f]{64}$ ]] || { echo "$f is not listed in SHA256SUMS."; return 1; }
    got=$(sha256sum "$d/$f" 2>/dev/null | cut -d' ' -f1)
    [[ $got == "$exp" ]] || { echo "Checksum mismatch: $f"; return 1; }
  done
  if [[ -f $RELEASE_PIN ]]; then key="$RELEASE_PIN"
  elif [[ -f $d/release.pub && -f $d/SHA256SUMS.sig ]]; then key="$d/release.pub"
  fi
  if [[ -n $key ]]; then
    [[ -s $d/SHA256SUMS.sig ]] || { echo "This release is not signed, but a release key is pinned ($RELEASE_PIN): refusing."; return 1; }
    if ! { base64 -d <"$d/SHA256SUMS.sig" >"$d/.sig.bin" 2>/dev/null &&
           openssl dgst -sha256 -verify "$key" -signature "$d/.sig.bin" "$d/SHA256SUMS" >/dev/null 2>&1; }; then
      rm -f "$d/.sig.bin"; echo "Signature verification FAILED."; return 1
    fi
    rm -f "$d/.sig.bin"; echo "Signature OK."
  else
    echo "Note: this release is not signed (no release key known yet): checksums only."
  fi
  return 0
}

fetch_payload() { # destdir
  local d="$1" f
  mkdir -p "$d"
  if [[ -n $FROM_DIR ]]; then
    for f in "${FILES[@]}"; do
      [[ -f $FROM_DIR/$f ]] || { echo "Missing $FROM_DIR/$f"; return 1; }
      cp "$FROM_DIR/$f" "$d/$f"
    done
    for f in release.pub SHA256SUMS.sig SHA256SUMS; do [[ -f $FROM_DIR/$f ]] && cp "$FROM_DIR/$f" "$d/$f"; done
    return 0
  fi
  [[ $BASE == https://* || $BASE == file://* ]] || { echo "Refusing to download from a non-https source: $BASE"; return 1; }
  if [[ $TESTMODE != 1 ]]; then
    command -v curl >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 || {
      apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssl >/dev/null 2>&1; }
  fi
  echo "Downloading from $BASE ..."
  for f in "${FILES[@]}" SHA256SUMS; do
    dl "$BASE/$f" "$d/$f" || { echo "Download failed: $BASE/$f"; return 1; }
  done
  for f in release.pub SHA256SUMS.sig; do dl "$BASE/$f" "$d/$f" 2>/dev/null || rm -f "$d/$f"; done
  verify_payload "$d" || { echo "Verification FAILED - aborting, nothing was installed."; return 1; }
  VERIFIED=1
}

# pin_release_key SRCDIR : remember the signing key of the first signed release; later releases must match it.
# A release verified against the pinned key may rotate it (it is listed in the signed SHA256SUMS).
pin_release_key() {
  local src="$1"
  [[ -f $src/release.pub ]] || return 0
  if [[ ! -f $RELEASE_PIN ]]; then
    install -d -m 700 "$ETC"; install -m 644 "$src/release.pub" "$RELEASE_PIN"
    echo "Pinned the release signing key: later updates must be signed by it."
  elif ! cmp -s "$src/release.pub" "$RELEASE_PIN"; then
    if [[ ${VERIFIED:-0} == 1 ]]; then
      install -m 644 "$src/release.pub" "$RELEASE_PIN"
      echo "Release signing key rotated (this release was signed by the previous key)."
    else
      echo "Warning: this folder ships a different release key than the pinned one; keeping the pinned key."
    fi
  fi
}

install_payload() { # srcdir
  mkdir -p "$OPT" "$VAR" "$(dirname "$BIN")"
  install -m 755 "$1/vpn" "$BIN"
  install -m 644 "$1/bot.py" "$OPT/bot.py"
  install -m 644 "$1/ikev2lib.py" "$OPT/ikev2lib.py"
  install -m 644 "$1/VERSION" "$OPT/VERSION"
  pin_release_key "$1"
}

write_result() { # ok version log
  [[ ${NOTIFY:-0} == 1 ]] || return 0
  mkdir -p "$VAR"
  python3 -c 'import json,sys; print(json.dumps({"ok": sys.argv[1]=="1", "version": sys.argv[2], "log": sys.argv[3]}))' "$1" "$2" "$3" >"$VAR/upgrade_result"
}

do_upgrade() { # srcdir
  local src="$1" prev="$VAR/prev" old="unknown" new log="$VAR/upgrade.log"
  [[ -x $BIN ]] || { echo "Nothing to upgrade (not installed)."; exit 1; }
  old=$(cat "$OPT/VERSION" 2>/dev/null || echo unknown)
  new=$(tr -d '[:space:]' <"$src/VERSION")
  echo "==> Upgrading $old -> $new"
  rm -rf "$prev"; mkdir -p "$prev"
  cp -a "$BIN" "$prev/vpn"
  cp -a "$OPT/bot.py" "$OPT/ikev2lib.py" "$prev/" 2>/dev/null || true
  echo "$old" >"$prev/VERSION"
  "$BIN" backup >/dev/null 2>&1 || true          # safety backup with the old tool
  install_payload "$src"
  : >"$log"
  if "$BIN" migrate >>"$log" 2>&1 && "$BIN" selftest >>"$log" 2>&1; then
    systemctl restart ikev2-bot >/dev/null 2>&1 || true
    write_result 1 "$new" ""
    echo "==> Upgrade complete: now v$new"
    return 0
  fi
  echo "==> Upgrade FAILED, rolling back to v$old" >&2
  tail -n 20 "$log" >&2
  install -m 755 "$prev/vpn" "$BIN"
  [[ -f $prev/bot.py ]] && install -m 644 "$prev/bot.py" "$OPT/bot.py"
  [[ -f $prev/ikev2lib.py ]] && install -m 644 "$prev/ikev2lib.py" "$OPT/ikev2lib.py"
  printf '%s\n' "$old" >"$OPT/VERSION"
  "$BIN" migrate >>"$log" 2>&1 || true
  write_result 0 "$old" "$(tail -n 15 "$log")"
  systemctl restart ikev2-bot >/dev/null 2>&1 || true
  return 1
}

# ------------------------------------------------------------------ args
UPGRADE=0; NOTIFY=0; YES=0; FROM_DIR=""; VERIFIED=0
MODE=ip; DOMAIN=""; EMAIL=""; IP=""; USER_NAME="user1"; PASS="${IKEV2MGR_PASS:-}"
FW=""; F2B=""; AU=""; TOKEN="${IKEV2MGR_BOT_TOKEN:-}"; ADMIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upgrade) UPGRADE=1; shift ;;
    --notify) NOTIFY=1; shift ;;
    --verified) VERIFIED=1; shift ;;     # used by 'vpn update': the files were verified before this script was started
    --yes|-y) YES=1; shift ;;
    --from) FROM_DIR="$(cd "${2:-}" 2>/dev/null && pwd)" || { echo "No such folder: ${2:-}"; exit 1; }; shift 2 ;;
    --domain) DOMAIN="${2:-}"; MODE=domain; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --ip) IP="${2:-}"; shift 2 ;;
    --user) USER_NAME="${2:-}"; shift 2 ;;
    --pass) PASS="${2:-}"; shift 2 ;;
    --firewall) FW=yes; shift ;;       --no-firewall) FW=no; shift ;;
    --fail2ban) F2B=yes; shift ;;      --no-fail2ban) F2B=no; shift ;;
    --autoupdate) AU=yes; shift ;;     --no-autoupdate) AU=no; shift ;;
    --bot-token) TOKEN="${2:-}"; shift 2 ;;
    --admin-id) ADMIN="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 && $TESTMODE != 1 ]]; then
  echo "Please run as root, e.g.:"
  echo "  sudo bash -c \"\$(curl -fsSL $BASE/install.sh)\""
  exit 1
fi
if [[ $TESTMODE != 1 ]]; then command -v apt-get >/dev/null || { echo "This installer supports Debian/Ubuntu (apt) only."; exit 1; }; fi
if [[ $YES == 0 && $UPGRADE == 0 && ! -t 0 ]]; then
  echo "The wizard needs a terminal (stdin is not interactive, e.g. 'curl | bash')."
  echo "Use:  sudo bash -c \"\$(curl -fsSL $BASE/install.sh)\""
  echo "or pass --yes with options for a non-interactive install."
  exit 1
fi

TMP=$(mktemp -d); chmod 700 "$TMP"; trap 'rm -rf "$TMP"' EXIT
fetch_payload "$TMP" || exit 1
NEW_VERSION=$(tr -d '[:space:]' <"$TMP/VERSION")
[[ $NEW_VERSION =~ ^[0-9]+(\.[0-9]+)*([-.][A-Za-z0-9]+)*$ ]] || { echo "Invalid VERSION in the release: '$NEW_VERSION'"; exit 1; }

# ------------------------------------------------------------------ upgrade path
if [[ $UPGRADE == 1 ]]; then
  if [[ -z $FROM_DIR ]]; then ( . "$TMP/vpn"; cfg_set UPDATE_BASE "$BASE" ) 2>/dev/null; fi
  do_upgrade "$TMP"; exit $?
fi

if [[ -f $ETC/config.env && -x $BIN ]]; then
  old=$(cat "$OPT/VERSION" 2>/dev/null || echo unknown)
  if [[ $YES == 1 || ! -t 0 ]]; then do_upgrade "$TMP"; exit $?; fi
  echo "An existing installation (v$old) was found."
  read -rp "Upgrade the tool to v$NEW_VERSION? Users and settings are kept. [Y/n] " a
  if [[ ${a:-Y} =~ ^[Yy]$ ]]; then do_upgrade "$TMP"; exit $?; fi
  echo "Nothing changed."; exit 0
fi

# ------------------------------------------------------------------ fresh install
# shellcheck disable=SC1091
. "$TMP/vpn"      # load helper functions and the text-UI helpers (ui_*, detect_public_ip, ...); already verified above
set +e            # the wizard handles answers itself

wizard() {
  local a detected ssh
  ui_header "IKEv2 VPN installer  v$NEW_VERSION"
  echo
  echo " Installs an IKEv2 VPN (strongSwan) with a text menu (sudo vpn),"
  echo " client profiles and an optional admin-only Telegram bot."
  echo " Press Ctrl+C at any time to cancel."
  echo
  echo " How will clients reach this server?"
  ui_item 1 "No domain - use the server IP (own CA)"
  ui_item 2 "I have a domain (Let's Encrypt)"
  echo
  a=$(ui_ask "Select" 1); echo
  if [[ $a == 2 ]]; then
    MODE=domain
    detected=$(detect_public_ip || echo "?")
    echo
    echo " The domain's A record must point to this server ($detected)"
    echo " and TCP port 80 must be open in your cloud firewall now."
    DOMAIN=$(ui_ask "Domain name" "$DOMAIN"); echo
    [[ -n $DOMAIN ]] || { echo "Domain is required."; exit 1; }
    EMAIL=$(ui_ask "Email for Let's Encrypt (optional)" "$EMAIL"); echo
  else
    MODE=ip
  fi

  echo
  USER_NAME=$(ui_ask "First VPN username (letters, digits, _ . -)" "$USER_NAME"); echo
  [[ $USER_NAME =~ $NAME_RE ]] || { echo "Invalid username."; exit 1; }
  echo " (a strong random password will be generated)"

  ssh=$(fw_ssh_ports)
  echo
  echo " Firewall: inbound allowed = SSH ($ssh) + UDP 500/4500; the rest is dropped."
  echo " Your current SSH session stays connected. Cloud firewalls (AWS"
  echo " Security Group) are separate and must allow UDP 500/4500."
  echo " NOTE: other services on this server (web site, panels...) would be blocked too;"
  echo "       add their ports later with: vpn set FW_EXTRA_TCP 443,8080"
  if ui_yesno "Enable the firewall?" y; then FW=yes; else FW=no; fi
  if ui_yesno "Install fail2ban (blocks SSH brute-force)?" y; then F2B=yes; else F2B=no; fi
  if ui_yesno "Enable automatic security updates?" y; then AU=yes; else AU=no; fi

  echo
  if ui_yesno "Set up the admin-only Telegram bot now? (can be done later)" y; then
    echo
    echo " 1) In Telegram open @BotFather, send /newbot, copy the token."
    echo " 2) Open @userinfobot to get YOUR numeric id."
    echo " 3) Open your new bot and press Start."
    echo
    TOKEN=$(ui_ask "Bot token (Enter to skip)" "$TOKEN"); echo
    if [[ -n $TOKEN ]]; then
      ADMIN=$(ui_ask "Your numeric Telegram id" "$ADMIN"); echo
      if [[ -z $ADMIN ]] || ! bot_validate_token "$TOKEN" >/dev/null; then
        echo " Telegram rejected the token (or the id is empty / no internet). Bot skipped;"
        echo " set it up later from: sudo vpn"
        TOKEN=""; ADMIN=""
      fi
    fi
  fi

  echo
  echo " ---------------- summary ----------------"
  echo "  Mode        : $MODE ${DOMAIN:+($DOMAIN)}"
  echo "  First user  : $USER_NAME"
  echo "  Firewall    : $FW    fail2ban: $F2B    auto-updates: $AU"
  echo "  Telegram bot: $([[ -n $TOKEN && -n $ADMIN ]] && echo yes || echo no)"
  echo "  (existing strongSwan config is backed up first)"
  echo
  ui_yesno "Start installation?" y || { echo "Cancelled."; exit 1; }
}

if [[ $YES == 0 && -t 0 && -t 1 ]]; then
  wizard
else
  [[ -n $FW ]]  || FW=no
  [[ -n $F2B ]] || F2B=no
  [[ -n $AU ]]  || AU=no
fi
clear 2>/dev/null || true

# validate everything BEFORE anything is installed (the same rules `vpn setup` enforces)
bad() { echo "Error: $*" >&2; exit 1; }
[[ -z $IP     ]] || v_ipv4 "$IP"              || bad "invalid --ip (expected an IPv4 address)"
[[ -z $DOMAIN || $DOMAIN =~ $DOMAIN_RE ]]    || bad "invalid domain name: $DOMAIN"
[[ -z $EMAIL  || $EMAIL  =~ $EMAIL_RE  ]]    || bad "invalid email address"
[[ $USER_NAME =~ $NAME_RE ]]                 || bad "invalid username"
[[ -z $PASS   ]] || pass_check "$USER_NAME" "$PASS" || bad "$PASS_ERR"
[[ -z $TOKEN  || $TOKEN =~ $TOKEN_RE ]]      || bad "that does not look like a Telegram bot token"
[[ -z $ADMIN  || $ADMIN =~ ^[0-9]+$ ]]       || bad "--admin-id must be numeric"
[[ $MODE == ip || -n $DOMAIN ]]              || bad "domain mode needs a domain"

install_payload "$TMP"
ARGS=(setup --mode "$MODE" --user "$USER_NAME" --firewall "${FW:-no}" --fail2ban "${F2B:-no}" --autoupdate "${AU:-no}")
[[ -n $DOMAIN ]] && ARGS+=(--domain "$DOMAIN")
[[ -n $EMAIL ]]  && ARGS+=(--email "$EMAIL")
[[ -n $IP ]]     && ARGS+=(--ip "$IP")
[[ -n $TOKEN && -n $ADMIN ]] && ARGS+=(--admin-id "$ADMIN")
[[ -z $FROM_DIR ]] && ARGS+=(--update-base "$BASE")

# secrets travel in the environment of the child process, never on a command line (visible in `ps`)
IKEV2_SETUP_PASS="$PASS" IKEV2_SETUP_BOT_TOKEN="$TOKEN" "$BIN" "${ARGS[@]}"
rc=$?
echo
[[ $rc -eq 0 ]] && echo "Next: run  sudo vpn  to manage users, profiles, bot and more."
exit $rc
