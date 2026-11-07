#!/usr/bin/env bash
# IKEV2MGR-INSTALLER
# ikev2-manager: IKEv2/strongSwan VPN installer + text-menu manager + Telegram bot.
# Downloads the tool files from GitHub (or --from DIR), verifies SHA256SUMS, installs.
set -uo pipefail

# Where the files come from. Replace SPARKY-CR/Ikev2-manager- with your GitHub repo
# (or export IKEV2MGR_BASE / IKEV2MGR_REPO before running).
IKEV2MGR_REPO="${IKEV2MGR_REPO:-SPARKY-CR/Ikev2-manager-}"
IKEV2MGR_BRANCH="${IKEV2MGR_BRANCH:-main}"
BASE="${IKEV2MGR_BASE:-https://raw.githubusercontent.com/$IKEV2MGR_REPO/$IKEV2MGR_BRANCH}"
FILES=(vpn bot.py ikev2lib.py VERSION)

ETC=/etc/ikev2
VAR=/var/lib/ikev2
OPT=/opt/ikev2
BIN=/usr/local/bin/vpn

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
  --pass PASSWORD        its password (default: random)
  --firewall | --no-firewall       allow only SSH + VPN inbound
  --fail2ban | --no-fail2ban       protect SSH with fail2ban
  --autoupdate | --no-autoupdate   automatic security updates
  --bot-token TOKEN --admin-id ID  enable the admin-only Telegram bot
EOF
}

fetch_payload() { # destdir
  local d="$1" f
  mkdir -p "$d"
  if [[ -n $FROM_DIR ]]; then
    for f in "${FILES[@]}"; do
      [[ -f $FROM_DIR/$f ]] || { echo "Missing $FROM_DIR/$f"; return 1; }
      cp "$FROM_DIR/$f" "$d/$f"
    done
    return 0
  fi
  if [[ $BASE == *SPARKY-CR/Ikev2-manager-* ]]; then
    echo "This installer has no download source yet."
    echo "Set it:  IKEV2MGR_REPO=youruser/yourrepo sudo -E bash install.sh"
    echo "or use a cloned repo:  sudo bash install.sh --from /path/to/repo"
    return 1
  fi
  command -v curl >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y curl >/dev/null 2>&1; }
  echo "Downloading from $BASE ..."
  for f in "${FILES[@]}" SHA256SUMS; do
    curl -fsSL --max-time 60 "$BASE/$f" -o "$d/$f" || { echo "Download failed: $BASE/$f"; return 1; }
  done
  ( cd "$d" && sha256sum -c SHA256SUMS --quiet 2>/dev/null ) || { echo "Checksum verification FAILED - aborting."; return 1; }
}

install_payload() { # srcdir
  mkdir -p "$OPT" "$VAR" "$(dirname "$BIN")"
  install -m 755 "$1/vpn" "$BIN"
  install -m 644 "$1/bot.py" "$OPT/bot.py"
  install -m 644 "$1/ikev2lib.py" "$OPT/ikev2lib.py"
  install -m 644 "$1/VERSION" "$OPT/VERSION"
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
UPGRADE=0; NOTIFY=0; YES=0; FROM_DIR=""
MODE=ip; DOMAIN=""; EMAIL=""; IP=""; USER_NAME="user1"; PASS=""
FW=""; F2B=""; AU=""; TOKEN=""; ADMIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upgrade) UPGRADE=1; shift ;;
    --notify) NOTIFY=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --from) FROM_DIR="$(cd "$2" 2>/dev/null && pwd)" || { echo "No such folder: $2"; exit 1; }; shift 2 ;;
    --domain) DOMAIN="$2"; MODE=domain; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --ip) IP="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --pass) PASS="$2"; shift 2 ;;
    --firewall) FW=yes; shift ;;       --no-firewall) FW=no; shift ;;
    --fail2ban) F2B=yes; shift ;;      --no-fail2ban) F2B=no; shift ;;
    --autoupdate) AU=yes; shift ;;     --no-autoupdate) AU=no; shift ;;
    --bot-token) TOKEN="$2"; shift 2 ;;
    --admin-id) ADMIN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root, e.g.:"
  echo "  sudo bash -c \"\$(curl -fsSL $BASE/install.sh)\""
  exit 1
fi
command -v apt-get >/dev/null || { echo "This installer supports Debian/Ubuntu (apt) only."; exit 1; }
if [[ $YES == 0 && $UPGRADE == 0 && ! -t 0 ]]; then
  echo "The wizard needs a terminal (stdin is not interactive, e.g. 'curl | bash')."
  echo "Use:  sudo bash -c \"\$(curl -fsSL $BASE/install.sh)\""
  echo "or pass --yes with options for a non-interactive install."
  exit 1
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fetch_payload "$TMP" || exit 1
NEW_VERSION=$(tr -d '[:space:]' <"$TMP/VERSION")

# ------------------------------------------------------------------ upgrade path
if [[ $UPGRADE == 1 ]]; then
  if [[ -z $FROM_DIR && $BASE != *SPARKY-CR/Ikev2-manager-* ]]; then ( . "$TMP/vpn"; cfg_set UPDATE_BASE "$BASE" ) 2>/dev/null; fi
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
. "$TMP/vpn"      # load helper functions and the text-UI helpers (ui_*, detect_public_ip, ...)
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

install_payload "$TMP"
ARGS=(setup --mode "$MODE" --user "$USER_NAME" --firewall "${FW:-no}" --fail2ban "${F2B:-no}" --autoupdate "${AU:-no}")
[[ -n $DOMAIN ]] && ARGS+=(--domain "$DOMAIN")
[[ -n $EMAIL ]]  && ARGS+=(--email "$EMAIL")
[[ -n $IP ]]     && ARGS+=(--ip "$IP")
[[ -n $PASS ]]   && ARGS+=(--pass "$PASS")
[[ -n $TOKEN && -n $ADMIN ]] && ARGS+=(--bot-token "$TOKEN" --admin-id "$ADMIN")
[[ -z $FROM_DIR && $BASE != *SPARKY-CR/Ikev2-manager-* ]] && ARGS+=(--update-base "$BASE")

"$BIN" "${ARGS[@]}"
rc=$?
echo
[[ $rc -eq 0 ]] && echo "Next: run  sudo vpn  to manage users, profiles, bot and more."
exit $rc
