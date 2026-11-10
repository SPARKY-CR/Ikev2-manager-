#!/usr/bin/env bash
# update / installer: nothing unverified is ever executed; https only; signatures; rollback; input validation
. "$(dirname "$0")/lib.sh"

BASEURL=https://example.test/repo
mk_keys() { # DIR : two independent signing keys (good + attacker)
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/good.key" 2>/dev/null; openssl ec -in "$1/good.key" -pubout -out "$1/good.pub" 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/evil.key" 2>/dev/null; openssl ec -in "$1/evil.key" -pubout -out "$1/evil.pub" 2>/dev/null
}
# mkrel DIR VERSION [KEYNAME|-] [PUBNAME]  : build a release folder (signed with KEYNAME, shipping PUBNAME)
mkrel() {
  local d="$1" v="$2" key="${3:--}" pub="${4:-${3:--}}"
  rm -rf "$d"; mkdir -p "$d/tools"
  cp "$ROOT/install.sh" "$ROOT/vpn" "$ROOT/bot.py" "$ROOT/ikev2lib.py" "$d/"; echo "$v" >"$d/VERSION"
  [[ $pub != - ]] && cp "$KEYS/$pub.pub" "$d/release.pub"
  local list="install.sh vpn bot.py ikev2lib.py VERSION"; [[ -f $d/release.pub ]] && list="$list release.pub"
  ( cd "$d" && sha256sum $list >SHA256SUMS )
  if [[ $key != - ]]; then ( cd "$d" && openssl dgst -sha256 -sign "$KEYS/$key.key" SHA256SUMS | base64 -w0 >SHA256SUMS.sig; echo >>SHA256SUMS.sig ); fi
  rm -rf "$d/tools"
}
# installed tool = a copy of the current script
install_tool() { cp "$V" "$T/bin/vpn"; chmod 755 "$T/bin/vpn"; cp "$ROOT/bot.py" "$ROOT/ikev2lib.py" "$T/opt/"; echo "${1:-1.0.0}" >"$T/opt/VERSION"; }
upd() { OUT=$("$T/bin/vpn" update "$@" 2>&1); RC=$?; }
http_calls() { python3 -c "
import json,sys
n=0
for l in open('$T/state/curl.log'):
    u=json.loads(l)['url'] or ''
    if u.startswith('http://'): n+=1
print(n)" 2>/dev/null || echo 0; }

KEYS=$(mktemp -d "$BASE_TMP/ikev2keys.XXXXXX"); mk_keys "$KEYS"; trap 'rm -rf "$KEYS"; cleanup_env' EXIT

section "https only"
setup_ip; install_tool; mkrel "$T/rel" 9.0.0
export STUB_HTTPS_MAP="$BASEURL=$T/rel"
upd --base http://example.test/repo --save-only; check_not "plain http:// update source refused" test $RC -eq 0; t_has "$OUT" "https" "...with an explanation"
for bad in 'ftp://x/y' 'https://x/y;reboot' 'https://x/$(id)' 'https://x/`id`' 'https://x y' 'javascript:alert(1)' ''; do
  upd --base "$bad" --save-only; check_not "update source [$bad] refused" test $RC -eq 0
done
( . "$T/bin/vpn"; cfg_set UPDATE_BASE http://example.test/repo ) >/dev/null 2>&1
upd --yes; check_not "an http:// source saved by an older version is refused at update time" test $RC -eq 0; t_has "$OUT" "insecure" "...and called insecure"
t_eq "$(http_calls)" 0 "no request was ever made over plain http"
check_not "nothing was installed" grep -q 9.0.0 "$T/opt/VERSION"
upd --check; check_not "--check refuses an http source too" test $RC -eq 0
upd --base "$BASEURL" --save-only; t_eq "$RC" 0 "https source accepted"
upd --check; t_eq "$RC" 0 "--check works"; t_has "$OUT" "installed=1.0.0" "check: installed"; t_has "$OUT" "latest=9.0.0" "check: latest"
t_eq "$(python3 -c "
import json
print(sum(1 for l in open('$T/state/curl.log') if 'SHA256SUMS' in (json.loads(l)['url'] or '')))")" 0 "--check downloads only VERSION"
protos=$(python3 -c "
import json
for l in open('$T/state/curl.log'): print(' '.join(json.loads(l)['argv']))")
t_has "$protos" "--proto =https --proto-redir =https" "curl is restricted with --proto / --proto-redir"

section "unsigned release (no key pinned yet): checksums are enforced"
setup_ip; install_tool; mkrel "$T/rel" 9.0.0; export STUB_HTTPS_MAP="$BASEURL=$T/rel"; upd --base "$BASEURL" --save-only >/dev/null
upd --yes; t_eq "$RC" 0 "update succeeds"; t_has "$OUT" "not signed" "...and warns that the release is unsigned"
t_eq "$(cat "$T/opt/VERSION")" 9.0.0 "VERSION updated"; check "installed script is the release's script" cmp "$T/bin/vpn" "$T/rel/vpn"
check "bot + lib installed" cmp "$T/opt/bot.py" "$T/rel/bot.py"
check_not "no release key got pinned (release ships none)" test -e "$T/etc/release.pub"
t_eq "$(ls -A "$T/tmp" | wc -l)" 0 "download folder removed"
upd --yes; t_has "$OUT" "Already up to date" "same version: nothing to do"

setup_ip; install_tool; mkrel "$T/rel" 9.0.0; export STUB_HTTPS_MAP="$BASEURL=$T/rel"; upd --base "$BASEURL" --save-only >/dev/null
echo "# tampered after checksums were made" >>"$T/rel/vpn"
upd --yes; check_not "tampered vpn script refused" test $RC -eq 0; t_has "$OUT" "checksum mismatch" "...checksum mismatch reported"
t_eq "$(cat "$T/opt/VERSION")" 1.0.0 "installed version unchanged"; check_not "installed script unchanged" cmp -s "$T/bin/vpn" "$T/rel/vpn"
mkrel "$T/rel" 9.0.0; echo "# evil" >>"$T/rel/install.sh"; upd --yes; check_not "tampered install.sh refused (it is covered by the checksums too)" test $RC -eq 0
mkrel "$T/rel" 9.0.0; echo "# evil" >>"$T/rel/bot.py"; upd --yes; check_not "tampered bot.py refused" test $RC -eq 0
mkrel "$T/rel" 9.0.0; sed -i '/ bot.py$/d' "$T/rel/SHA256SUMS"; upd --yes; check_not "file missing from SHA256SUMS refused" test $RC -eq 0
mkrel "$T/rel" 9.0.0; rm "$T/rel/ikev2lib.py"; upd --yes; check_not "missing file in the release refused" test $RC -eq 0
mkrel "$T/rel" 9.0.0; rm "$T/rel/SHA256SUMS"; upd --yes; check_not "missing SHA256SUMS refused" test $RC -eq 0
mkrel "$T/rel" 'not a version'; upd --yes; check_not "garbage VERSION refused" test $RC -eq 0
t_eq "$(cat "$T/opt/VERSION")" 1.0.0 "still the original version after all refused updates"

section "signed releases: key pinned on first use, then mandatory"
setup_ip; install_tool; export STUB_HTTPS_MAP="$BASEURL=$T/rel"; mkrel "$T/rel" 9.0.0 good; upd --base "$BASEURL" --save-only >/dev/null
upd --yes; t_eq "$RC" 0 "first signed release installs"; t_has "$OUT" "Signature OK" "...signature verified"
check "release key pinned at install time" cmp "$T/etc/release.pub" "$KEYS/good.pub"
mkrel "$T/rel" 9.0.1 good; upd --yes; t_eq "$RC" 0 "next release signed with the pinned key installs"; t_eq "$(cat "$T/opt/VERSION")" 9.0.1 "...at 9.0.1"
mkrel "$T/rel" 9.0.2 -; upd --yes; check_not "UNSIGNED release refused once a key is pinned (no downgrade to checksums-only)" test $RC -eq 0; t_has "$OUT" "pinned" "...says why"
mkrel "$T/rel" 9.0.2 evil evil; upd --yes; check_not "release signed by ANOTHER key (and shipping that key) refused" test $RC -eq 0; t_has "$OUT" "signature verification FAILED" "...signature failure reported"
mkrel "$T/rel" 9.0.2 good; echo "9.0.2 " >"$T/rel/VERSION"; upd --yes; check_not "files changed after signing (checksums + signature no longer match) refused" test $RC -eq 0
mkrel "$T/rel" 9.0.2 good; ( cd "$T/rel"; sha256sum install.sh vpn bot.py ikev2lib.py VERSION >SHA256SUMS ); upd --yes; check_not "re-made SHA256SUMS without a new signature refused" test $RC -eq 0
mkrel "$T/rel" 9.0.2 good; echo "AAAA" >"$T/rel/SHA256SUMS.sig"; upd --yes; check_not "garbage signature refused" test $RC -eq 0
mkrel "$T/rel" 9.0.2 good; rm -f "$T/rel/SHA256SUMS.sig"; upd --yes; check_not "signature stripped by a man in the middle refused" test $RC -eq 0
t_eq "$(cat "$T/opt/VERSION")" 9.0.1 "installed version still 9.0.1"
check "pinned key unchanged by the attacks" cmp "$T/etc/release.pub" "$KEYS/good.pub"
mkrel "$T/rel" 9.0.0 good; upd --yes; check_not "validly signed OLDER release refused (rollback attack)" test $RC -eq 0; t_has "$OUT" "older" "...says it is older"
upd --yes --force; t_eq "$RC" 0 "...unless --force is given"

section "key rotation (new key introduced by a release signed with the old key)"
setup_ip; install_tool; export STUB_HTTPS_MAP="$BASEURL=$T/rel"; mkrel "$T/rel" 9.0.0 good; upd --base "$BASEURL" --save-only >/dev/null; upd --yes >/dev/null
mkrel "$T/rel" 9.1.0 good evil; upd --yes; t_eq "$RC" 0 "release signed by the old key that ships a new key installs"
check "pinned key is now the new one" cmp "$T/etc/release.pub" "$KEYS/evil.pub"
mkrel "$T/rel" 9.2.0 evil evil; upd --yes; t_eq "$RC" 0 "next release signed by the new key installs"
mkrel "$T/rel" 9.3.0 good good; upd --yes; check_not "the old key no longer works" test $RC -eq 0

section "local folder updates"
setup_ip; install_tool; mkrel "$T/rel" 9.0.0 good; upd "$T/rel" --yes; t_eq "$RC" 0 "update from a local folder"; t_eq "$(cat "$T/opt/VERSION")" 9.0.0 "...installed"
check "first local folder with a key pins it (trust on first use)" cmp "$T/etc/release.pub" "$KEYS/good.pub"
mkrel "$T/rel2" 9.1.0 evil; upd "$T/rel2" --yes; t_eq "$RC" 0 "a local folder with ANOTHER key still installs (admin chose it)..."
check "...but never replaces the pinned key" cmp "$T/etc/release.pub" "$KEYS/good.pub"; t_has "$OUT" "keeping the pinned key" "...and says so"
echo "#!/bin/bash" >"$T/installer-only.sh"; upd "$T/installer-only.sh" --yes; check_not "the old 'update from installer FILE' mode is gone" test $RC -eq 0; t_has "$OUT" "folder" "...and points to a folder"
upd /nonexistent --yes; check_not "missing folder refused" test $RC -eq 0

section "automatic rollback when the new version is broken"
setup_ip; install_tool; mkrel "$T/rel" 9.0.0; export STUB_HTTPS_MAP="$BASEURL=$T/rel"
printf '\nthis is ( not valid bash\n' >>"$T/rel/vpn"; ( cd "$T/rel" && sha256sum install.sh vpn bot.py ikev2lib.py VERSION >SHA256SUMS )
upd --base "$BASEURL" --save-only >/dev/null; cp "$T/bin/vpn" "$T/vpn.before"; upd --yes
check_not "a broken release reports failure" test $RC -eq 0; t_has "$OUT" "rolling back" "...and rolls back"
check "old script restored byte-for-byte" cmp "$T/bin/vpn" "$T/vpn.before"; t_eq "$(cat "$T/opt/VERSION")" 1.0.0 "old VERSION restored"

section "install.sh run directly (the curl | bash path)"
setup_ip; install_tool; mkrel "$T/rel" 9.0.0 good; export STUB_HTTPS_MAP="$BASEURL=$T/rel"
run_i() { OUT=$(IKEV2MGR_BASE="$1" bash "$ROOT/install.sh" "${@:2}" 2>&1); RC=$?; }
run_i http://example.test/repo --upgrade; check_not "install.sh refuses an http:// base" test $RC -eq 0; t_has "$OUT" "non-https" "...says why"
run_i "$BASEURL" --upgrade; t_eq "$RC" 0 "install.sh --upgrade from a verified https base"; t_eq "$(cat "$T/opt/VERSION")" 9.0.0 "...installed"
mkrel "$T/rel" 9.0.1 good; echo "# x" >>"$T/rel/vpn"; run_i "$BASEURL" --upgrade; check_not "install.sh rejects a tampered file" test $RC -eq 0; t_eq "$(cat "$T/opt/VERSION")" 9.0.0 "...nothing installed"
mkrel "$T/rel" 9.0.1 evil evil; run_i "$BASEURL" --upgrade; check_not "install.sh rejects a release signed by another key (key pinned)" test $RC -eq 0
mkrel "$T/rel" 9.0.1 -; run_i "$BASEURL" --upgrade; check_not "install.sh rejects an unsigned release once a key is pinned" test $RC -eq 0
mkrel "$T/rel" 9.0.1 good; run_i "$BASEURL" --upgrade; t_eq "$RC" 0 "install.sh accepts the next properly signed release"

section "fresh install through install.sh (integration, no root/apt needed in test mode)"
new_env; export STUB_HTTPS_MAP="$BASEURL=$T/rel"; mkrel "$T/rel" 9.0.0 good
TOK='123456789:AAExampleTokenExampleTokenExample12'
tr_out=$(IKEV2MGR_PASS="$GOODPW" IKEV2MGR_BOT_TOKEN="$TOK" IKEV2MGR_BASE="$BASEURL" bash -x "$ROOT/install.sh" --yes --ip 203.0.113.7 --user admin1 --admin-id 4242 --firewall 2>&1); rc=$?
t_eq "$rc" 0 "fresh install succeeds"
check "tool installed" test -x "$T/bin/vpn"; t_eq "$(awk -F: '$1=="admin1"{print $2}' "$T/etc/users.db")" "$GOODPW" "first user got the password given through the environment"
t_eq "$( . "$ROOT/vpn"; cfg_load; echo "$BOT_TOKEN/$ADMIN_ID/$FIREWALL/$MODE/$SERVER_NAME" )" "$TOK/4242/yes/ip/203.0.113.7" "bot token, admin id, firewall, mode and address stored"
setup_line=$(grep -F "$T/bin/vpn setup" <<<"$tr_out" | head -1); argv_part=${setup_line#*"$T/bin/vpn setup"}
[[ -n $setup_line ]] && pass "found the 'vpn setup' call in the trace" || fail "found the 'vpn setup' call in the trace"
t_hasnt "$argv_part" "$GOODPW" "the password is NOT on the command line of 'vpn setup'"
t_hasnt "$argv_part" "$TOK" "the bot token is NOT on the command line of 'vpn setup'"
check "release key pinned from the signed release" cmp "$T/etc/release.pub" "$KEYS/good.pub"
check "swanctl.conf was generated" grep -q 'id = admin1' "$T/swan/swanctl.conf"
t_eq "$(stat -c %a "$T/etc/users.db")" 600 "users.db is 0600"

section "install.sh validates everything before touching the system"
for args in "--ip 999.1.1.1" "--ip abc" "--domain bad_domain" "--domain a.b;reboot" "--user a:b" "--user x y" "--email nope" "--pass weak" "--pass passwordpassword" "--bot-token abc --admin-id 1" "--admin-id 12a" ; do
  new_env; export STUB_HTTPS_MAP="$BASEURL=$T/rel"
  OUT=$(IKEV2MGR_BASE="$BASEURL" bash "$ROOT/install.sh" --yes --ip 203.0.113.7 $args 2>&1); RC=$?
  check_not "[$args] refused" test $RC -eq 0
  check_not "[$args] nothing was installed" test -e "$T/bin/vpn"
done
new_env; OUT=$(bash "$ROOT/install.sh" --help 2>&1); t_eq "$?" 0 "--help works"; t_has "$OUT" "--bot-token" "usage lists options"
OUT=$(bash "$ROOT/install.sh" --bogus 2>&1); check_not "unknown option refused" test $? -eq 0

section "release.sh (maintainer tool)"
new_env; R="$T/repo"; mkdir -p "$R/tools"; cp "$ROOT/install.sh" "$ROOT/vpn" "$ROOT/bot.py" "$ROOT/ikev2lib.py" "$ROOT/VERSION" "$R/"; cp "$ROOT/tools/release.sh" "$R/tools/"
export RELEASE_KEY="$T/maint/release.key"
out=$(cd "$R" && bash tools/release.sh init 2>&1); t_eq "$?" 0 "init"; check "private key created (0600)" test "$(stat -c %a "$RELEASE_KEY")" = 600; check "release.pub written to the repo" test -s "$R/release.pub"
out=$(cd "$R" && bash tools/release.sh init 2>&1); check_not "init never overwrites an existing key" test $? -eq 0
out=$(cd "$R" && bash tools/release.sh sign 2>&1); t_eq "$?" 0 "sign"; t_has "$out" "OK: checksums and signature are valid" "sign verifies its own output"
out=$(cd "$R" && bash tools/release.sh verify 2>&1); t_eq "$?" 0 "verify"
check "SHA256SUMS lists install.sh and release.pub" bash -c "grep -q ' install.sh$' '$R/SHA256SUMS' && grep -q ' release.pub$' '$R/SHA256SUMS'"
echo "# tamper" >>"$R/vpn"; out=$(cd "$R" && bash tools/release.sh verify 2>&1); check_not "verify detects a modified file" test $? -eq 0
if command -v shasum >/dev/null 2>&1; then   # macOS/BSD maintainers: same result with shasum instead of sha256sum
  R3="$T/repo3"; mkdir -p "$R3/tools"; cp "$ROOT/install.sh" "$ROOT/vpn" "$ROOT/bot.py" "$ROOT/ikev2lib.py" "$ROOT/VERSION" "$R3/"; cp "$ROOT/tools/release.sh" "$R3/tools/"
  out=$(cd "$R3" && RELEASE_HASH="shasum -a 256" RELEASE_KEY="$T/maint3/key" bash tools/release.sh init 2>&1 && RELEASE_HASH="shasum -a 256" RELEASE_KEY="$T/maint3/key" bash tools/release.sh sign 2>&1); t_eq "$?" 0 "release.sh works with shasum (macOS) as well"
  check "sums made with shasum verify with sha256sum" bash -c "cd '$R3' && sha256sum -c SHA256SUMS >/dev/null"
fi
# the real updater accepts what release.sh produces (new scratch env; the maintainer key lives outside it)
MAINT=$(mktemp -d "$BASE_TMP/ikev2maint.XXXXXX"); export RELEASE_KEY="$MAINT/release.key"
setup_ip; install_tool; R2="$T/repo2"; mkdir -p "$R2/tools"; cp "$ROOT/install.sh" "$ROOT/vpn" "$ROOT/bot.py" "$ROOT/ikev2lib.py" "$R2/"; echo 9.9.9 >"$R2/VERSION"; cp "$ROOT/tools/release.sh" "$R2/tools/"
( cd "$R2" && bash tools/release.sh init >/dev/null 2>&1 && bash tools/release.sh sign >/dev/null 2>&1 ); t_eq "$?" 0 "release.sh init+sign on a fresh repo copy"
export STUB_HTTPS_MAP="$BASEURL=$R2"
upd --base "$BASEURL" --save-only >/dev/null; upd --yes; t_eq "$RC" 0 "'vpn update' accepts a release produced by tools/release.sh"; t_has "$OUT" "Signature OK" "...and verifies its signature"
unset RELEASE_KEY; rm -rf "$MAINT"

summary "update/installer"
