#!/usr/bin/env bash
# certificates (expiry maths, auto renewal, CA), client profiles, units, bot token handling
. "$(dirname "$0")/lib.sh"

# helper: run something with the clock moved forward by N days
in_future() { # DAYS cmd...
  local SHIFT_DAYS_="$1"; shift
  ( . "$V"; date() { if [[ ${1:-} == +%s ]]; then echo $(( $(command date +%s) + 86400*SHIFT_DAYS_ )); else command date "$@"; fi; }; "$@" )
}
mkcert() { # DAYS  -> writes $T/swan/x509/server.pem
  mkdir -p "$T/swan/x509"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out "$T/swan/x509/server.pem" -days "$1" -subj "/CN=203.0.113.7" 2>/dev/null
}
sum() { sha256sum "$T/swan/x509/server.pem" | cut -c1-16; }

section "certificate expiry maths"
setup_ip
t_eq "$( . "$V"; cert_days_left )" none "no certificate -> none"
t_eq "$( . "$V"; cert_state )" missing "no certificate -> state missing"
mkcert 100
d=$( . "$V"; cert_days_left ); check "100-day cert reports 99 or 100 days" test "$d" -ge 99 -a "$d" -le 100
t_eq "$( . "$V"; cert_state )" ok "100 days -> ok"
mkcert 10; t_eq "$( . "$V"; cert_state )" expiring "10 days -> expiring"
mkcert 10
d=$(in_future 20 cert_days_left); check "expired cert gives a NEGATIVE count (-10 or -9)" test "$d" -le -9 -a "$d" -ge -11
t_eq "$(in_future 20 cert_state)" expired "20 days later -> expired"
t_eq "$(in_future 9 cert_state)" expiring "less than a day left (0 days) -> expiring, not expired"
printf 'garbage' >"$T/swan/x509/server.pem"; t_eq "$( . "$V"; cert_days_left )" none "unreadable certificate -> none"

section "cert auto: renews expiring, EXPIRED and missing certificates (bug: expired ones were skipped)"
setup_ip; mkcert 100; a=$(sum); run cert auto; t_eq "$(sum)" "$a" "valid cert (100 d) is left alone"
mkcert 10; a=$(sum); run cert auto; t_eq "$RC" 0 "cert auto exits 0"; [[ $(sum) != "$a" ]] && pass "cert expiring in 10 days is renewed" || fail "cert expiring in 10 days is renewed"
mkcert 10; a=$(sum); in_future 400 cmd_cert auto >/dev/null 2>&1; [[ $(sum) != "$a" ]] && pass "EXPIRED cert (390 days ago) is renewed" || fail "EXPIRED cert (390 days ago) is renewed"
rm -f "$T/swan/x509/server.pem"; run cert auto; check "missing cert is issued" test -s "$T/swan/x509/server.pem"
d=$( . "$V"; cert_days_left ); check "re-issued cert is valid for ~5 years" test "$d" -gt 1800
check "server key is mode 600" test "$(stat -c %a "$T/swan/private/server.key")" = 600
t_eq "$(ls -A "$T/tmp" | wc -l)" 0 "no temp files left behind after issuing"
STUB_PKI_FAIL=--issue run cert renew; check_not "failing pki makes cert renew fail" test $RC -eq 0
t_eq "$(ls -A "$T/tmp" | wc -l)" 0 "no temp key material left after a FAILED issue"
run status --kv; t_has "$OUT" "cert_state=ok" "status --kv exposes cert_state"; t_has "$OUT" "cert_days=" "status --kv exposes cert_days"; t_has "$OUT" "backup_key=no" "status --kv exposes backup_key"
mkcert 10; run status; t_has "$OUT" "days left" "status prints days left"
t_eq "$(in_future 30 cmd_status 2>&1 | grep -c 'EXPIRED')" 1 "status warns loudly when the certificate has expired"

section "CA creation"
new_env; ( . "$V"; cfg_set MODE ip; cfg_set SERVER_NAME 203.0.113.7 ) >/dev/null 2>&1
( . "$V"; pki_init_ca ) >/dev/null 2>&1
check "ca.key is mode 600" test "$(stat -c %a "$T/etc/pki/ca.key")" = 600
t_has "$(openssl x509 -in "$T/etc/pki/ca.pem" -noout -ext basicConstraints 2>&1)" "pathlen:0" "CA has pathlen:0 (cannot sign sub-CAs)"
new_env; ( . "$V"; cfg_set MODE ip; cfg_set SERVER_NAME 203.0.113.7 ) >/dev/null 2>&1
out=$(STUB_PKI_NO_PATHLEN=1 bash -c ". '$V'; pki_init_ca" 2>&1); rc=$?
t_eq "$rc" 0 "an old pki that rejects --pathlen still produces a CA"; t_has "$out" "without a path-length" "...and warns about it"
check "fallback CA file exists" test -s "$T/etc/pki/ca.pem"

section "profiles"
setup_ip; run user add alice "$GOODPW" >/dev/null
mkdir -p "$T/custom"; echo notes >"$T/custom/notes.txt"; chmod 644 "$T/custom/notes.txt"; chmod 755 "$T/custom"
run profile alice "$T/custom"; t_eq "$RC" 0 "profile into an existing folder"
t_eq "$(stat -c %a "$T/custom/notes.txt")" 644 "unrelated file in the folder keeps its permissions (bug: was chmod 600)"
t_eq "$(stat -c %a "$T/custom")" 755 "existing folder permissions untouched"
for f in alice.sswan alice.mobileconfig alice-windows.ps1 zedsecure-alice.txt README-alice.txt ca.crt; do
  t_eq "$(stat -c %a "$T/custom/$f" 2>/dev/null)" 600 "$f is mode 600"
done
run profile alice "$T/newdir/deep"; t_eq "$(stat -c %a "$T/newdir/deep")" 700 "a folder created by 'profile' is mode 700"
run profile alice; check "default export folder used" test -s "$T/exp/alice/alice.mobileconfig"
t_hasnt "$(cat "$T/custom/alice.sswan")" "$GOODPW" "the .sswan file does not contain the password"
t_has "$(cat "$T/custom/alice.mobileconfig")" "$GOODPW" "the .mobileconfig carries the password (needed by iOS)"
xmllint --noout "$T/custom/alice.mobileconfig" 2>/dev/null && pass "mobileconfig is well-formed XML" || fail "mobileconfig is well-formed XML"
python3 -c "import json,sys; json.load(open('$T/custom/alice.sswan'))" && pass ".sswan is valid JSON" || fail ".sswan is valid JSON"
t_has "$(cat "$T/custom/README-alice.txt")" "IPv6" "README warns about IPv6"
link=$(grep -o 'zedsecure://[^ ]*' "$T/custom/zedsecure-alice.txt" | head -1)
python3 - "$link" "$GOODPW" <<'PY' && pass "ZedSecure link decodes and contains the user/password/CA" || fail "ZedSecure link decodes and contains the user/password/CA"
import sys, base64, json
b = sys.argv[1].split("://", 1)[1]; b += "=" * (-len(b) % 4)
d = json.loads(base64.b64decode(b)); s = d["s"]["settings"]
assert s["password"] == sys.argv[2] and s["caCertPem"]
PY
# files must be private from the first byte (no umask window): record the mode every file had right before 'chmod'
mkdir -p "$T/shim"; cat >"$T/shim/chmod" <<'SH'
#!/usr/bin/env bash
for a in "$@"; do [[ -f $a ]] && echo "$(stat -c %a "$a") $a" >>"$STUB_STATE/chmod-before.log"; done
exec /bin/chmod "$@"
SH
chmod +x "$T/shim/chmod"; rm -rf "$T/custom2"
( umask 000; PATH="$T/shim:$PATH" "$V" profile alice "$T/custom2" >/dev/null 2>&1 )
bad=$(grep -E "custom2/(alice|zedsecure|README)" "$STUB_STATE/chmod-before.log" 2>/dev/null | grep -v '^600 ' | head -3)
[[ -z $bad ]] && pass "profile files were already 0600 before any chmod ran (even under umask 000)" || fail "profile files were already 0600 before any chmod ran" "$bad"
# password must not be in any process command line
mkdir -p "$T/pyshim"; cat >"$T/pyshim/python3" <<SH
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$T/python-argv.log"
exec /usr/bin/python3 "\$@"
SH
chmod +x "$T/pyshim/python3"; rm -f "$T/python-argv.log"
PATH="$T/pyshim:$PATH" "$V" profile alice "$T/custom3" >/dev/null 2>&1; PATH="$T/pyshim:$PATH" "$V" zed alice >/dev/null 2>&1
check "ikev2lib helper ran" test -s "$T/python-argv.log"
check_not "user password never appears in a python3 command line" grep -q "$GOODPW" "$T/python-argv.log"
run zed alice; t_has "$OUT" "zedsecure://" "vpn zed prints a link"

section "systemd units"
setup_ip; cp "$ROOT/bot.py" "$ROOT/ikev2lib.py" "$T/opt/"; cp "$V" "$T/bin/vpn"; chmod 755 "$T/bin/vpn"
( . "$T/bin/vpn"; install_units ) >/dev/null 2>&1
for u in ikev2-net.service ikev2-bot.service ikev2-certcheck.service ikev2-certcheck.timer; do check "$u written" test -s "$T/units/$u"; done
for d in NoNewPrivileges=yes PrivateTmp=yes UMask=0077 ProtectControlGroups=yes LockPersonality=yes; do
  t_has "$(cat "$T/units/ikev2-bot.service")" "$d" "bot unit has $d"
done
t_has "$(cat "$T/units/ikev2-net.service")" "ExecStart=$T/bin/vpn net apply" "net unit points at the installed script"
if command -v systemd-analyze >/dev/null 2>&1; then
  out=$(systemd-analyze verify "$T/units/ikev2-bot.service" "$T/units/ikev2-net.service" "$T/units/ikev2-certcheck.service" "$T/units/ikev2-certcheck.timer" 2>&1)
  bad=$(grep -iE "unknown (key|lvalue|section)|unknown assignment|invalid|bad |not executable|syntax" <<<"$out" | head -3)
  [[ -z $bad ]] && pass "systemd-analyze verify finds no syntax/directive problems" || fail "systemd-analyze verify finds no syntax/directive problems" "$bad"
fi

section "telegram bot management: the token never reaches a command line"
setup_ip; TOK='123456789:AAExampleTokenExampleTokenExample12'
run_in "$TOK" bot setup - 4242; t_eq "$RC" 0 "bot setup - (token on stdin) works"
t_eq "$( . "$V"; cfg_load; echo "$BOT_TOKEN:$ADMIN_ID" )" "$TOK:4242" "token and admin id stored"
check "config.env stays 600" test "$(stat -c %a "$T/etc/config.env")" = 600
run bot test; t_eq "$RC" 0 "bot test works"
check "curl was called" test -s "$T/state/curl.log"
check_not "token never appears in any curl argv" python3 - "$T/state/curl.log" "$TOK" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    d = json.loads(line)
    if any(sys.argv[2] in a for a in d["argv"]): sys.exit(0)
sys.exit(1)
PY
check "token was passed through the curl config (stdin) instead" grep -q "$TOK" "$T/state/curl.log"
for bad in 'abc' '123:short' '123456789:AAExampleTokenExampleTokenExample12"; id; "' ; do
  run bot setup "$bad" 4242; check_not "invalid token [$bad] refused" test $RC -eq 0
done
run bot setup "$TOK" 12a; check_not "non-numeric admin id refused" test $RC -eq 0
STUB_TG_BAD=1 run bot setup "$TOK" 4242; check_not "token rejected by Telegram is refused" test $RC -eq 0

summary "certs/profiles/units/bot"
