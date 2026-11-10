#!/usr/bin/env bash
# Config file handling, users DB, password policy, locking, rollback on failed apply
. "$(dirname "$0")/lib.sh"

section "config.env: safe parsing / writing"
setup_ip
out=$( . "$V"; cfg_set DOMAIN "it's a \"test\" \$HOME \`id\` x"; cfg_load; printf '%s' "$DOMAIN" )
t_eq "$out" "it's a \"test\" \$HOME \`id\` x" "cfg_set/cfg_load round-trip special characters"
( . "$V"; cfg_set DOMAIN "line1
line2" ) >/dev/null 2>&1; rc=$?
check_not "cfg_set refuses values with a newline" test $rc -eq 0
out=$( . "$V"; cfg_load; printf '%s' "$DOMAIN" )
t_eq "$out" "it's a \"test\" \$HOME \`id\` x" "a refused value leaves the old value untouched"
printf '%s\n' "FOO=\$(touch $T/pwned)" "MODE=\$(touch $T/pwned2)" >>"$T/etc/config.env"
( . "$V"; cfg_load ) >/dev/null 2>&1
check_not "config.env is never executed as shell code" test -e "$T/pwned" -o -e "$T/pwned2"
check "config.env is mode 600" test "$(stat -c %a "$T/etc/config.env")" = 600
out=$( . "$V"; cfg_set EMAIL a@b.co; cfg_set EMAIL c@d.co; grep -c '^EMAIL=' "$T/etc/config.env" )
t_eq "$out" "1" "cfg_set replaces (no duplicate keys)"

section "users: add / disable / delete + password policy"
setup_ip
run user add alice "$GOODPW"; t_eq "$RC" 0 "user add with a strong password"
check "users.db is mode 600" test "$(stat -c %a "$T/etc/users.db")" = 600
check "swanctl.conf is mode 600" test "$(stat -c %a "$T/swan/swanctl.conf")" = 600
grep -q "id = alice" "$T/swan/swanctl.conf" && pass "user appears in swanctl.conf" || fail "user appears in swanctl.conf"
run user add alice "$GOODPW"; t_has "$OUT" "already exists" "duplicate user refused"
for bad in 'a:b' 'x y' '../etc' '-rf' ''; do
  run user add "$bad" "$GOODPW"; check_not "invalid username [$bad] refused" test $RC -eq 0
done
for pw in 'short1!' 'has"quote12345' 'has\back123456' 'semi;colon1234' 'with space1234' 'aaaaaaaaaaaa' '123456789012' 'abcdefghijkl' 'password1234' 'Qwerty123456' 'xxbobxx-Pass9!z'; do
  run user add bob "$pw"; check_not "weak/invalid password [$pw] refused" test $RC -eq 0
done
check_not "refused password did not create the user" grep -q '^bob:' "$T/etc/users.db"
run user add bob; t_eq "$RC" 0 "auto-generated password accepted"
pw=$(awk -F: '$1=="bob"{print $2}' "$T/etc/users.db"); t_eq "${#pw}" 16 "generated password has 16 chars"
run_in "$GOODPW" user add carol --stdin --plain; t_eq "$RC" 0 "password can be read from stdin"
t_eq "$(awk -F: '$1=="carol"{print $2}' "$T/etc/users.db")" "$GOODPW" "stdin password stored"
run_in "New-Passw0rd.zz9" user passwd carol --stdin --plain
t_eq "$(awk -F: '$1=="carol"{print $2}' "$T/etc/users.db")" "New-Passw0rd.zz9" "passwd --stdin changes the password"
run user disable alice; t_eq "$RC" 0 "disable ok"
grep -q "id = alice" "$T/swan/swanctl.conf" && fail "disabled user removed from swanctl.conf" || pass "disabled user removed from swanctl.conf"
run user enable alice; grep -q "id = alice" "$T/swan/swanctl.conf" && pass "re-enabled user is back" || fail "re-enabled user is back"
run user del bob; t_eq "$RC" 0 "delete ok"; grep -q '^bob:' "$T/etc/users.db" && fail "deleted user gone from users.db" || pass "deleted user gone from users.db"
# a legacy user (8-11 char password from an old version) must keep working
printf 'legacy:Oldpass12:enabled:1700000000\n' >>"$T/etc/users.db"; run user enable legacy
grep -q "id = legacy" "$T/swan/swanctl.conf" && pass "legacy 8-11 char passwords are still honoured" || fail "legacy 8-11 char passwords are still honoured"
# malformed lines in users.db must never reach swanctl.conf
printf '%s\n' '1' 'evil name:Pass1234567x:enabled:1' 'x:pw"} secrets {:enabled:1' 'extra:Pass1234567x:enabled:1:more' >>"$T/etc/users.db"; run user enable alice
check_not "malformed users.db lines never reach swanctl.conf (name with space)" grep -q 'evil' "$T/swan/swanctl.conf"
check_not "malformed users.db lines never reach swanctl.conf (5 fields)" grep -q 'id = extra' "$T/swan/swanctl.conf"
t_eq "$(grep -c '^secrets' "$T/swan/swanctl.conf")" 1 "no injected second secrets block"
t_eq "$(grep -cE '^  eap-[0-9]+ \{' "$T/swan/swanctl.conf")" "$(awk -F: 'NF==4 && $3=="enabled" && length($1)<=32 && $1 ~ /^[A-Za-z0-9][A-Za-z0-9_.-]*$/ && length($2)>=8 && $2 ~ /^[A-Za-z0-9._@+=,!%^*~-]+$/' "$T/etc/users.db" | wc -l)" "only well-formed enabled users get a secret"

section "failed apply must NOT be reported as success (user del/disable/add/passwd)"
setup_ip; run user add alice "$GOODPW"; run user add bob "$GOODPW"
mkdir -p "$T/etc/custom"; echo "BADTOKEN = 1" >"$T/etc/custom/connection.conf"; export IKEV2_TEST_FAIL=BADTOKEN
cp "$T/etc/users.db" "$T/users.before"; cp "$T/swan/swanctl.conf" "$T/swanctl.before"
run user disable alice; check_not "disable returns non-zero when swanctl rejects the config" test $RC -eq 0
run user del bob;       check_not "del returns non-zero when swanctl rejects the config" test $RC -eq 0
run user add dave "$GOODPW"; check_not "add returns non-zero when swanctl rejects the config" test $RC -eq 0
run user passwd alice "Other-Passw0rd.77"; check_not "passwd returns non-zero when swanctl rejects the config" test $RC -eq 0
t_has "$OUT" "NOT" "error text says the change was NOT applied"
cmp -s "$T/etc/users.db" "$T/users.before" && pass "users.db rolled back (consistent with the live config)" || fail "users.db rolled back (consistent with the live config)" "$(diff "$T/users.before" "$T/etc/users.db")"
cmp -s "$T/swan/swanctl.conf" "$T/swanctl.before" && pass "live swanctl.conf unchanged" || fail "live swanctl.conf unchanged"
unset IKEV2_TEST_FAIL; rm -f "$T/etc/custom/connection.conf"

section "concurrency: users.db is serialised and written atomically"
setup_ip
for i in $(seq 1 20); do "$V" user add "u$i" >/dev/null 2>&1 & done; wait
t_eq "$(wc -l <"$T/etc/users.db")" 20 "20 parallel 'user add' -> 20 users"
for i in $(seq 1 20); do "$V" user disable "u$i" >/dev/null 2>&1 & done; wait
t_eq "$(awk -F: '$3=="disabled"' "$T/etc/users.db" | wc -l)" 20 "20 parallel 'user disable' -> all 20 disabled (no lost updates)"
t_eq "$(awk -F: 'NF!=4' "$T/etc/users.db" | wc -l)" 0 "users.db has no malformed lines after the race"
t_eq "$(wc -l <"$T/etc/users.db")" 20 "users.db still has exactly 20 lines"
for i in $(seq 1 10); do "$V" user passwd "u$i" auto --plain >/dev/null 2>&1 & "$V" user enable "u$((i+10))" >/dev/null 2>&1 & done; wait
t_eq "$(awk -F: 'NF!=4' "$T/etc/users.db" | wc -l)" 0 "mixed parallel passwd/enable keeps users.db well-formed"
t_eq "$(grep -cE '^  eap-[0-9]+ \{' "$T/swan/swanctl.conf")" "$(awk -F: '$3=="enabled"' "$T/etc/users.db" | wc -l)" "swanctl.conf matches users.db after the race"
check "lock file never left a stale temp file" test -z "$(ls "$T/etc" | grep -E 'users.db\.|config.env\.' )"

summary "config/users"
