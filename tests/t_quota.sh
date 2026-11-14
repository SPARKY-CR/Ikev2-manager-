#!/usr/bin/env bash
# Traffic limit + expiry: parsing, accounting across rekeys, enforcement (disable / delete / notify), renewal, defaults
. "$(dirname "$0")/lib.sh"

GB=$((1024*1024*1024)); MB=$((1024*1024))
# mksas USER IKE_ID IN_SPI IN_BYTES OUT_BYTES : the one session `swanctl --list-sas` reports
mksas() {
  cat >"$T/sas.txt" <<SAS
rw: #$2, ESTABLISHED, IKEv2, aaaaaaaaaaaaaaaa_i bbbbbbbbbbbbbbbb_r*
  local  '203.0.113.7' @ 10.0.0.5[4500]
  remote '$1' @ 198.51.100.20[40001] EAP: '$1' [10.30.0.1]
  established 10s ago, rekeying in 1000s
  net: #$2, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 10s ago, rekeying in 3200s, expires in 3475s
    in  $3,   $4 bytes,    12 packets,     3s ago
    out ${3}f,   $5 bytes,    10 packets,     3s ago
SAS
  export STUB_SAS_FILE="$T/sas.txt"
}
used_of() { python3 "$ROOT/ikev2lib.py" quota list --plain | awk -F'|' -v n="$1" '$1==n{print $3}'; }
state_of() { python3 "$ROOT/ikev2lib.py" quota list --plain | awk -F'|' -v n="$1" '$1==n{print $6}'; }
status_of() { awk -F: -v n="$1" '$1==n{print $3}' "$T/etc/users.db"; }

section "size / expiry parsing"
setup_ip
P="python3 $ROOT/ikev2lib.py quota"
t_eq "$($P parse-size 10G)" $((10*GB)) "10G"
t_eq "$($P parse-size 500M)" $((500*MB)) "500M"
t_eq "$($P parse-size 1.5g)" $((GB*3/2)) "1.5g"
t_eq "$($P parse-size 20)" $((20*GB)) "a bare number means GB"
t_eq "$($P parse-size 2048b)" 2048 "'b' means bytes"
t_eq "$($P parse-size unlimited)" 0 "unlimited -> 0"
t_eq "$($P parse-size 0)" 0 "0 -> unlimited"
for bad in abc -5G 10X 1e3 "" "5 GG" 99999999T; do
  [[ -z $bad ]] && continue
  check_not "size [$bad] refused" $P parse-size "$bad"
done
t_eq "$($P parse-expiry never)" 0 "expiry never"
now=$(date +%s); e=$($P parse-expiry 30)
check "30 = 30 days from now" test $((e - now)) -ge $((30*86400-5)) -a $((e - now)) -le $((30*86400+5))
check "date form" test "$($P parse-expiry 2031-12-31)" -gt "$now"
for bad in 2026-13-40 soon -3 99999999 2026/12/31; do check_not "expiry [$bad] refused" $P parse-expiry "$bad"; done

section "user add with limit / expiry"
setup_ip
run user add alice "$GOODPW" --limit 1G --days 30; t_eq "$RC" 0 "user add --limit --days"
run quota show alice; t_has "$OUT" "of 1.0 GB" "limit stored"; t_has "$OUT" "30d" "expiry about 30 days"
run user add bob --limit abc; check_not "bad --limit refused" test $RC -eq 0
check_not "refused add did not create the user" grep -q '^bob:' "$T/etc/users.db"
run user add bob --expires 2020-01-01; check_not "expiry in the past refused" test $RC -eq 0
run user add bob --action explode; check_not "bad --action refused" test $RC -eq 0
run user add bob --limit; check_not "option without value refused" test $RC -eq 0
run user add bob --plain; t_eq "$RC" 0 "no limit given = unlimited user"
run quota show bob; t_has "$OUT" "unlimited" "unlimited by default"; t_has "$OUT" "expires never" "never expires by default"
run user list; t_has "$OUT" "USAGE" "user list shows usage column"; t_has "$OUT" "EXPIRES" "user list shows expiry column"
run user show alice; t_has "$OUT" "Quota:" "user show prints the quota"
check "quotas.db is mode 600" test "$(stat -c %a "$T/etc/quotas.db")" = 600

section "accounting: baseline, delta, rekey, counter reset"
setup_ip; run user add alice "$GOODPW" --limit 10G
mksas alice 7 c0000001 $((100*MB)) 0
run quota tick; t_eq "$RC" 0 "tick ok"
t_eq "$(used_of alice)" 0 "first tick only records a baseline (earlier traffic is not billed)"
mksas alice 7 c0000001 $((400*MB)) $((100*MB)); run quota tick
t_eq "$(used_of alice)" $((400*MB)) "second tick adds the difference (500M-100M)"
run quota tick; t_eq "$(used_of alice)" $((400*MB)) "a tick without new traffic adds nothing"
mksas alice 7 c0000002 $((50*MB)) 0; run quota tick
t_eq "$(used_of alice)" $((450*MB)) "after a rekey the new child SA counts from zero"
mksas alice 7 c0000002 $((10*MB)) 0; run quota tick
t_eq "$(used_of alice)" $((460*MB)) "a counter that went down is treated as a restart"
rm -f "$T/sas.txt"; run quota tick
t_eq "$(used_of alice)" $((460*MB)) "disconnect: nothing lost, nothing added"
mksas alice 8 c0000009 $((30*MB)) 0; run quota tick
t_eq "$(used_of alice)" $((490*MB)) "a new session adds its whole counter"
mksas ghost 9 c0000010 $((30*MB)) 0; run quota tick
check_not "traffic of an unknown account is ignored" grep -q ghost "$T/etc/quotas.db"

section "enforcement: disable, renew, expiry"
setup_ip; run user add alice "$GOODPW" --limit 1G; run user add bob "$GOODPW"
mksas alice 7 c0000001 0 0; run quota tick
mksas alice 7 c0000001 $((900*MB)) 0; run quota tick
t_eq "$(status_of alice)" enabled "under the limit: still enabled"
mksas alice 7 c0000001 $((1100*MB)) 0; run quota tick
t_eq "$(status_of alice)" disabled "over the limit: disabled"
t_has "$OUT" "disabled (quota)" "the tick reports what it did"
check_not "disabled user is gone from swanctl.conf" grep -q 'id = alice' "$T/swan/swanctl.conf"
t_eq "$(state_of alice)" quota "state remembers the quota disabled it"
t_eq "$(status_of bob)" enabled "other users untouched"
run quota add alice --limit 5G; t_eq "$RC" 0 "renew with add --limit"
t_eq "$(status_of alice)" enabled "renewed user is enabled again immediately"
grep -q 'id = alice' "$T/swan/swanctl.conf" && pass "renewed user is back in swanctl.conf" || fail "renewed user is back in swanctl.conf"
run quota show alice; t_has "$OUT" "of 6.0 GB" "add --limit adds to the limit"
run quota set alice --limit 1G; t_eq "$(status_of alice)" disabled "lowering the limit under the usage disables at once"
run quota reset alice; t_eq "$(status_of alice)" enabled "reset re-enables a quota-disabled user"
t_eq "$(used_of alice)" 0 "reset sets usage to 0"
run user disable bob; run quota set bob --limit 1M; mksas bob 3 c0000003 0 0; run quota tick
mksas bob 3 c0000003 $((5*MB)) 0; run quota tick
t_eq "$(status_of bob)" disabled "manually disabled user stays disabled"
t_eq "$(state_of bob)" "" "and the quota logic does not take ownership of it"
run quota reset bob; t_eq "$(status_of bob)" disabled "so a renewal never re-enables a manually disabled user"
run quota set alice --expires 2020-01-01; t_eq "$(status_of alice)" disabled "past expiry disables"
t_eq "$(state_of alice)" expired "state is 'expired'"
run user enable alice; t_has "$OUT" "over its traffic limit or expired" "enabling an expired user warns"
run quota tick; t_eq "$(status_of alice)" disabled "...and the next tick disables it again"
run quota set alice --days 10; t_eq "$(status_of alice)" enabled "extending the expiry re-enables"
run quota add alice --days 5; t_has "$OUT" "expires" "add --days works"
run quota set alice --days never; run quota show alice; t_has "$OUT" "expires never" "--days never removes the expiry"
run quota set nobody --limit 1G; check_not "unknown user refused" test $RC -eq 0
run quota set alice --limit; check_not "incomplete option refused" test $RC -eq 0
run quota set alice --bogus 1; check_not "unknown option refused" test $RC -eq 0

section "actions: delete / notify / global default"
setup_ip; run user add del1 --limit 10M --action delete; run user add note1 --limit 10M --action notify
run user add plain1 --limit 10M
mksas del1 1 c1 0 0; run quota tick
mksas del1 1 c1 $((20*MB)) 0; run quota tick
check_not "action delete removes the user" grep -q '^del1:' "$T/etc/users.db"
check_not "...and its quota record" grep -q '^del1:' "$T/etc/quotas.db"
check_not "...and its login" grep -q 'id = del1' "$T/swan/swanctl.conf"
mksas note1 2 c2 0 0; run quota tick; mksas note1 2 c2 $((20*MB)) 0; run quota tick
t_eq "$(status_of note1)" enabled "action notify never blocks the user"
mksas plain1 3 c3 0 0; run quota tick; mksas plain1 3 c3 $((20*MB)) 0; run quota tick
t_eq "$(status_of plain1)" disabled "default action = disable"
run quota reset plain1; run set QUOTA_ACTION delete; t_eq "$RC" 0 "global action can be changed"
mksas plain1 3 c3 $((20*MB)) 0; run quota tick
mksas plain1 3 c3 $((40*MB)) 0; run quota tick
check_not "global action delete applies to users on 'default'" grep -q '^plain1:' "$T/etc/users.db"
run set QUOTA_ACTION bogus; check_not "bad global action refused" test $RC -eq 0

section "defaults for new users"
setup_ip
run set DEFAULT_LIMIT 20G; t_eq "$RC" 0 "DEFAULT_LIMIT accepted"; run set DEFAULT_DAYS 30; t_eq "$RC" 0 "DEFAULT_DAYS accepted"
run set DEFAULT_LIMIT foo; check_not "DEFAULT_LIMIT junk refused" test $RC -eq 0
run set DEFAULT_DAYS 99999; check_not "DEFAULT_DAYS too large refused" test $RC -eq 0
run user add dave; run quota show dave
t_has "$OUT" "of 20.0 GB" "new user gets DEFAULT_LIMIT"; t_has "$OUT" "30d" "new user gets DEFAULT_DAYS"
run user add erin --limit unlimited --days never; run quota show erin
t_has "$OUT" "unlimited" "explicit unlimited overrides the default"; t_has "$OUT" "expires never" "explicit never overrides the default"
run set DEFAULT_LIMIT default; run set DEFAULT_DAYS default; run get DEFAULT_LIMIT; t_has "$OUT" "(default)" "defaults can be reset"

section "notifications for the bot"
setup_ip; run user add alice --limit 1G --days 2
mksas alice 7 c0000001 0 0; run quota tick
mksas alice 7 c0000001 $((900*MB)) 0; run quota tick; run quota tick
ev=$(cat "$T/var/quota_events.jsonl" 2>/dev/null)
t_has "$ev" '"kind": "warn_limit"' "80% warning queued"
t_has "$ev" '"kind": "warn_expiry"' "expiry warning queued (2 days left)"
t_eq "$(grep -c warn_limit <<<"$ev")" 1 "each warning is sent only once"
mksas alice 7 c0000001 $((1100*MB)) 0; run quota tick
t_has "$(cat "$T/var/quota_events.jsonl")" '"kind": "limit"' "limit reached event queued"

section "robustness"
setup_ip
for i in 1 2 3 4 5 6; do "$V" user add "u$i" --limit 1G >/dev/null 2>&1 & "$V" quota tick >/dev/null 2>&1 & done; wait
t_eq "$(awk -F: 'NF!=7' "$T/etc/quotas.db" | wc -l)" 0 "quotas.db stays well-formed under parallel add + tick"
t_eq "$(wc -l <"$T/etc/quotas.db")" 6 "one record per user"
printf 'junk\n:::\nx:notanumber:0:disable:0::\n' >>"$T/etc/quotas.db"; run quota list; t_eq "$RC" 0 "malformed quota lines are ignored"
run user del u1; check_not "deleting a user drops its record" grep -q '^u1:' "$T/etc/quotas.db"
( . "$V"; install_units ) >/dev/null 2>&1
grep -q 'quota tick' "$T/units/ikev2-quota.service" && pass "ikev2-quota.service runs 'quota tick'" || fail "ikev2-quota.service runs 'quota tick'"
grep -q 'OnUnitActiveSec=20' "$T/units/ikev2-quota.timer" && pass "ikev2-quota.timer fires every 20 s" || fail "ikev2-quota.timer fires every 20 s"
run help; t_has "$OUT" "vpn quota" "help documents the quota command"

summary "quota"
