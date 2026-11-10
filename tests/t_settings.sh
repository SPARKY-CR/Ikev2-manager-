#!/usr/bin/env bash
# `vpn set / get / reset / preset / raw` : validation, exit codes, robustness
. "$(dirname "$0")/lib.sh"

section "vpn set: exit codes (a successful set must exit 0)"
setup_ip
while read -r k v; do
  run set "$k" "$v"; t_eq "$RC" 0 "vpn set $k $v -> exit 0"
done <<'LIST'
DNS 9.9.9.9,149.112.112.112
POOL 10.77.0.0/16
LOCAL_TS 0.0.0.0/0
IKE_PROPOSALS aes256-sha256-modp2048
ESP_PROPOSALS aes256gcm16
DPD_DELAY 45s
FRAGMENTATION yes
MOBIKE no
UNIQUE replace
REKEY_TIME 4h
REAUTH_TIME 24h
CHILD_REKEY_TIME 1h
CHILD_LIFE_TIME 80m
SEND_CERT always
MSS_CLAMP 1360
NAT yes
FW_EXTRA_TCP 443,8080
FW_EXTRA_UDP 51820
LOG_LEVEL 2
CLIENT_ISOLATION no
BLOCK_PRIVATE no
IKE_RATE_LIMIT 60
IPV6_BLOCK yes
LIST
run set MSS_CLAMP default; t_eq "$RC" 0 "reset to default exits 0"
run preset ike compat; t_eq "$RC" 0 "preset ike compat exits 0"
run preset ike strict-sha2; t_eq "$RC" 0 "preset ike strict-sha2 exits 0"
run preset dns quad9; t_eq "$RC" 0 "preset dns exits 0"

section "vpn set: validation and config.env integrity"
setup_ip
NL=$'a\nb'
for kv in "DNS|1.1.1.1"$'\n'"foo = bar" "LOCAL_TS|0.0.0.0/0"$'\n'"x = y" "DNS|1.1.1.1"$'\r' "IKE_PROPOSALS|aes256"$'\n'"x" "DPD_DELAY|30s"$'\n'"x" "FW_EXTRA_TCP|443"$'\n'"x" "FRAGMENTATION|yes"$'\n'"x"; do
  k=${kv%%|*}; v=${kv#*|}
  before=$(cat "$T/etc/config.env" 2>/dev/null); run set "$k" "$v"
  check_not "newline/CR in $k refused" test $RC -eq 0
  t_eq "$(cat "$T/etc/config.env" 2>/dev/null)" "$before" "config.env untouched after refused $k"
done
for kv in "DNS|1.1.1.1,evil" "DNS|1.1.1.256" "DNS|" "POOL|10.0.0.0/7" "POOL|10.0.0.0/31" "POOL|10.0.0.0/16;x" "LOCAL_TS|0.0.0.0/33" "LOCAL_TS|10.0.0.0/8,bad" "IKE_PROPOSALS|aes256-sha256-modp2048,\$(id)" "IKE_PROPOSALS|a b" "DPD_DELAY|30s;x" "DPD_DELAY|1h20m" "MSS_CLAMP|100" "MSS_CLAMP|9999" "FW_EXTRA_TCP|443;rm" "FW_EXTRA_TCP|70000" "FW_EXTRA_TCP|0" "NAT|maybe" "UNIQUE|always" "LOG_LEVEL|9" "IKE_RATE_LIMIT|5" "IKE_RATE_LIMIT|lots" "IKE_RATE_LIMIT|1000000" "IPV6_BLOCK|1" "CLIENT_ISOLATION|YES"; do
  k=${kv%%|*}; v=${kv#*|}; [[ $k == DNS && -z $v ]] && continue   # empty value means "reset" by design
  run set "$k" "$v"; check_not "invalid value [$k=$v] refused" test $RC -eq 0
done
run set NOPE 1; check_not "unknown key refused" test $RC -eq 0
run get; t_eq "$RC" 0 "vpn get works"; for k in CLIENT_ISOLATION BLOCK_PRIVATE IKE_RATE_LIMIT IPV6_BLOCK; do t_has "$OUT" "$k" "vpn get lists $k"; done
run get DNS; t_eq "$RC" 0 "vpn get DNS works"
( . "$V"; cfg_load; [[ -n $DNS ]] ) && pass "config.env still parses after all refused changes" || fail "config.env still parses after all refused changes"

section "vpn set: failed apply restores the previous value"
setup_ip; run set DNS 9.9.9.9
mkdir -p "$T/etc/custom"; echo "BADTOKEN = 1" >"$T/etc/custom/connection.conf"; export IKEV2_TEST_FAIL=BADTOKEN
run set DNS 8.8.8.8; check_not "set is refused when swanctl rejects the config" test $RC -eq 0
unset IKEV2_TEST_FAIL; rm -f "$T/etc/custom/connection.conf"
run get DNS; t_has "$OUT" "9.9.9.9" "previous DNS value restored"

section "vpn reset needs confirmation"
setup_ip; run set DNS 9.9.9.9
run reset </dev/null; check_not "reset without --yes refuses (non-interactive)" test $RC -eq 0
run get DNS; t_has "$OUT" "9.9.9.9" "setting survived the refused reset"
run reset --yes; t_eq "$RC" 0 "reset --yes works"
run get DNS; t_has "$OUT" "DNS = 1.1.1.1,8.8.8.8" "DNS is back to default"

section "presets"
setup_ip
run preset ike strict-sha2
conf=$(grep -c 'proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha256-ecp256,aes256-sha384-ecp384' "$T/swan/swanctl.conf"); t_eq "$conf" 1 "strict-sha2 writes an explicit list"
t_hasnt "$(grep -E '^\s+proposals' "$T/swan/swanctl.conf")" "default" "strict-sha2 has no built-in 'default' list"
t_hasnt "$(grep -E '^\s+proposals' "$T/swan/swanctl.conf")" "sha1" "strict-sha2 contains no SHA-1"
run preset ike compat; t_has "$(grep -E '^\s+proposals' "$T/swan/swanctl.conf")" "default" "compat restores the default list"
run preset ike nonsense; check_not "unknown ike preset refused" test $RC -eq 0

section "IPv6 guard in swanctl.conf"
setup_ip
run user add alice "$GOODPW" >/dev/null
t_hasnt "$(grep local_ts "$T/swan/swanctl.conf")" "::/0" "default: no ::/0"
run set IPV6_BLOCK yes; t_has "$(grep local_ts "$T/swan/swanctl.conf")" "0.0.0.0/0,::/0" "IPV6_BLOCK=yes adds ::/0 to local_ts"
run set LOCAL_TS 10.0.0.0/8; t_hasnt "$(grep local_ts "$T/swan/swanctl.conf")" "::/0" "split tunnel: ::/0 is not added"
run set LOCAL_TS 0.0.0.0/0; run set IPV6_BLOCK no; t_hasnt "$(grep local_ts "$T/swan/swanctl.conf")" "::/0" "IPV6_BLOCK=no removes it again"

section "raw snippets"
setup_ip
printf 'reauth_time = 3h\n' | run_in 'reauth_time = 3h' raw set connection; t_eq "$RC" 0 "raw set applies"
t_has "$(cat "$T/swan/swanctl.conf")" "reauth_time = 3h" "raw snippet is in swanctl.conf"
export IKEV2_TEST_FAIL=BADTOKEN; run_in 'BADTOKEN = 1' raw set connection; check_not "rejected raw snippet is refused" test $RC -eq 0
unset IKEV2_TEST_FAIL
run raw show connection; t_has "$OUT" "reauth_time = 3h" "rejected raw snippet was rolled back"
run raw clear connection; t_eq "$RC" 0 "raw clear works"
run conf show; t_eq "$RC" 0 "conf show works"; t_hasnt "$OUT" "SuperSecret" "conf show masks secrets"

summary "settings"
