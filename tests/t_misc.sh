#!/usr/bin/env bash
# smoke tests of the everyday commands, locking behaviour, selftest, migrate, uninstall
. "$(dirname "$0")/lib.sh"

section "everyday commands work"
setup_ip; run user add alice "$GOODPW" >/dev/null
run help; t_eq "$RC" 0 "help"; for w in "backup key" "--stdin" "IKE_RATE_LIMIT" "update --base https" "reset [--yes]"; do t_has "$OUT" "$w" "help mentions: $w"; done
run version; t_has "$OUT" "ikev2-manager $(cat "$ROOT/VERSION")" "version prints the release"
run user list; t_eq "$RC" 0 "user list"; t_has "$OUT" alice "list shows the user"
run user list --plain; t_has "$OUT" "alice|enabled|" "list --plain format (used by the bot)"
run user show alice; t_has "$OUT" "$GOODPW" "user show prints the password (explicit admin action)"
run status --kv; t_eq "$RC" 0 "status --kv"; for k in version server mode users enabled online cert_days cert_state backup_key firewall pool dns; do t_has "$OUT" "$k=" "kv has $k"; done
run status; t_eq "$RC" 0 "status"
run ca; t_has "$OUT" "BEGIN CERTIFICATE" "ca prints the CA certificate"
run conf show; t_eq "$RC" 0 "conf show"
run logs 5; t_eq "$RC" 0 "logs 5"
for bad in "5; reboot" "-f" "0" "abc" "99999" "--output=json"; do run logs "$bad"; check_not "logs [$bad] refused" test $RC -eq 0; done
run profile nosuchuser; check_not "profile of an unknown user refused" test $RC -eq 0
run profile alice; t_eq "$RC" 0 "profile"; t_has "$OUT" "alice.mobileconfig" "profile lists the files it wrote"; t_hasnt "$OUT" "notes" "...and only those"
run bogus; check_not "unknown command refused" test $RC -eq 0

section "locking: reads never block, writers wait their turn"
setup_ip; run user add alice "$GOODPW" >/dev/null
( flock -x "$T/etc/.lock" sleep 3 ) & sleep 0.4
s=$(date +%s.%N); run status --kv; e=$(date +%s.%N)
check "status --kv is not blocked by a running writer" bash -c "awk 'BEGIN{exit !($e-$s < 2)}'"
run user list; t_eq "$RC" 0 "user list is not blocked"
s=$(date +%s.%N); run user add bob "$GOODPW"; e=$(date +%s.%N)
t_eq "$RC" 0 "a writer waits for the lock and then succeeds"; check "...it really waited (>= 1.5 s)" bash -c "awk 'BEGIN{exit !($e-$s >= 1.5)}'"
wait
( flock -x "$T/etc/.lock" sleep 3 ) & sleep 0.4
IKEV2_LOCK_TIMEOUT=1 run user add carol "$GOODPW"; check_not "lock timeout -> the command fails" test $RC -eq 0; t_has "$OUT" "still running" "...with a clear message"
check_not "...and nothing was changed" grep -q '^carol:' "$T/etc/users.db"
wait

section "selftest / migrate"
setup_ip; run user add alice "$GOODPW" >/dev/null; cp "$ROOT/bot.py" "$T/opt/"
run selftest; t_eq "$RC" 0 "selftest passes on a healthy install"
echo 'this is not a config line' >>"$T/etc/config.env"; run selftest; check_not "selftest detects a corrupted config.env" test $RC -eq 0; t_has "$OUT" "unparsable" "...and says why"
sed -i '/this is not a config line/d' "$T/etc/config.env"; run selftest; t_eq "$RC" 0 "healthy again"
run migrate; t_eq "$RC" 0 "migrate"; run migrate; t_eq "$RC" 0 "migrate is idempotent"
check "migrate keeps the backup folder private" test "$(stat -c %a "$T/bak")" = 700
t_has "$(cat "$T/units/ikev2-bot.service" 2>/dev/null)" "NoNewPrivileges=yes" "migrate refreshes the unit files (new hardening reaches upgraded installs)"

section "uninstall"
setup_ip; run user add alice "$GOODPW" >/dev/null; cp "$ROOT/bot.py" "$T/opt/"
mkdir -p "$T/strongswand" "$T/swan/x509" "$T/swan/private" "$T/swan/x509ca" "$T/exp/alice"; export IKEV2_STRONGSWAND="$T/strongswand"
for f in "$T/units/ikev2-net.service" "$T/units/ikev2-bot.service" "$T/units/ikev2-certcheck.service" "$T/units/ikev2-certcheck.timer" "$T/sysctl/99-ikev2.conf" "$T/strongswand/ikev2-manager.conf" "$T/swan/x509/server.pem" "$T/swan/private/server.key" "$T/exp/alice/alice.mobileconfig" "$T/log"; do : >"$f"; done
cp "$V" "$T/bin/vpn"; run net apply >/dev/null
run uninstall </dev/null; check_not "uninstall without --yes needs a typed confirmation (no tty -> aborts)" test $RC -eq 0
check "nothing was removed by the aborted uninstall" test -f "$T/units/ikev2-bot.service"
echo "yes" | run_in "yes" uninstall; check_not "lower-case 'yes' is not enough" test $RC -eq 0
run_in "YES" uninstall; t_eq "$RC" 0 "typing YES uninstalls"
for f in "$T/units/ikev2-net.service" "$T/units/ikev2-bot.service" "$T/units/ikev2-certcheck.timer" "$T/sysctl/99-ikev2.conf" "$T/strongswand/ikev2-manager.conf" "$T/swan/swanctl.conf" "$T/swan/x509/server.pem" "$T/swan/private/server.key" "$T/bin/vpn" "$T/opt"; do check_not "removed: ${f#"$T"/}" test -e "$f"; done
check "the final backup is kept" bash -c "ls '$T'/bak/ikev2-backup-*.tar.gz"
check "users/CA data stay without --purge" test -f "$T/etc/users.db"
t_has "$OUT" "passwords" "non-purge uninstall warns that exported profiles (with passwords) remain"
check "exported profiles are not silently deleted without --purge" test -d "$T/exp/alice"
t_eq "$(iptables -S IKEV2_FWD 2>&1 | grep -c 'No chain')" 1 "firewall/NAT rules are gone"
setup_ip; run user add alice "$GOODPW" >/dev/null; cp "$ROOT/bot.py" "$T/opt/"; mkdir -p "$T/exp/alice"; : >"$T/exp/alice/alice.mobileconfig"; : >"$T/log"; cp "$V" "$T/bin/vpn"
run uninstall --purge --yes; t_eq "$RC" 0 "uninstall --purge --yes"
check_not "--purge removes /etc/ikev2-style data" test -e "$T/etc/users.db"
check_not "--purge removes exported profiles (they contain passwords)" test -e "$T/exp"
check_not "--purge removes the log file" test -e "$T/log"
check "...but the final backup survives" bash -c "ls '$T'/bak/ikev2-backup-*.tar.gz"
unset IKEV2_STRONGSWAND

summary "misc"
