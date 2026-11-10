#!/usr/bin/env bash
# domain mode (Let's Encrypt, certbot stubbed) and the text UI driven through stdin
. "$(dirname "$0")/lib.sh"
ERRRE='unbound variable|syntax error|command not found|bad substitution|No such file or directory|integer expression expected|unexpected'

section "domain mode"
setup_ip; run user add alice "$GOODPW" >/dev/null
run domain set bad_domain; check_not "invalid domain refused" test $RC -eq 0
run domain set vpn.example.com 'not-an-email'; check_not "invalid email refused" test $RC -eq 0
run domain set vpn.example.com admin@example.com; t_eq "$RC" 0 "domain set works"
t_eq "$( . "$V"; cfg_load; echo "$MODE/$SERVER_NAME/$DOMAIN/$EMAIL" )" "domain/vpn.example.com/vpn.example.com/admin@example.com" "config switched to domain mode"
check "Let's Encrypt cert deployed" test -s "$T/swan/x509/server.pem"; check "key is 600" test "$(stat -c %a "$T/swan/private/server.key")" = 600
t_has "$(cat "$T/swan/swanctl.conf")" "id = vpn.example.com" "swanctl.conf uses the domain"
check "certbot got the deploy hook and the pre/post hooks" bash -c "grep -q 'deploy-hook .* cert deploy' '$T/state/calls.log' && grep -q 'pre-hook' '$T/state/calls.log'"
check "hooks written" test -x "$T/etc/hooks/pre.sh" -o -f "$T/etc/hooks/pre.sh"
run profile alice; t_eq "$RC" 0 "profile in domain mode"; check_not "no CA file is exported in domain mode" test -e "$T/exp/alice/ca.crt"
run cert info; t_has "$OUT" "domain" "cert info"
a=$(sha256sum "$T/swan/x509/server.pem" | cut -c1-12); run cert auto; t_eq "$RC" 0 "cert auto in domain mode (cert valid for 90 days)"
t_eq "$(sha256sum "$T/swan/x509/server.pem" | cut -c1-12)" "$a" "...valid certificate untouched"
rm -f "$T/swan/x509/server.pem"; : >"$T/state/calls.log"; run cert auto; t_has "$(cat "$T/state/calls.log")" "certbot renew" "a missing certificate triggers certbot renew"
run cert deploy; t_eq "$RC" 0 "cert deploy copies the live cert"; check "...cert is back" test -s "$T/swan/x509/server.pem"
run domain unset 2>/dev/null; # needs the public IP: not available offline -> must fail cleanly
( . "$V"; cfg_set MODE ip; cfg_set DOMAIN ""; cfg_set SERVER_NAME 203.0.113.7 ) >/dev/null 2>&1
run cert deploy; t_eq "$RC" 0 "after leaving domain mode the certbot deploy hook is a harmless no-op"; t_has "$OUT" "Not in domain mode" "...and says so"

section "domain mode through the installer"
new_env; export STUB_HTTPS_MAP="https://example.test/repo=$T/rel"
mkdir -p "$T/rel"; cp "$ROOT/install.sh" "$ROOT/vpn" "$ROOT/bot.py" "$ROOT/ikev2lib.py" "$ROOT/VERSION" "$T/rel/"; ( cd "$T/rel" && sha256sum install.sh vpn bot.py ikev2lib.py VERSION >SHA256SUMS )
OUT=$(IKEV2MGR_BASE=https://example.test/repo bash "$ROOT/install.sh" --yes --domain vpn.example.com --email a@b.co --ip 203.0.113.7 --user dom1 2>&1); RC=$?
t_eq "$RC" 0 "fresh install in domain mode"; t_eq "$( . "$ROOT/vpn"; cfg_load; echo "$MODE/$SERVER_NAME" )" "domain/vpn.example.com" "domain mode configured"
check "first user created" grep -q '^dom1:' "$T/etc/users.db"

section "text UI (driven through stdin)"
setup_ip; run user add alice "$GOODPW" >/dev/null; cp "$ROOT/bot.py" "$T/opt/"
tui() { # LINE... : type these lines into the menu (in a real pseudo-terminal)
  OUT=$(python3 "$TESTS/pty_run.py" "$V" -- "$@" 2>&1 | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g'); RC=${PIPESTATUS[0]}
}
tui "0"; t_eq "$RC" 0 "main menu opens and exits"; t_hasnt "$(grep -E "$ERRRE" <<<"$OUT")" "line" "no shell errors on the main menu"
for m in 1 2 3 4 5 6 7 8; do tui "$m" "0" "0"; t_eq "$RC" 0 "menu $m opens and goes back"; [[ -z $(grep -E "$ERRRE" <<<"$OUT") ]] && pass "menu $m prints no shell errors" || fail "menu $m prints no shell errors" "$(grep -E "$ERRRE" <<<"$OUT" | head -3)"; done
tui "2" "" "0"; t_has "$OUT" "Status" "status screen"
tui "4" "0" "0"; for k in CLIENT_ISOLATION BLOCK_PRIVATE IKE_RATE_LIMIT IPV6_BLOCK; do t_has "$OUT" "$k" "advanced menu lists $k"; done
tui "7" "1" "" "0" "0"; check "backup menu: 'Create backup now' made an archive" bash -c "ls '$T'/bak/ikev2-backup-*.tar.gz"
tui "7" "2" "" "0" "0"; t_has "$OUT" "backup key init" "backup menu: encrypted backup without key explains what to do"
tui "7" "3" "n" "0" "0"; t_has "$OUT" "Backup encryption: OFF" "backup menu: key status"
tui "7" "4" "" "0" "0"; t_has "$OUT" "ikev2-backup-" "backup menu: list"
tui "9" "no" "0"; check "uninstall in the TUI needs the typed word YES" test -f "$T/etc/users.db"; t_has "$OUT" "Type YES" "...and asks for it"
tui "8" "1" "" "0" "0"; t_eq "$RC" 0 "update menu: check for updates exits cleanly (no source reachable offline)"
t_hasnt "$OUT" "installer file" "update menu no longer offers the unverified installer-file mode"

summary "domain/tui"
