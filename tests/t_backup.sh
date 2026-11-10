#!/usr/bin/env bash
# backups: permissions, encryption to a certificate (private key never stored), restore safety
. "$(dirname "$0")/lib.sh"
export IKEV2_BACKUP_KEY_BITS=2048     # keep the tests fast

mktar() { # OUT member... : craft an archive with python (name|type|linkname|mode)
  local out="$1"; shift
  python3 - "$out" "$@" <<'PY'
import sys, tarfile, io
out, *specs = sys.argv[1:]
with tarfile.open(out, "w:gz") as tf:
    for s in specs:
        name, typ, link, mode = (s.split("|") + ["", "", ""])[:4]
        ti = tarfile.TarInfo(name); ti.mode = int(mode or "600", 8)
        if typ == "sym": ti.type = tarfile.SYMTYPE; ti.linkname = link; tf.addfile(ti)
        elif typ == "hard": ti.type = tarfile.LNKTYPE; ti.linkname = link; tf.addfile(ti)
        elif typ == "dir": ti.type = tarfile.DIRTYPE; tf.addfile(ti)
        else: d = b"evil"; ti.size = len(d); tf.addfile(ti, io.BytesIO(d))
PY
}

section "plain backup"
setup_ip; run user add alice "$GOODPW" >/dev/null
run backup; t_eq "$RC" 0 "backup works"
b=$(ls "$T"/bak/ikev2-backup-*.tar.gz | head -1)
t_eq "$(stat -c %a "$b")" 600 "archive is mode 600"; t_eq "$(stat -c %a "$T/bak")" 700 "backup folder is mode 700"
t_has "$(tar -tzf "$b")" "etc/users.db" "archive contains users.db"
t_eq "$(ls "$T"/bak/*.enc 2>/dev/null | wc -l)" 0 "no encrypted copy without --encrypt"
run backup --encrypt; check_not "--encrypt without a key is refused" test $RC -eq 0; t_has "$OUT" "backup key init" "...and explains how to create a key"
t_eq "$(ls "$T"/bak/*.enc 2>/dev/null | wc -l)" 0 "no half-made .enc file"
run backup --bogus; check_not "unknown option refused" test $RC -eq 0
run backups; t_has "$OUT" "ikev2-backup-" "vpn backups lists archives"

section "backup key: generated on the server, private half is only shown once"
setup_ip; run user add alice "$GOODPW" >/dev/null
run backup key show; t_has "$OUT" "OFF" "key show: off at first"
run backup key init; t_eq "$RC" 0 "key init works"
printf '%s\n' "$OUT" | sed -n '/BEGIN [A-Z ]*PRIVATE KEY/,/END [A-Z ]*PRIVATE KEY/p' >"$T/printed.key"
check "private key was printed for the admin" grep -q 'PRIVATE KEY' "$T/printed.key"
check "certificate installed (mode 644, public)" test "$(stat -c %a "$T/etc/backup-cert.pem")" = 644
body=$(sed -n '2p' "$T/printed.key")
leak=$(grep -rlF -- "$body" "$T" 2>/dev/null | grep -v "^$T/printed.key$" | head -3)
[[ -z $leak ]] && pass "the private key is NOT stored anywhere under the server's folders" || fail "the private key is NOT stored anywhere under the server's folders" "$leak"
t_hasnt "$(cat "$T/etc/backup-cert.pem")" "PRIVATE KEY" "the installed file holds only the certificate"
run backup key init; check_not "second init is refused (would orphan old backups)" test $RC -eq 0
run backup key show; t_has "$OUT" "ON" "key show: on"; t_has "$OUT" "Fingerprint" "key show prints the fingerprint"

section "encrypted backup"
run backup --encrypt; t_eq "$RC" 0 "backup --encrypt works"
enc=$(ls "$T"/bak/*.enc | head -1); plain="${enc%.enc}"
t_eq "$(stat -c %a "$enc")" 600 ".enc is mode 600"
check_not "ciphertext does not contain the VPN password" grep -qa "$GOODPW" "$enc"
check_not "ciphertext does not look like a tar/gzip archive" bash -c "head -c2 '$enc' | xxd -p | grep -qi '^1f8b'"
check "plain archive does contain it (so the test is meaningful)" bash -c "tar -xzOf '$plain' | grep -qa '$GOODPW'"
run backup decrypt "$enc" "$T/printed.key" "$T/out.tgz"; t_eq "$RC" 0 "vpn backup decrypt with the printed key"
check "decrypted archive is byte-identical to the plain one" cmp "$plain" "$T/out.tgz"
openssl cms -decrypt -binary -inform DER -in "$enc" -inkey "$T/printed.key" -out "$T/manual.tgz" 2>/dev/null
check "the documented manual openssl command works too" cmp "$plain" "$T/manual.tgz"
openssl genrsa -out "$T/wrong.key" 2048 2>/dev/null
run backup decrypt "$enc" "$T/wrong.key" "$T/bad.tgz"; check_not "wrong key cannot decrypt" test $RC -eq 0
check_not "no partial output left after a failed decrypt" test -e "$T/bad.tgz"

section "bring your own certificate (private key never touches the server)"
setup_ip
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/my.key" -out "$T/my.crt" -days 30 -subj /CN=mine 2>/dev/null
run backup key set "$T/my.crt"; t_eq "$RC" 0 "key set with an RSA certificate"
run backup --encrypt; t_eq "$RC" 0 "encrypt with it"
enc=$(ls "$T"/bak/*.enc | head -1); run backup decrypt "$enc" "$T/my.key" "$T/my.tgz"; t_eq "$RC" 0 "decrypts with the admin's own key"
echo garbage >"$T/junk"; run backup key set "$T/junk"; check_not "garbage refused" test $RC -eq 0
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/ec.key" -out "$T/ec.crt" -days 30 -subj /CN=ec 2>/dev/null
run backup key set "$T/ec.crt"; check_not "EC certificate refused (RSA only)" test $RC -eq 0
openssl req -x509 -newkey rsa:1024 -nodes -keyout "$T/small.key" -out "$T/small.crt" -days 30 -subj /CN=small 2>/dev/null
run backup key set "$T/small.crt"; check_not "1024-bit RSA refused" test $RC -eq 0
run backup key remove; t_eq "$RC" 0 "key remove"; check_not "certificate gone" test -e "$T/etc/backup-cert.pem"
run backup key show; t_has "$OUT" "OFF" "off again"

section "rotation"
setup_ip; for i in $(seq 1 12); do touch -d "2020-01-01 00:$(printf %02d $i)" /dev/null; echo x >"$T/bak/ikev2-backup-20200101-0000$(printf %02d $i).tar.gz"; touch -d "2020-01-01 00:$(printf %02d $i):00" "$T/bak/ikev2-backup-20200101-0000$(printf %02d $i).tar.gz"; done
chmod 700 "$T/bak"; run backup
t_eq "$(ls "$T"/bak/ikev2-backup-*.tar.gz | wc -l)" 10 "only the newest 10 archives are kept"
t_eq "$(ls "$T"/bak/ikev2-backup-20200101-000001.tar.gz 2>/dev/null | wc -l)" 0 "the oldest ones are removed"

section "restore"
setup_ip; run user add alice "$GOODPW" >/dev/null; run backup >/dev/null; b=$(ls "$T"/bak/ikev2-backup-*.tar.gz | head -1)
run user add bob "$GOODPW" >/dev/null; check "bob exists before restore" grep -q '^bob:' "$T/etc/users.db"
run restore "$b"; t_eq "$RC" 0 "restore works"
check_not "restore brought back the old state (bob is gone)" grep -q '^bob:' "$T/etc/users.db"
check "alice is back" grep -q '^alice:' "$T/etc/users.db"
t_eq "$(ls "$T"/bak/ikev2-prerestore-*.tar.gz 2>/dev/null | wc -l)" 1 "a pre-restore safety copy was made"
check "swanctl.conf was regenerated from the restored data" grep -q 'id = alice' "$T/swan/swanctl.conf"
check_not "...without the user that is gone" grep -q 'id = bob' "$T/swan/swanctl.conf"
t_eq "$(ls "$T"/bak/ikev2-backup-*.tar.gz | wc -l)" 1 "the restore did not rotate away the archive it restores from"
run restore; check_not "restore without a file fails" test $RC -eq 0
run restore /nonexistent; check_not "restore of a missing file fails" test $RC -eq 0

section "restore of an encrypted backup"
setup_ip; run user add alice "$GOODPW" >/dev/null; run backup key init >/dev/null
printf '%s\n' "$OUT" >/dev/null; run backup key show >/dev/null
# make a key pair we control
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/k.key" -out "$T/k.crt" -days 30 -subj /CN=k 2>/dev/null; run backup key set "$T/k.crt" >/dev/null
run backup --encrypt >/dev/null; enc=$(ls "$T"/bak/*.enc | head -1)
run user add bob "$GOODPW" >/dev/null
run restore "$enc"; check_not "encrypted restore needs a key" test $RC -eq 0; check "bob untouched after the refused restore" grep -q '^bob:' "$T/etc/users.db"
run restore "$enc" --key "$T/wrong.key"; check_not "wrong key refused" test $RC -eq 0; check "bob still untouched" grep -q '^bob:' "$T/etc/users.db"
run restore "$enc" --key "$T/k.key"; t_eq "$RC" 0 "restore with the right key"; check_not "state restored" grep -q '^bob:' "$T/etc/users.db"
t_eq "$(ls "$T"/tmp | wc -l)" 0 "decrypted temp copy was removed"

section "restore refuses hostile archives (never writes outside the tool's folders)"
setup_ip; run user add alice "$GOODPW" >/dev/null; cp "$T/etc/users.db" "$T/users.keep"
E="${T#/}/etc"; S="${T#/}/swan"; OUTSIDE="${T#/}/outside"
declare -A BAD=(
  [outside]="$OUTSIDE/pwn"
  [traversal]="$E/../outside/pwn"
  [absolute]="/$OUTSIDE/pwn"
  [symlink-escape]="$E/x|sym|../outside|777"
  [symlink-abs]="$E/x|sym|/tmp|777"
  [hardlink]="$E/h|hard|etc/passwd|600"
  [setuid]="$E/su|||4755"
  [world-writable]="$S/ww|||666"
)
for k in "${!BAD[@]}"; do
  mktar "$T/evil-$k.tgz" "$E/users.db|||600" "${BAD[$k]}"
  run restore "$T/evil-$k.tgz"; check_not "hostile archive [$k] refused" test $RC -eq 0
done
check_not "nothing was written outside" test -e "$T/outside/pwn"
cmp -s "$T/users.keep" "$T/etc/users.db" && pass "users.db untouched by every refused restore" || fail "users.db untouched by every refused restore"
t_eq "$(ls "$T"/bak/ikev2-prerestore-* 2>/dev/null | wc -l)" 0 "refused restores do not even create safety copies"
echo "not a tar" >"$T/junk.tgz"; run restore "$T/junk.tgz"; check_not "non-archive refused" test $RC -eq 0

summary "backup"
