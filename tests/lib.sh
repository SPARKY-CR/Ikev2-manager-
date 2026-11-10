#!/usr/bin/env bash
# Tiny dependency-free test helpers used by tests/t_*.sh
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TESTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0; FAILED=()
BASE_TMP="${TMPDIR:-/tmp}"      # the real temp dir (new_env points TMPDIR at a scratch folder)
chmod +x "$ROOT/vpn" "$ROOT/install.sh" 2>/dev/null || true      # (same reason: exec bits can get lost)

section() { printf '\n== %s\n' "$*"; }
pass() { PASS=$((PASS+1)); printf '  ok    %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s\n' "$1"; [[ -n ${2:-} ]] && printf '        %s\n' "${2//$'\n'/$'\n        '}"; return 0; }
t_eq()    { if [[ "$1" == "$2" ]]; then pass "$3"; else fail "$3" "expected: [$2]"$'\n'"actual:   [$1]"; fi; }
t_has()   { if [[ "$1" == *"$2"* ]]; then pass "$3"; else fail "$3" "missing [$2] in: ${1:0:400}"; fi; }
t_hasnt() { if [[ "$1" != *"$2"* ]]; then pass "$3"; else fail "$3" "unexpected [$2] in: ${1:0:400}"; fi; }
# check "description" cmd args...   (passes when cmd succeeds)
check()   { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d" "command failed: $*"; fi; }
# check_not "description" cmd args... (passes when cmd fails)
check_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$d" "command unexpectedly succeeded: $*"; else pass "$d"; fi; }
summary() {
  printf '\n%s: %d passed, %d failed\n' "${1:-tests}" "$PASS" "$FAIL"
  if [[ $FAIL -gt 0 ]]; then printf 'failed:\n'; printf '  - %s\n' "${FAILED[@]}"; return 1; fi
  return 0
}

# run VPN args... -> sets OUT (stdout+stderr) and RC
run() { OUT=$("$V" "$@" 2>&1); RC=$?; }
# run_in STDIN VPN args...
run_in() { local in="$1"; shift; OUT=$("$V" "$@" 2>&1 <<<"$in"); RC=$?; }

new_env() {
  T=$(mktemp -d "$BASE_TMP/ikev2t.XXXXXX"); ENVS+=("$T")
  mkdir -p "$T"/{etc,var,opt,swan,bak,exp,sysctl,units,f2b,apt,state,bin,tmp}
  cp "$ROOT/ikev2lib.py" "$ROOT/VERSION" "$T/opt/"
  export IKEV2_TEST=1 IKEV2_ETC="$T/etc" IKEV2_VAR="$T/var" IKEV2_OPT="$T/opt" IKEV2_SWAN="$T/swan" \
         IKEV2_BACKUPS="$T/bak" IKEV2_EXPORTS="$T/exp" IKEV2_LOG="$T/log" IKEV2_SYSCTL_D="$T/sysctl" \
         IKEV2_UNIT_DIR="$T/units" IKEV2_F2B_D="$T/f2b" IKEV2_APT_D="$T/apt" STUB_STATE="$T/state" \
         IKEV2_BIN="$T/bin/vpn" IKEV2_LE="$T/le" LC_ALL=C TMPDIR="$T/tmp"
  # the stubs are copied into the scratch folder and made executable there, so the tests also work when the checkout
  # lost exec bits or symlinks (upload through the GitHub web page, Windows, zip files, ...)
  mkdir -p "$T/stubs"; cp "$TESTS"/stubs/* "$T/stubs/"; cp -f "$TESTS/stubs/iptables" "$T/stubs/ip6tables"; chmod +x "$T/stubs"/*
  export PATH="$T/stubs:$PATH"
  unset IKEV2_TEST_FAIL STUB_IPT_FAIL STUB_HTTPS_MAP STUB_PKI_NO_PATHLEN STUB_PKI_FAIL STUB_TG_BAD STUB_SAS_FILE
  V="$ROOT/vpn"
}
# a configured IP-mode server with a stand-in CA
setup_ip() {
  new_env
  ( . "$V"; cfg_set MODE ip; cfg_set SERVER_IP 203.0.113.7; cfg_set SERVER_NAME 203.0.113.7 ) >/dev/null 2>&1
  mkdir -p "$T/etc/pki"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/etc/pki/ca.key" -out "$T/etc/pki/ca.pem" -days 3650 -subj "/CN=IKEv2 VPN CA" 2>/dev/null
}
ENVS=()
cleanup_env() { local d; for d in "${ENVS[@]}"; do [[ -d $d ]] && rm -rf "$d"; done; return 0; }
trap cleanup_env EXIT
GOODPW='Str0ng-Passw0rd.x1'
