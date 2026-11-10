#!/usr/bin/env bash
# Maintainer tool: sign a release of ikev2-manager.
#
#   bash tools/release.sh init            create your signing key (once) and write release.pub into the repo
#   bash tools/release.sh sign            regenerate SHA256SUMS + SHA256SUMS.sig for the current files
#   bash tools/release.sh verify          verify SHA256SUMS + SHA256SUMS.sig of this folder
#
# The PRIVATE key never goes into the repo. Default location: ~/.ikev2mgr/release.key
# (override with RELEASE_KEY=/path). Keep it offline / in a password manager and back it up:
# if it is lost, installs that pinned the old public key can not receive updates signed
# with a new one (they would have to be reinstalled).
#
# Why: `vpn update` pins release.pub on the first install and from then on refuses any release
# whose SHA256SUMS is not signed by the matching private key. A stolen GitHub token or a
# compromised mirror can therefore not push code to existing servers.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
KEY="${RELEASE_KEY:-$HOME/.ikev2mgr/release.key}"
FILES=(install.sh vpn bot.py ikev2lib.py VERSION)

die() { echo "Error: $*" >&2; exit 1; }
# portable: GNU coreutils on Linux, shasum on macOS/BSD (RELEASE_HASH can force a tool, e.g. "shasum -a 256")
if [[ -n ${RELEASE_HASH:-} ]]; then read -ra HASH <<<"$RELEASE_HASH"
elif command -v sha256sum >/dev/null 2>&1; then HASH=(sha256sum)
else HASH=(shasum -a 256); fi
sums() {
  local list=("${FILES[@]}")
  [[ -f release.pub ]] && list+=(release.pub)
  "${HASH[@]}" "${list[@]}"
}

case "${1:-}" in
  init)
    [[ -f $KEY ]] && die "$KEY already exists - refusing to overwrite your signing key."
    mkdir -p "$(dirname "$KEY")"; chmod 700 "$(dirname "$KEY")"
    ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$KEY" )
    openssl ec -in "$KEY" -pubout -out release.pub 2>/dev/null
    echo "Private key : $KEY      <- back it up, never commit it"
    echo "Public key  : release.pub   <- commit this file"
    echo "Fingerprint : $(openssl pkey -pubin -in release.pub -outform DER | sha256sum | cut -c1-32)"
    echo "Next        : bash tools/release.sh sign" ;;
  sign)
    [[ -f $KEY ]] || die "no signing key at $KEY (run: bash tools/release.sh init)"
    [[ -f release.pub ]] || die "release.pub is missing (run: bash tools/release.sh init)"
    openssl ec -in "$KEY" -pubout 2>/dev/null | cmp -s - release.pub || die "release.pub does not belong to $KEY"
    for f in "${FILES[@]}"; do [[ -f $f ]] || die "missing $f"; done
    bash -n vpn && bash -n install.sh && python3 -m py_compile bot.py ikev2lib.py
    sums >SHA256SUMS
    openssl dgst -sha256 -sign "$KEY" SHA256SUMS | openssl base64 -A >SHA256SUMS.sig; echo >>SHA256SUMS.sig
    bash "$0" verify
    echo "Version $(tr -d '[:space:]' <VERSION) is signed. Commit: SHA256SUMS SHA256SUMS.sig release.pub (+ the changed files)." ;;
  verify)
    [[ -f release.pub && -f SHA256SUMS && -f SHA256SUMS.sig ]] || die "release.pub / SHA256SUMS / SHA256SUMS.sig missing"
    "${HASH[@]}" -c SHA256SUMS >/dev/null || die "checksum mismatch"
    SIG=$(mktemp "${TMPDIR:-/tmp}/ikev2mgr-sig.XXXXXX") || die "cannot create a temp file"   # (Termux has no /tmp: use $TMPDIR)
    trap 'rm -f "$SIG"' EXIT
    openssl base64 -d -A <SHA256SUMS.sig >"$SIG" 2>/dev/null || die "bad signature file"
    if openssl dgst -sha256 -verify release.pub -signature "$SIG" SHA256SUMS >/dev/null; then
      echo "OK: checksums and signature are valid."
    else die "signature does not match release.pub"; fi ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
