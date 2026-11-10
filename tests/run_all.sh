#!/usr/bin/env bash
# Runs every test-suite (shell + python). No root, network or strongSwan needed: system tools are stubbed.
#   tests/run_all.sh                       test this checkout
#   ROOT=/path/to/other/checkout tests/run_all.sh    test another copy with these tests (e.g. an older release)
# -v prints every check, otherwise only failures and the per-suite summaries.
cd "$(dirname "$0")" || exit 1
export ROOT="${ROOT:-$(cd .. && pwd)}"
verbose=0; [[ ${1:-} == -v ]] && verbose=1
total_fail=0; total_pass=0
for suite in t_*.sh; do
  out=$(bash "$suite" 2>&1); rc=$?
  [[ $verbose == 1 ]] && printf '%s\n' "$out" || printf '%s\n' "$out" | grep -E '^(==|  FAIL|        |failed:|  - )' | grep -vE '^== ' || true
  line=$(printf '%s\n' "$out" | grep -E ': [0-9]+ passed, [0-9]+ failed' | tail -1)
  printf '%-22s %s\n' "$suite" "${line:-NO RESULT (crashed?)}"
  p=$(sed -n 's/.*: \([0-9]*\) passed.*/\1/p' <<<"$line"); f=$(sed -n 's/.* passed, \([0-9]*\) failed.*/\1/p' <<<"$line")
  total_pass=$((total_pass + ${p:-0})); total_fail=$((total_fail + ${f:-0})); [[ $rc -ne 0 ]] && ((total_fail += ${f:-0} == 0 ? 1 : 0))
done
for t in test_lib.py test_bot.py; do
  out=$(python3 -W ignore "$t" 2>&1); rc=$?
  n=$(sed -n 's/^Ran \([0-9]*\) tests.*/\1/p' <<<"$out")
  if [[ $rc -eq 0 ]]; then printf '%-22s %s passed, 0 failed\n' "$t" "$n"; total_pass=$((total_pass + ${n:-0}))
  else printf '%-22s FAILED\n' "$t"; printf '%s\n' "$out" | grep -E '^(FAIL|ERROR|AssertionError)' | head -20; total_fail=$((total_fail + 1)); fi
done
echo; echo "TOTAL: $total_pass passed, $total_fail failed"
[[ $total_fail -eq 0 ]]
