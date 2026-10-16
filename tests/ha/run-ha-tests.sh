#!/usr/bin/env bash
# run-ha-tests.sh — run every offline HA test file and sum the verdicts.
# See tests/ha/lib.sh for exactly what these tests do and do not prove.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0
total_pass=0
total_fail=0
for t in t-static t-params t-harden t-install t-patroni-backup t-collect-hostcheck; do
	echo "######## $t"
	out="$(bash "$HERE/$t.sh" 2>&1)" || rc=1
	printf '%s\n' "$out"
	p="$(printf '%s\n' "$out" | grep -c '^ok ')"
	f="$(printf '%s\n' "$out" | grep -c '^FAIL ')"
	total_pass=$((total_pass + p))
	total_fail=$((total_fail + f))
done
echo
echo "HA TESTS TOTAL: $total_pass passed, $total_fail failed"
[ "$rc" = 0 ] && [ "$total_fail" = 0 ]
