#!/usr/bin/env bash
# run-policy-tests.sh — the sensitivity proof.
#
# This is the half of the wave that matters. Asserting that the committed
# desired state satisfies the policy proves almost nothing on its own: a policy
# with every assertion accidentally disabled would also pass. What makes the
# guard meaningful is that a deliberately-unsafe realm is REJECTED, and
# rejected FOR THE STATED REASON.
#
# Runs entirely offline over committed JSON. No Keycloak, no container, no
# network, no daemon. jq and a shell are the whole dependency set.
#
# Knobs (all with documented defaults):
#   REPO_ROOT      repository root                (derived from this file)
#   CASES_FILE     the fixture ratchet            ($REPO_ROOT/tests/required-cases.tsv)
#   FIXTURE_ROOT   where fixtures live            ($REPO_ROOT/tests/fixtures)

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CASES_FILE="${CASES_FILE:-$REPO_ROOT/tests/required-cases.tsv}"
FIXTURE_ROOT="${FIXTURE_ROOT:-$REPO_ROOT/tests/fixtures}"
EVAL="$REPO_ROOT/bin/policy-eval.sh"

# The four rejections this wave was commissioned to prove. Listed separately
# from the ratchet so that swapping the mandated fixtures for easier ones is
# also a failure, not just deleting them.
MANDATED_REJECTIONS=(flow-direct-grant pkce redirect-wildcard public)

pass_count=0
reject_count=0
failures=0

note() { printf '%s\n' "$*"; }
bad() {
	printf 'NOT-PROVEN  %s\n' "$*"
	failures=$((failures + 1))
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ---------------------------------------------------------------------------
# 1. The ratchet, both directions.
# ---------------------------------------------------------------------------
declared="$work/declared.txt"
ondisk="$work/ondisk.txt"
awk -F'\t' '!/^#/ && NF >= 3 { print $2 }' "$CASES_FILE" | sort >"$declared"
(cd "$REPO_ROOT" && find tests/fixtures -type f -name '*.json' | sort) >"$ondisk"

if ! diff -u "$declared" "$ondisk" >"$work/ratchet.diff"; then
	note "The fixture ratchet is out of sync (declared '-' vs on disk '+'):"
	cat "$work/ratchet.diff"
	bad "tests/required-cases.tsv and tests/fixtures/ disagree"
fi

declared_count="$(wc -l <"$declared" | tr -d ' ')"
if [ "$declared_count" -lt 20 ]; then
	bad "only $declared_count cases declared; the sensitivity set has shrunk below the level this wave shipped"
fi

for code in "${MANDATED_REJECTIONS[@]}"; do
	if ! awk -F'\t' -v c="$code" '!/^#/ && NF >= 3 && $3 == c { found = 1 } END { exit !found }' "$CASES_FILE"; then
		bad "no fixture claims rejection code '$code'; this wave requires one"
	fi
done

# ---------------------------------------------------------------------------
# 2. Every declared case, evaluated through the SAME dispatcher production uses.
# ---------------------------------------------------------------------------
while IFS=$'\t' read -r policy fixture expectation; do
	case "$policy" in '' | '#'*) continue ;; esac
	path="$REPO_ROOT/$fixture"

	if [ ! -r "$path" ]; then
		bad "$fixture: fixture not readable"
		continue
	fi
	if ! jq -e . "$path" >/dev/null 2>&1; then
		bad "$fixture: not valid JSON"
		continue
	fi

	# Every fixture must say, in its own file, what it is and what it expects,
	# so a reviewer reading the unsafe config sees the claim beside it.
	if ! jq -e '._case and ._expect and (._expect.policy | type == "string")' "$path" >/dev/null; then
		bad "$fixture: missing _case / _expect metadata"
		continue
	fi
	if [ "$(jq -r '._expect.policy' "$path")" != "$policy" ]; then
		bad "$fixture: declares policy '$(jq -r '._expect.policy' "$path")' but the ratchet says '$policy'"
		continue
	fi

	ctx="$work/ctx.json"
	inp="$work/inp.json"
	case "$policy" in
	realm)
		jq '.manifest' "$path" >"$ctx"
		jq '.realm_clients' "$path" >"$inp"
		;;
	*)
		jq '.expected' "$path" >"$ctx"
		jq '.client' "$path" >"$inp"
		;;
	esac

	set +e
	output="$("$EVAL" "$policy" "$ctx" "$inp" 2>&1)"
	status=$?
	set -e

	if [ "$expectation" = "ACCEPT" ]; then
		if [ "$status" -eq 0 ] && [ -z "$output" ]; then
			printf 'ACCEPTED    %s\n' "$fixture"
			pass_count=$((pass_count + 1))
		else
			bad "$fixture: expected the policy to ACCEPT a correctly hardened client, got exit $status: $output"
		fi
		continue
	fi

	# A rejection fixture must be rejected, AND for the declared reason.
	if [ "$status" -eq 0 ]; then
		bad "$fixture: the policy ACCEPTED a deliberately unsafe fixture. Expected rejection '$expectation'."
		continue
	fi
	if [ "$status" -ne 1 ]; then
		bad "$fixture: policy-eval exited $status (not a clean rejection): $output"
		continue
	fi
	if ! printf '%s\n' "$output" | grep -q "^FAIL ${expectation}:"; then
		bad "$fixture: rejected, but not for the declared reason '$expectation'. A rejection for the wrong reason proves nothing about the property under test. Got:"
		printf '%s\n' "$output" | sed 's/^/              /'
		continue
	fi
	printf 'REJECTED    %-56s (%s)\n' "$fixture" "$expectation"
	reject_count=$((reject_count + 1))
done < <(grep -v '^#' "$CASES_FILE" | grep -v '^[[:space:]]*$')

# ---------------------------------------------------------------------------
# 3. Non-vacuity. A run that evaluated nothing must not report success.
# ---------------------------------------------------------------------------
if [ "$pass_count" -eq 0 ]; then
	bad "no ACCEPT case was proven; the policies may be rejecting everything, which is not a working guard either"
fi
if [ "$reject_count" -lt 16 ]; then
	bad "only $reject_count rejections proven; this wave shipped at least 16"
fi

note ""
note "accepted: $pass_count   rejected-for-the-stated-reason: $reject_count   problems: $failures"
if [ "$failures" -ne 0 ]; then
	note "SENSITIVITY PROOF FAILED"
	exit 1
fi
note "sensitivity proof complete"
