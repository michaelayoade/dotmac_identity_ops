#!/usr/bin/env bash
# policy-eval.sh — the ONE dispatcher from a policy name to a jq program.
#
# Both halves of this repository go through this file: the offline fixture
# runner (tests/run-policy-tests.sh) and the live verifier (bin/verify.sh).
# That is the point. If the live verifier evaluated its own copy of the rules,
# CI would be proving a policy that production does not run.
#
# Usage: policy-eval.sh <mobile|web|realm> <context.json> <input.json>
#   mobile/web  context = the expected-clients manifest ENTRY for that client
#               input   = one complete Keycloak client representation
#   realm       context = the whole expected-clients manifest
#               input   = the realm's complete client list (a JSON array)
#
# Exit 0 = policy satisfied and NO output.
# Exit 1 = violations, printed one per line.
# Exit 2 = usage error.
# Any other nonzero = jq failed; that is a failure too, never a pass.

set -euo pipefail

if [[ $- == *x* ]]; then
	echo "policy-eval.sh: refusing to run under xtrace; traced output can carry material that must not be logged" >&2
	exit 2
fi

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
POLICY_DIR="${POLICY_DIR:-$REPO_ROOT/policy}"

if [ "$#" -ne 3 ]; then
	echo "usage: policy-eval.sh <mobile|web|realm> <context.json> <input.json>" >&2
	exit 2
fi

kind="$1"
context_file="$2"
input_file="$3"

case "$kind" in
mobile)
	program="$POLICY_DIR/verify-mobile-client.jq"
	arg_name="expected"
	;;
web)
	program="$POLICY_DIR/verify-web-client.jq"
	arg_name="expected"
	;;
realm)
	program="$POLICY_DIR/verify-realm-clients.jq"
	arg_name="manifest"
	;;
*)
	echo "policy-eval.sh: unknown policy '$kind'" >&2
	exit 2
	;;
esac

for f in "$program" "$context_file" "$input_file"; do
	if [ ! -r "$f" ]; then
		echo "policy-eval.sh: cannot read $f" >&2
		exit 2
	fi
done

# A jq error must not be mistaken for "no violations", so the substitution is
# allowed to fail the script under `set -e`.
violations="$(jq -r --argjson "$arg_name" "$(cat "$context_file")" -f "$program" "$input_file")"

if [ -n "$violations" ]; then
	printf '%s\n' "$violations"
	exit 1
fi
exit 0
