#!/usr/bin/env bash
# check-policy.sh — the OFFLINE gate. This is what CI runs.
#
# It needs no Keycloak, no database, no container and no network: jq and a
# shell over committed JSON. That separation is deliberate. The live verifier
# (bin/verify.sh) can only run where a real realm is reachable, so if the guard
# lived only there it would never gate a change; and a guard that never runs on
# a pull request is documentation.
#
# Four things, in order:
#   1. every JSON file in the repository parses
#   2. the committed desired state is internally consistent AND satisfies the
#      same policies the live verifier applies
#   3. the sensitivity proof (tests/run-policy-tests.sh)
#   4. no secret value has been committed
#
# Knobs: REPO_ROOT (derived).

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_ROOT"

MANIFEST="${MANIFEST:-realm/expected-clients.json}"
CLIENT_DIR="${CLIENT_DIR:-realm/clients}"
EVAL="$REPO_ROOT/bin/policy-eval.sh"

problems=0
fail() {
	printf 'FAIL  %s\n' "$*"
	problems=$((problems + 1))
}
ok() { printf 'ok    %s\n' "$*"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== 1. JSON parse =="
json_count=0
while IFS= read -r f; do
	json_count=$((json_count + 1))
	if ! jq -e . "$f" >/dev/null 2>&1; then
		fail "$f does not parse as JSON"
	fi
done < <(find . -path ./.git -prune -o -type f -name '*.json' -print | sort)
if [ "$json_count" -eq 0 ]; then
	fail "no JSON files found; this check would otherwise pass over nothing"
else
	ok "$json_count JSON files parse"
fi

echo
echo "== 2. desired state =="
if ! jq -e . "$MANIFEST" >/dev/null 2>&1; then
	fail "$MANIFEST unreadable; cannot continue"
	exit 1
fi

managed=0
while IFS= read -r entry; do
	client_id="$(jq -r '.clientId' <<<"$entry")"
	class="$(jq -r '.class' <<<"$entry")"
	file="$(jq -r '.desired_state_file // ""' <<<"$entry")"

	if [ -z "$file" ]; then
		fail "$client_id: class $class declares no desired_state_file"
		continue
	fi
	if [ ! -r "$file" ]; then
		fail "$client_id: desired_state_file $file is missing"
		continue
	fi
	managed=$((managed + 1))

	# The manifest and the client document must agree. Two files describing one
	# client is exactly the drift shape ADR-0065 § 7 was written about, so the
	# overlap is asserted rather than trusted.
	actual_enabled="$(jq -c '.enabled' "$file")"
	want_enabled="$(jq -c '.enabled' <<<"$entry")"
	[ "$actual_enabled" = "$want_enabled" ] ||
		fail "$client_id: enabled=$actual_enabled in $file but $want_enabled in $MANIFEST"

	actual_redirects="$(jq -c '(.redirectUris // []) | sort' "$file")"
	want_redirects="$(jq -c '(.redirect_uris // []) | sort' <<<"$entry")"
	[ "$actual_redirects" = "$want_redirects" ] ||
		fail "$client_id: redirect URIs $actual_redirects in $file but $want_redirects in $MANIFEST"

	actual_origins="$(jq -c '(.webOrigins // []) | sort' "$file")"
	want_origins="$(jq -c '(.web_origins // []) | sort' <<<"$entry")"
	[ "$actual_origins" = "$want_origins" ] ||
		fail "$client_id: web origins $actual_origins in $file but $want_origins in $MANIFEST"

	case "$class" in
	mobile-native) policy=mobile ;;
	confidential-web) policy=web ;;
	*)
		fail "$client_id: class $class has no shape policy"
		continue
		;;
	esac

	printf '%s' "$entry" >"$work/entry.json"
	set +e
	out="$("$EVAL" "$policy" "$work/entry.json" "$file" 2>&1)"
	status=$?
	set -e
	if [ "$status" -eq 0 ]; then
		ok "$client_id ($class) satisfies the $policy policy"
	else
		fail "$client_id ($class) violates the $policy policy:"
		printf '%s\n' "$out" | sed 's/^/        /'
	fi
done < <(jq -c '.clients[] | select(.class != "keycloak-builtin")' "$MANIFEST")

if [ "$managed" -eq 0 ]; then
	fail "the manifest declares no managed client; the desired-state check would pass over nothing"
fi

# No orphan desired-state file: a client document nobody declared is a client
# nobody reviewed.
while IFS= read -r f; do
	cid="$(jq -r '.clientId // ""' "$f")"
	if ! jq -e --arg c "$cid" 'any(.clients[]; .clientId == $c)' "$MANIFEST" >/dev/null; then
		fail "$f describes client '$cid', which $MANIFEST does not declare"
	fi
done < <(find "$CLIENT_DIR" -type f -name '*.json' | sort)

# The realm inventory baseline fixture must still describe the real desired
# state, or the fixture would keep passing after the desired state changed.
BASELINE="tests/fixtures/realm/pass/baseline.json"
for f in "$CLIENT_DIR"/*.json; do
	cid="$(jq -r '.clientId' "$f")"
	if ! jq -e --slurpfile want "$f" --arg c "$cid" \
		'[.realm_clients[] | select(.clientId == $c)] == $want' "$BASELINE" >/dev/null; then
		fail "$BASELINE has drifted from $f; the inventory baseline no longer describes the committed desired state"
	fi
done

echo
echo "== 3. sensitivity proof =="
if ! "$REPO_ROOT/tests/run-policy-tests.sh"; then
	fail "the sensitivity proof did not hold"
fi

echo
echo "== 4. no committed secret value =="
if ! "$REPO_ROOT/bin/check-no-secrets.sh"; then
	fail "a secret value appears to have been committed"
fi

echo
if [ "$problems" -ne 0 ]; then
	echo "check-policy: $problems problem(s)"
	exit 1
fi
echo "check-policy: all offline gates hold"
