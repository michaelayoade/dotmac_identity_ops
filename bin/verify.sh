#!/usr/bin/env bash
# verify.sh — the LIVE verifier. Reads the running realm and grades it with the
# same policy files CI grades fixtures with (bin/policy-eval.sh is the single
# dispatcher; neither side keeps its own copy of the rules).
#
# This needs a real Keycloak. It is NOT the pull-request gate — bin/check-policy.sh
# is, and it runs offline. This one runs on the IdP host, after a deployment,
# and on a schedule as a drift check.
#
# Fail-closed by construction: `set -euo pipefail`, an explicit failure counter,
# and an EXIT trap that reports FAILED for ANY nonzero exit including one this
# script never anticipated. An unreachable admin API is a failure, not a pass.
#
# Every knob has a documented default; nothing environment-specific is baked in.
#   KC_COMPOSE_FILE   compose file            (compose/docker-compose.yml)
#   KC_COMPOSE_PROJECT compose project name   (keycloak)
#   KC_SERVICE        keycloak service name   (keycloak)
#   KC_DB_SERVICE     database service name   (postgres)
#   KC_REALM          realm to verify         (dotmac)
#   KC_INTERNAL_URL   in-container server url (http://localhost:8080)
#   KC_ADMIN_REALM    admin realm             (master)
#   KC_ADMIN_USER     admin username          (admin)
#   KC_ADMIN_PASSWORD admin password, read from the OpenBao location named by
#                     BAO_KEYCLOAK_PATH (field admin_password). That location is
#                     a REQUIRED operator input with no default and is not
#                     recorded here; see docs/SECRETS.md. NEVER a literal in any
#                     file.
#   KC_ISSUER         the PERMANENT issuer    (https://idp.dotmac.io/realms/dotmac)
#   VERIFY_DISCOVERY  check public discovery  (true)
#   VERIFY_ROLLOUT    check that a disabled client refuses a ceremony (true)

set -euo pipefail

if [[ $- == *x* ]]; then
	echo "verify.sh: refusing to run under xtrace; the admin password would reach the trace" >&2
	exit 2
fi

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KC_COMPOSE_FILE="${KC_COMPOSE_FILE:-$REPO_ROOT/compose/docker-compose.yml}"
KC_COMPOSE_PROJECT="${KC_COMPOSE_PROJECT:-keycloak}"
KC_SERVICE="${KC_SERVICE:-keycloak}"
KC_DB_SERVICE="${KC_DB_SERVICE:-postgres}"
KC_REALM="${KC_REALM:-dotmac}"
KC_INTERNAL_URL="${KC_INTERNAL_URL:-http://localhost:8080}"
KC_ADMIN_REALM="${KC_ADMIN_REALM:-master}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ISSUER="${KC_ISSUER:-https://idp.dotmac.io/realms/$KC_REALM}"
VERIFY_DISCOVERY="${VERIFY_DISCOVERY:-true}"
VERIFY_ROLLOUT="${VERIFY_ROLLOUT:-true}"
MANIFEST="${MANIFEST:-$REPO_ROOT/realm/expected-clients.json}"
REALM_DESIRED="${REALM_DESIRED:-$REPO_ROOT/realm/dotmac-realm.json}"
EVAL="$REPO_ROOT/bin/policy-eval.sh"

: "${KC_ADMIN_PASSWORD:?verify.sh: KC_ADMIN_PASSWORD is not set. Read it into the environment from the OpenBao location named by BAO_KEYCLOAK_PATH, field admin_password — the operator private runbook records that location; never place the value in a file.}"

failures=0
# Set BEFORE anything can fail, and replaced once the temp dir exists. Any exit
# path — an assertion failure, an unreachable admin API, an unanticipated
# `set -e` abort — prints a verdict, so a silent exit can never read as a pass.
verdict="FAILED"
trap 'echo; echo "verify.sh: $verdict"' EXIT

fail() {
	printf 'FAIL  %s\n' "$*"
	failures=$((failures + 1))
}
ok() { printf 'ok    %s\n' "$*"; }

work="$(mktemp -d)"
# Same verdict, now also cleaning up. Replacing the trap rather than adding a
# second one, because bash keeps only the last EXIT trap.
trap 'rm -rf "$work"; echo; echo "verify.sh: $verdict"' EXIT

# Compose must be able to interpolate `${KC_DB_NAME:?}` and friends even when
# this script is run on its own (e.g. `make verify`), not only as a step inside
# bin/deploy.sh which has already exported them. Both env files are passed when
# present; neither is ever committed.
CONFIG_ENV_FILE="${CONFIG_ENV_FILE:-$REPO_ROOT/.env}"
SECRET_ENV_FILE="${SECRET_ENV_FILE:-$REPO_ROOT/.env.secrets}"

dc() {
	local -a envs=()
	if [ -r "$CONFIG_ENV_FILE" ]; then envs+=(--env-file "$CONFIG_ENV_FILE"); fi
	if [ -r "$SECRET_ENV_FILE" ]; then envs+=(--env-file "$SECRET_ENV_FILE"); fi
	docker compose "${envs[@]}" -p "$KC_COMPOSE_PROJECT" -f "$KC_COMPOSE_FILE" "$@"
}

# Every `docker compose exec -T` redirects stdin from /dev/null. A script that
# is itself being fed on stdin and then nests an exec that also consumes stdin
# will silently eat its own remaining lines; stdin gets exactly one owner.
kcadm() {
	dc exec -T -e KCADM_PASSWORD="$KC_ADMIN_PASSWORD" "$KC_SERVICE" \
		/opt/keycloak/bin/kcadm.sh "$@" </dev/null
}

kc_login() {
	dc exec -T -e KCADM_PASSWORD="$KC_ADMIN_PASSWORD" "$KC_SERVICE" \
		sh -c '/opt/keycloak/bin/kcadm.sh config credentials \
		    --server "$0" --realm "$1" --user "$2" --password "$KCADM_PASSWORD" >/dev/null' \
		"$KC_INTERNAL_URL" "$KC_ADMIN_REALM" "$KC_ADMIN_USER" </dev/null
}

echo "== containers =="
for svc in "$KC_SERVICE" "$KC_DB_SERVICE"; do
	state="$(dc ps --format json "$svc" 2>/dev/null | jq -r '.State // .Status // "unknown"' | head -1)"
	if [ "$state" = "running" ]; then
		ok "$svc is running"
	else
		fail "$svc is '$state', not running"
	fi
done

echo
echo "== admin session =="
if kc_login; then
	ok "authenticated to $KC_ADMIN_REALM as $KC_ADMIN_USER (password never printed)"
else
	fail "could not authenticate to the admin API; every assertion below is unproven"
	verdict="FAILED — admin API unreachable"
	exit 1
fi

echo
echo "== realm =="
kcadm get "realms/$KC_REALM" >"$work/realm.json" || fail "could not read realm $KC_REALM"
if [ -s "$work/realm.json" ]; then
	while IFS= read -r key; do
		want="$(jq -c --arg k "$key" '.[$k]' "$REALM_DESIRED")"
		got="$(jq -c --arg k "$key" '.[$k]' "$work/realm.json")"
		if [ "$want" = "$got" ]; then
			ok "realm.$key = $got"
		else
			fail "realm.$key is $got but the desired state says $want"
		fi
	done < <(jq -r 'keys[] | select(startswith("_") | not)' "$REALM_DESIRED")
fi

echo
echo "== client inventory =="
kcadm get clients -r "$KC_REALM" >"$work/clients.json" || fail "could not list clients"
if [ -s "$work/clients.json" ]; then
	if "$EVAL" realm "$MANIFEST" "$work/clients.json"; then
		ok "the realm holds exactly the declared client inventory"
	else
		fail "client inventory does not match realm/expected-clients.json"
	fi
fi

echo
echo "== client shape =="
while IFS= read -r entry; do
	client_id="$(jq -r '.clientId' <<<"$entry")"
	class="$(jq -r '.class' <<<"$entry")"
	case "$class" in
	mobile-native) policy=mobile ;;
	confidential-web) policy=web ;;
	*)
		fail "$client_id: class $class has no shape policy"
		continue
		;;
	esac

	# Fetch the client by its internal id, so the FULL representation is graded.
	# `kcadm --fields attributes` can render `{}` for nested attributes, which
	# would turn a MISSING S256 pin into a silent pass — the exact failure this
	# verifier exists to prevent.
	uuid="$(jq -r --arg c "$client_id" '.[] | select(.clientId == $c) | .id' "$work/clients.json" | head -1)"
	if [ -z "$uuid" ] || [ "$uuid" = "null" ]; then
		fail "$client_id: not present in the realm"
		continue
	fi
	kcadm get "clients/$uuid" -r "$KC_REALM" >"$work/client.json" || {
		fail "$client_id: could not read the full client representation"
		continue
	}
	printf '%s' "$entry" >"$work/entry.json"

	if "$EVAL" "$policy" "$work/entry.json" "$work/client.json"; then
		ok "$client_id satisfies the $policy policy"
	else
		fail "$client_id violates the $policy policy (detail above)"
	fi

	# A disabled pre-rollout client must actually refuse a ceremony, not merely
	# carry enabled=false in a JSON document. Configuration is a claim; the
	# authorization endpoint's answer is the evidence.
	if [ "$VERIFY_ROLLOUT" = "true" ] && [ "$(jq -r '.enabled' <<<"$entry")" = "false" ]; then
		code="$(curl -s -o /dev/null -w '%{http_code}' \
			"$KC_ISSUER/protocol/openid-connect/auth?client_id=$client_id&response_type=code&redirect_uri=https://example.invalid/&scope=openid&code_challenge=x&code_challenge_method=S256" || echo 000)"
		if [ "$code" = "400" ]; then
			ok "$client_id refuses an authorization request while disabled (HTTP 400)"
		else
			fail "$client_id is declared disabled but the authorization endpoint answered HTTP $code, not 400"
		fi
	fi
done < <(jq -c '.clients[] | select(.class != "keycloak-builtin")' "$MANIFEST")

if [ "$VERIFY_DISCOVERY" = "true" ]; then
	echo
	echo "== public discovery =="
	if curl -fsS "$KC_ISSUER/.well-known/openid-configuration" >"$work/disco.json"; then
		got_issuer="$(jq -r '.issuer' "$work/disco.json")"
		if [ "$got_issuer" = "$KC_ISSUER" ]; then
			ok "issuer is the permanent $KC_ISSUER"
		else
			# Changing the issuer orphans every external_identity_bindings row in
			# every relying party rather than renaming them.
			fail "issuer is $got_issuer, not the permanent $KC_ISSUER"
		fi
		jwks="$(jq -r '.jwks_uri' "$work/disco.json")"
		if curl -fsS "$jwks" | jq -e '[.keys[] | select(.alg == "RS256")] | length > 0' >/dev/null; then
			ok "JWKS advertises an RS256 key"
		else
			fail "JWKS advertises no RS256 key"
		fi
		# Recorded, not asserted: these are REALM-level advertisements. ADR-0069
		# § 4 makes the mitigation per-client, and the per-client pins are what
		# the shape policy above asserts.
		echo "note  realm advertises code_challenge_methods_supported = $(jq -c '.code_challenge_methods_supported' "$work/disco.json")"
		echo "note  realm advertises grant_types_supported = $(jq -c '.grant_types_supported' "$work/disco.json")"
		echo "note  both are expected to be permissive; the control is the per-client pin, not the realm advertisement."
	else
		fail "could not fetch $KC_ISSUER/.well-known/openid-configuration"
	fi
fi

echo
if [ "$failures" -ne 0 ]; then
	verdict="FAILED ($failures assertion(s))"
	exit 1
fi
verdict="PASSED"
