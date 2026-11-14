#!/usr/bin/env bash
# apply-clients.sh — push the committed desired state into the realm.
#
# Applies ONLY the fields this repository declares. It does not create clients
# it does not know about and it does not delete unknown ones: deleting a client
# is a decision with a blast radius, so an unknown client is REPORTED by the
# inventory policy and removed by a human, not silently reaped by a script.
#
# `kcadm update -f` sends the declared representation, not a field-level merge,
# so a declared file that has drifted from the live realm OVERWRITES live
# settings. Therefore updating an existing client is opt-in and can be scoped:
#
# Knobs: as bin/verify.sh, plus
#   APPLY_DRY_RUN       print what would change, change nothing. Each would-UPDATE
#                       prints a field-level diff (declared keys vs the live value
#                       of the same keys; the `secret` field is never read into the
#                       comparison or printed)                          (false)
#   APPLY_ONLY          comma-separated clientIds. Clients not listed get no create
#                       and no update. A name that is not an applicable client in
#                       the manifest is refused (exit 2). Empty = all   ()
#   --only <clientId>   CLI form of APPLY_ONLY; repeatable, adds to it
#   APPLY_ALLOW_UPDATE  must be `true` for ANY update of an existing client. Without
#                       it a run that would update refuses (exit 3) BEFORE writing
#                       anything. Creating missing clients needs no opt-in.  (false)
#
# The admin password is exported as KCADM_PASSWORD and passed to the container by
# NAME only (`-e KCADM_PASSWORD`), so it is never in the host's argv. The kcadm
# login cache in the container is removed on exit (best effort). Client reads have
# `.secret` stripped before they reach any temp file.

set -euo pipefail

if [[ $- == *x* ]]; then
	echo "apply-clients.sh: refusing to run under xtrace" >&2
	exit 2
fi

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KC_COMPOSE_FILE="${KC_COMPOSE_FILE:-$REPO_ROOT/compose/docker-compose.yml}"
KC_COMPOSE_PROJECT="${KC_COMPOSE_PROJECT:-keycloak}"
KC_SERVICE="${KC_SERVICE:-keycloak}"
KC_REALM="${KC_REALM:-dotmac}"
KC_INTERNAL_URL="${KC_INTERNAL_URL:-http://localhost:8080}"
KC_ADMIN_REALM="${KC_ADMIN_REALM:-master}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
MANIFEST="${MANIFEST:-$REPO_ROOT/realm/expected-clients.json}"
APPLY_DRY_RUN="${APPLY_DRY_RUN:-false}"
APPLY_ONLY="${APPLY_ONLY:-}"
APPLY_ALLOW_UPDATE="${APPLY_ALLOW_UPDATE:-false}"

while [ "$#" -gt 0 ]; do
	case "$1" in
	--only)
		[ "$#" -ge 2 ] && [ -n "$2" ] || { echo "apply-clients.sh: --only needs a clientId" >&2; exit 2; }
		APPLY_ONLY="${APPLY_ONLY:+$APPLY_ONLY,}$2"
		shift 2
		;;
	*)
		echo "apply-clients.sh: unknown argument '$1' (usage: apply-clients.sh [--only <clientId>]...)" >&2
		exit 2
		;;
	esac
done

# Resolve the selection against the manifest BEFORE any container call: a typo
# must refuse, not silently apply to nothing (or to everything).
only_list=()
if [ -n "$APPLY_ONLY" ]; then
	IFS=',' read -r -a _raw <<<"$APPLY_ONLY"
	for _n in "${_raw[@]}"; do
		_n="${_n//[[:space:]]/}"
		if [ -n "$_n" ]; then only_list+=("$_n"); fi
	done
	if [ "${#only_list[@]}" -eq 0 ]; then
		echo "apply-clients.sh: APPLY_ONLY is set but names no client; refusing" >&2
		exit 2
	fi
	for _n in "${only_list[@]}"; do
		if ! jq -e --arg c "$_n" '.clients[] | select(.class != "keycloak-builtin" and .clientId == $c)' "$MANIFEST" >/dev/null; then
			echo "apply-clients.sh: APPLY_ONLY names '$_n', which is not an applicable client in $MANIFEST; refusing" >&2
			exit 2
		fi
	done
fi
selected() { # selected <clientId>
	[ "${#only_list[@]}" -eq 0 ] && return 0
	local n
	for n in "${only_list[@]}"; do [ "$n" = "$1" ] && return 0; done
	return 1
}

: "${KC_ADMIN_PASSWORD:?apply-clients.sh: KC_ADMIN_PASSWORD is not set. Read it from the OpenBao location named by BAO_KEYCLOAK_PATH, field admin_password — the operator private runbook records that location; never place the value in a file.}"

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
	docker compose ${envs[@]+"${envs[@]}"} -p "$KC_COMPOSE_PROJECT" -f "$KC_COMPOSE_FILE" "$@"
}

# Every `docker compose exec -T` gets exactly ONE stdin owner. That is why the
# desired-state document is STAGED into the container by its own exec first and
# then referenced by path, rather than piped into kcadm: a wrapper that
# redirects `</dev/null` would otherwise silently swallow the JSON, and kcadm
# would apply an empty body.
kcadm() {
	dc exec -T -e KCADM_PASSWORD "$KC_SERVICE" \
		/opt/keycloak/bin/kcadm.sh "$@" </dev/null
}

stage() { # stage <local-file> <in-container-path>
	dc exec -T "$KC_SERVICE" sh -c 'cat > "$0"' "$2" <"$1"
}

# By NAME only: docker reads the value from this process's environment, so it is
# never an argument visible to ps/auditd on the host.
export KCADM_PASSWORD="$KC_ADMIN_PASSWORD"

work="$(mktemp -d)"
logged_in=false
# Best effort: `kcadm config credentials` leaves a master-admin token cache in
# the container; remove it however this script exits.
cleanup() {
	rm -rf "$work"
	if [ "$logged_in" = true ]; then
		dc exec -T "$KC_SERVICE" sh -c 'rm -f "$HOME/.keycloak/kcadm.config"' </dev/null >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

logged_in=true
dc exec -T -e KCADM_PASSWORD "$KC_SERVICE" \
	sh -c '/opt/keycloak/bin/kcadm.sh config credentials --server "$0" --realm "$1" --user "$2" --password "$KCADM_PASSWORD" >/dev/null' \
	"$KC_INTERNAL_URL" "$KC_ADMIN_REALM" "$KC_ADMIN_USER" </dev/null

# Only ids and names are needed from the list; .secret is stripped as it is
# captured, before anything is written to disk.
kcadm get clients -r "$KC_REALM" --fields id,clientId | jq 'map(del(.secret))' >"$work/clients.json"

# Pass 1: plan. Nothing is written here.
plan=()
n_update=0
while IFS= read -r entry; do
	client_id="$(jq -r '.clientId' <<<"$entry")"
	selected "$client_id" || continue
	file="$REPO_ROOT/$(jq -r '.desired_state_file' <<<"$entry")"
	uuid="$(jq -r --arg c "$client_id" '.[] | select(.clientId == $c) | .id' "$work/clients.json" | head -1)"
	if [ -z "$uuid" ] || [ "$uuid" = "null" ]; then
		plan+=("create|$client_id|$file|")
	else
		plan+=("update|$client_id|$file|$uuid")
		n_update=$((n_update + 1))
	fi
done < <(jq -c '.clients[] | select(.class != "keycloak-builtin")' "$MANIFEST")

if [ "$n_update" -gt 0 ] && [ "$APPLY_ALLOW_UPDATE" != "true" ] && [ "$APPLY_DRY_RUN" != "true" ]; then
	echo "apply-clients: refusing to UPDATE existing client(s) without APPLY_ALLOW_UPDATE=true." >&2
	echo "  kcadm update -f overwrites live settings with the declared file. Run APPLY_DRY_RUN=true to see the diff," >&2
	echo "  then scope the run with APPLY_ONLY / --only. Nothing was written." >&2
	for p in ${plan[@]+"${plan[@]}"}; do
		IFS='|' read -r action cid _ _ <<<"$p"
		if [ "$action" = update ]; then echo "  would refuse: UPDATE $cid" >&2; fi
	done
	exit 3
fi

# Field-level diff: declared keys vs the live value of the same keys. The live
# representation has .secret stripped at capture; declared .secret (there should
# be none) is dropped too. Prints key names and non-secret values only.
show_diff() { # show_diff <client_id> <uuid> <declared-file> (client_id is for the caller's log only)
	local uuid="$2"
	kcadm get "clients/$uuid" -r "$KC_REALM" | jq 'del(.secret)' >"$work/live.json"
	local out
	out="$(jq -r --slurpfile live "$work/live.json" '
		(del(.secret)) as $d | $live[0] as $l
		| [ $d | to_entries[] | select(.value != $l[.key])
		    | "    \(.key): declared=\(.value | tojson) live=\($l[.key] | tojson)"
		    + (if .key == "attributes" and ((.value | type) == "object") and (($l[.key] | type) == "object")
		       then "\n      live-only attribute keys (dropped if the update replaces attributes): \([ $l[.key] | keys[] | select(. as $k | ($d.attributes | has($k)) | not) ] | tojson)"
		       else "" end) ]
		| .[]' "$3")"
	if [ -z "$out" ]; then
		echo "    no change"
	else
		printf '%s\n' "$out"
	fi
}

# Pass 2: act.
for p in ${plan[@]+"${plan[@]}"}; do
	IFS='|' read -r action client_id file uuid <<<"$p"

	if [ "$APPLY_DRY_RUN" = "true" ]; then
		if [ "$action" = create ]; then
			echo "would CREATE $client_id from $file"
		else
			echo "would UPDATE $client_id ($uuid) from $file"
			show_diff "$client_id" "$uuid" "$file"
			[ "$APPLY_ALLOW_UPDATE" = "true" ] || echo "    (a real run would refuse this update: APPLY_ALLOW_UPDATE is not true)"
		fi
		continue
	fi

	staged="/tmp/dotmac-desired-$client_id.json"
	stage "$file" "$staged"
	if [ "$action" = create ]; then
		echo "creating $client_id"
		kcadm create clients -r "$KC_REALM" -f "$staged"
	else
		echo "updating $client_id"
		kcadm update "clients/$uuid" -r "$KC_REALM" -f "$staged"
	fi
	dc exec -T "$KC_SERVICE" rm -f "$staged" </dev/null
done

echo "apply-clients: desired state applied. bin/verify.sh is what proves it took."
