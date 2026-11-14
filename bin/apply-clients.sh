#!/usr/bin/env bash
# apply-clients.sh — push the committed desired state into the realm.
#
# Applies ONLY the fields this repository declares. It does not create clients
# it does not know about and it does not delete unknown ones: deleting a client
# is a decision with a blast radius, so an unknown client is REPORTED by the
# inventory policy and removed by a human, not silently reaped by a script.
#
# Keycloak merges top-level fields and `attributes` key by key on update, so
# keys this repository does not declare are left alone. But every key it DOES
# declare is overwritten with the declared value, so a declared file that has
# drifted from the live realm (redirectUris, webOrigins, fullScopeAllowed, the
# PKCE attribute, post-logout URIs) silently changes live settings. Therefore
# updating an existing client is opt-in and can be scoped:
#
# Knobs: as bin/verify.sh, plus
#   APPLY_DRY_RUN       print what would change, change nothing. Each would-UPDATE
#                       prints a field-level diff (declared keys vs the live value
#                       of the same keys; arrays compared sorted, an empty-string
#                       attribute equals an absent one; live-only attribute keys
#                       are listed by NAME only). `secret` and
#                       attributes["client.secret.rotated"] are removed at capture
#                       and never compared or printed)                  (false)
#   APPLY_ONLY          comma-separated clientIds. Clients not listed get no create
#                       and no update. A name that is not an applicable client in
#                       the manifest is refused (exit 2). Empty = all   ()
#   --only <clientId>   CLI form of APPLY_ONLY; repeatable. If given at all it
#                       REPLACES any APPLY_ONLY from the environment
#   APPLY_ALLOW_UPDATE  must be `true` for ANY update of an existing client. Without
#                       it a run that would update refuses (exit 3) BEFORE writing
#                       anything. Creating missing clients needs no opt-in. Setting
#                       it to true REQUIRES APPLY_ONLY/--only (else exit 2).  (false)
#
# The resolved client list is printed before anything is done.
#
# The admin password is exported as KC_CLI_PASSWORD (which kcadm reads when
# --password is omitted) and passed to the container by NAME only
# (`-e KC_CLI_PASSWORD`), so it is on no argv, host or container. Each run uses
# its own kcadm login cache and staging directory inside the container (a
# mktemp -d, passed as `--config`), removed exactly on exit, so concurrent runs
# cannot delete each other's login. Client reads have `.secret` and
# attributes["client.secret.rotated"] stripped before any temp file.

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

cli_only=false
while [ "$#" -gt 0 ]; do
	case "$1" in
	--only)
		[ "$#" -ge 2 ] && [ -n "$2" ] || { echo "apply-clients.sh: --only needs a clientId" >&2; exit 2; }
		# The CLI replaces the environment's APPLY_ONLY (once), then accumulates.
		if [ "$cli_only" = false ]; then APPLY_ONLY=""; cli_only=true; fi
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
if [ "$APPLY_ALLOW_UPDATE" = "true" ] && [ "${#only_list[@]}" -eq 0 ]; then
	echo "apply-clients.sh: APPLY_ALLOW_UPDATE=true requires APPLY_ONLY (or --only); refusing to update without a scope" >&2
	exit 2
fi
if [ "${#only_list[@]}" -eq 0 ]; then
	echo "apply-clients: scope: all applicable clients in the manifest: $(jq -r '[.clients[] | select(.class != "keycloak-builtin") | .clientId] | join(",")' "$MANIFEST")"
else
	echo "apply-clients: scope: $(IFS=,; echo "${only_list[*]}")"
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
	dc exec -T "$KC_SERVICE" \
		/opt/keycloak/bin/kcadm.sh "$@" --config "$kc_cfg" </dev/null
}

stage() { # stage <local-file> <in-container-path>
	dc exec -T "$KC_SERVICE" sh -c 'cat > "$0"' "$2" <"$1"
}

# By NAME only: docker reads the value from this process's environment, so it is
# on no argv. kcadm reads KC_CLI_PASSWORD when --password is omitted.
export KC_CLI_PASSWORD="$KC_ADMIN_PASSWORD"

work="$(mktemp -d)"
kc_dir=""
kc_cfg=""
# Best effort, however this script exits: remove THIS run's private directory in
# the container (login cache + staged files, including after a failed create or
# update). Exactly that path, never a shared one.
cleanup() {
	rm -rf "$work"
	if [ -n "$kc_dir" ]; then
		dc exec -T "$KC_SERVICE" rm -rf "$kc_dir" </dev/null >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

kc_dir="$(dc exec -T "$KC_SERVICE" mktemp -d /tmp/kcadm.XXXXXX </dev/null)"
case "$kc_dir" in /tmp/kcadm.?*) ;; *) echo "apply-clients: could not create a private kcadm directory in the container" >&2; kc_dir=""; exit 1 ;; esac
kc_cfg="$kc_dir/kcadm.config"

dc exec -T -e KC_CLI_PASSWORD "$KC_SERVICE" \
	/opt/keycloak/bin/kcadm.sh config credentials --server "$KC_INTERNAL_URL" --realm "$KC_ADMIN_REALM" --user "$KC_ADMIN_USER" --config "$kc_cfg" >/dev/null </dev/null

# Only ids and names are needed from the list; .secret is stripped as it is
# captured, before anything is written to disk.
kcadm get clients -r "$KC_REALM" --fields id,clientId | jq 'map(del(.secret) | del(.attributes["client.secret.rotated"]))' >"$work/clients.json"

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

# Field-level diff: declared keys vs the live value of the same keys, attributes
# key by key. Arrays are compared sorted; an empty-string declared attribute
# equals an absent live one. .secret and attributes["client.secret.rotated"] are
# stripped at capture (and from the declared side). Live-only attribute keys are
# listed by NAME only, never by value.
show_diff() { # show_diff <client_id> <uuid> <declared-file> (client_id is for the caller's log only)
	local uuid="$2"
	kcadm get "clients/$uuid" -r "$KC_REALM" |
		jq 'del(.secret) | del(.attributes["client.secret.rotated"])' >"$work/live.json"
	local out names
	out="$(jq -r --slurpfile live "$work/live.json" '
		def norm: walk(if type == "array" then sort else . end);
		(del(.secret) | del(.attributes["client.secret.rotated"])) as $d | $live[0] as $l
		| ( [ $d | to_entries[] | select(.key != "attributes")
		      | select((.value | norm) != ($l[.key] | norm))
		      | "    \(.key): declared=\(.value | tojson) live=\($l[.key] | tojson)" ]
		  + [ ($d.attributes // {}) | to_entries[] | . as $e | (($l.attributes // {})[$e.key]) as $lv
		      | select(((($e.value | norm) != ($lv | norm))) and (($e.value == "" and $lv == null) | not))
		      | "    attributes.\($e.key): declared=\($e.value | tojson) live=\($lv | tojson)" ] )
		| .[]' "$3")"
	names="$(jq -r --slurpfile live "$work/live.json" '
		(del(.secret) | del(.attributes["client.secret.rotated"])) as $d | $live[0] as $l
		| [ ($l.attributes // {}) | keys[] | select(. as $k | (($d.attributes // {}) | has($k)) | not) ] | join(", ")' "$3")"
	if [ -z "$out" ]; then
		echo "    no change"
	else
		printf '%s\n' "$out"
	fi
	if [ -n "$names" ]; then echo "    live-only attribute keys (left alone, update merges per key): $names"; fi
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

	staged="$kc_dir/desired-$client_id.json"
	stage "$file" "$staged"
	if [ "$action" = create ]; then
		echo "creating $client_id"
		kcadm create clients -r "$KC_REALM" -f "$staged"
	else
		echo "updating $client_id"
		kcadm update "clients/$uuid" -r "$KC_REALM" -f "$staged"
	fi
	dc exec -T "$KC_SERVICE" rm -f "$staged" </dev/null || true
done

echo "apply-clients: desired state applied. bin/verify.sh is what proves it took."
