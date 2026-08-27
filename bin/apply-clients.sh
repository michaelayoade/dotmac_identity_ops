#!/usr/bin/env bash
# apply-clients.sh — push the committed desired state into the realm.
#
# Applies ONLY the fields this repository declares. It does not create clients
# it does not know about and it does not delete unknown ones: deleting a client
# is a decision with a blast radius, so an unknown client is REPORTED by the
# inventory policy and removed by a human, not silently reaped by a script.
#
# Knobs: as bin/verify.sh, plus
#   APPLY_DRY_RUN   print what would change, change nothing   (false)

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
	docker compose "${envs[@]}" -p "$KC_COMPOSE_PROJECT" -f "$KC_COMPOSE_FILE" "$@"
}

# Every `docker compose exec -T` gets exactly ONE stdin owner. That is why the
# desired-state document is STAGED into the container by its own exec first and
# then referenced by path, rather than piped into kcadm: a wrapper that
# redirects `</dev/null` would otherwise silently swallow the JSON, and kcadm
# would apply an empty body.
kcadm() {
	dc exec -T -e KCADM_PASSWORD="$KC_ADMIN_PASSWORD" "$KC_SERVICE" \
		/opt/keycloak/bin/kcadm.sh "$@" </dev/null
}

stage() { # stage <local-file> <in-container-path>
	dc exec -T "$KC_SERVICE" sh -c 'cat > "$0"' "$2" <"$1"
}

dc exec -T -e KCADM_PASSWORD="$KC_ADMIN_PASSWORD" "$KC_SERVICE" \
	sh -c '/opt/keycloak/bin/kcadm.sh config credentials --server "$0" --realm "$1" --user "$2" --password "$KCADM_PASSWORD" >/dev/null' \
	"$KC_INTERNAL_URL" "$KC_ADMIN_REALM" "$KC_ADMIN_USER" </dev/null

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

kcadm get clients -r "$KC_REALM" >"$work/clients.json"

while IFS= read -r entry; do
	client_id="$(jq -r '.clientId' <<<"$entry")"
	file="$REPO_ROOT/$(jq -r '.desired_state_file' <<<"$entry")"
	uuid="$(jq -r --arg c "$client_id" '.[] | select(.clientId == $c) | .id' "$work/clients.json" | head -1)"

	if [ "$APPLY_DRY_RUN" = "true" ]; then
		if [ -z "$uuid" ] || [ "$uuid" = "null" ]; then
			echo "would CREATE $client_id from $file"
		else
			echo "would UPDATE $client_id ($uuid) from $file"
		fi
		continue
	fi

	staged="/tmp/dotmac-desired-$client_id.json"
	stage "$file" "$staged"
	if [ -z "$uuid" ] || [ "$uuid" = "null" ]; then
		echo "creating $client_id"
		kcadm create clients -r "$KC_REALM" -f "$staged"
	else
		echo "updating $client_id"
		kcadm update "clients/$uuid" -r "$KC_REALM" -f "$staged"
	fi
	dc exec -T "$KC_SERVICE" rm -f "$staged" </dev/null
done < <(jq -c '.clients[] | select(.class != "keycloak-builtin")' "$MANIFEST")

echo "apply-clients: desired state applied. bin/verify.sh is what proves it took."
