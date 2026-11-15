#!/usr/bin/env bash
# Source after kcadm() is defined. The only raw response path is this pipe from
# Keycloak's server-masked export into an isolated, bounded JSON projection.
set -euo pipefail
kcadm_snapshot() { # <projected-output-file> [realm]
	local output="$1" realm="${2:-$KC_REALM}"
	if ! (
		set -o pipefail
		kcadm create partial-export -r "$realm" -q exportClients=true -q exportGroupsAndRoles=false -o |
			python3 -I -S -B "$REPO_ROOT/bin/project-kcadm-snapshot.py" \
				"$REPO_ROOT" "$MANIFEST" "${REALM_DESIRED:-$REPO_ROOT/realm/dotmac-realm.json}"
	) >"$output" 2>/dev/null; then
		echo "kcadm snapshot unavailable; verification is unproven" >&2
		return 1
	fi
}
