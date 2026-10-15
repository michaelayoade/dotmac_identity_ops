#!/usr/bin/env bash
# verify-ha.sh — bin/verify.sh for the IdP HA layout (packet H2.5). The policy,
# the dispatcher and every assertion are verify.sh's: this file only maps the
# HA node's layout onto its knobs, so CI and production cannot grade different
# rules (AGENTS.md § 3). No invariant is dropped; the `ops` realm is added.
#
# Differences from the single-host layout, all expressed as knobs:
#   * compose lives in the node deployment directory (HA_DIR, a private value),
#     project keycloak-ha, container `keycloak`
#   * the database is Patroni/HAProxy, not a compose service -> KC_DB_SERVICE empty
#   * kcadm authenticates as the verifier SERVICE ACCOUNT (client credentials),
#     not an admin password; the secret is read from a root-600 env file and
#     handed on in the environment, never on a command line
#   * discovery/JWKS/auth are fetched from Keycloak on loopback, not through DNS
#     (before the cutover DNS still points at the old host and would be graded
#     instead of this node); the ISSUER is still compared with the permanent one
#
# Usage (root, on the node):  bin/verify-ha.sh
# Knobs: HA_VERIFY_ENV ($HA_DIR/verify.env, root 600, defines
#        KC_VERIFY_CLIENT_ID and KC_VERIFY_CLIENT_SECRET)  HA_COMPOSE_FILE
#        VERIFY_EXTRA_REALMS (ops)  plus every verify.sh knob.

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

if [[ $- == *x* ]]; then
	echo "verify-ha.sh: refusing to run under xtrace; the client secret would reach the trace" >&2
	exit 2
fi

load_values
require HA_DIR
HA_VERIFY_ENV="${HA_VERIFY_ENV:-$HA_DIR/verify.env}"
[ -r "$HA_VERIFY_ENV" ] || die "verifier credentials file not readable (root 600; the operator places them there by hidden prompt)"
if [ "${IDPHA_ALLOW_UNSAFE_VALUES:-0}" != "1" ]; then
	[ "$(file_mode "$HA_VERIFY_ENV")" = "600" ] && [ "$(file_owner "$HA_VERIFY_ENV")" = "0" ] || die "verifier credentials file must be root-owned mode 600"
fi
# shellcheck disable=SC1090
. "$HA_VERIFY_ENV"
: "${KC_VERIFY_CLIENT_ID:?verify.env must define KC_VERIFY_CLIENT_ID}"
: "${KC_VERIFY_CLIENT_SECRET:?verify.env must define KC_VERIFY_CLIENT_SECRET}"

export KC_COMPOSE_FILE="${HA_COMPOSE_FILE:-$HA_DIR/compose.yml}"
export KC_COMPOSE_PROJECT="${KC_COMPOSE_PROJECT:-keycloak-ha}"
export KC_SERVICE="${KC_SERVICE:-keycloak}"
export KC_DB_SERVICE=""
export KC_INTERNAL_URL="${KC_INTERNAL_URL:-http://127.0.0.1:8080}"
export KC_ADMIN_AUTH=client
export KC_ADMIN_USER="$KC_VERIFY_CLIENT_ID"
export KC_ADMIN_PASSWORD="$KC_VERIFY_CLIENT_SECRET"
export KC_DISCOVERY_FETCH_BASE="${KC_DISCOVERY_FETCH_BASE:-http://127.0.0.1:8080/realms/${KC_REALM:-dotmac}}"
export VERIFY_EXTRA_REALMS="${VERIFY_EXTRA_REALMS-ops}"
# No .env / .env.secrets exist on an HA node; the compose file is self-contained.
export CONFIG_ENV_FILE="${CONFIG_ENV_FILE:-/nonexistent}"
export SECRET_ENV_FILE="${SECRET_ENV_FILE:-/nonexistent}"
unset KC_VERIFY_CLIENT_SECRET

exec "$LIB_DIR/verify.sh"
