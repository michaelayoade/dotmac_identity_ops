#!/usr/bin/env bash
# deploy.sh — deploy the Keycloak control plane from an EXACT repository commit.
#
# The commit is the unit of deployment, not the working tree and not a branch
# name. A branch is a moving label; "we deployed main" is not an answer to
# "which policy was in force at 03:00". Every run records the 40-character
# commit it deployed and the image digests it ran, and refuses to proceed from
# a dirty tree.
#
#   ./bin/deploy.sh <commit-sha>
#
# The deployment is not finished when the containers come up. It is finished
# when bin/verify.sh has graded the LIVE realm against the committed policy. A
# failed verification triggers bin/rollback.sh and exits nonzero.
#
# Knobs (documented defaults):
#   CONFIG_ENV_FILE       operator knobs, non-secret  (./.env, from .env.example)
#   SECRET_ENV_FILE       rendered from OpenBao, removed on exit (./.env.secrets)
#   BAO_KEYCLOAK_PATH     OpenBao KV location    (REQUIRED, no default)
#   REQUIRE_IMAGE_DIGEST  refuse an unpinned image (true)
#   DEPLOY_LOG            deployment record       (./deploy-log.tsv)
#   SKIP_ROLLBACK         leave a failed deploy in place for inspection (false)

set -euo pipefail

if [[ $- == *x* ]]; then
	echo "deploy.sh: refusing to run under xtrace; OpenBao material would reach the trace" >&2
	exit 2
fi

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_ROOT"

COMMIT="${1:-${IDENTITY_OPS_COMMIT:-}}"
# TWO files, deliberately. The operator's non-secret knobs (image digest pin,
# ports, hostnames) are AUTHORED and persist; the credential file is RENDERED at
# deploy time and removed on exit. One file for both would mean this script
# truncating the operator's configuration — including the image digest it is
# about to check — every time it ran.
CONFIG_ENV_FILE="${CONFIG_ENV_FILE:-$REPO_ROOT/.env}"
SECRET_ENV_FILE="${SECRET_ENV_FILE:-$REPO_ROOT/.env.secrets}"
REQUIRE_IMAGE_DIGEST="${REQUIRE_IMAGE_DIGEST:-true}"
DEPLOY_LOG="${DEPLOY_LOG:-$REPO_ROOT/deploy-log.tsv}"
SKIP_ROLLBACK="${SKIP_ROLLBACK:-false}"
KC_COMPOSE_FILE="${KC_COMPOSE_FILE:-$REPO_ROOT/compose/docker-compose.yml}"
KC_COMPOSE_PROJECT="${KC_COMPOSE_PROJECT:-keycloak}"
KC_SERVICE="${KC_SERVICE:-keycloak}"
KC_DB_SERVICE="${KC_DB_SERVICE:-postgres}"
BAO="${BAO:-bao}"

die() {
	echo "deploy.sh: $*" >&2
	exit 1
}

[ -n "$COMMIT" ] || die "usage: deploy.sh <commit-sha>. A deployment names an exact commit; a branch name is a moving label."
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "'$COMMIT' is not a full 40-character commit sha. An abbreviated sha can become ambiguous as the repository grows."

echo "== 1. pin the source =="
git rev-parse --verify "${COMMIT}^{commit}" >/dev/null 2>&1 || die "commit $COMMIT is not in this repository"
[ -z "$(git status --porcelain)" ] || die "the working tree is dirty. Deploy a commit, never a desk."
git checkout --detach "$COMMIT" >/dev/null
HEAD_SHA="$(git rev-parse HEAD)"
[ "$HEAD_SHA" = "$COMMIT" ] || die "checked out $HEAD_SHA, expected $COMMIT"
echo "ok    deploying exactly $COMMIT"

echo
echo "== 2. offline policy gate =="
# The same gate CI runs. A deployment must not be the first time the desired
# state is graded.
"$REPO_ROOT/bin/check-policy.sh" || die "the committed desired state does not satisfy its own policy; refusing to deploy it"

echo
echo "== 3. operator configuration =="
if [ -r "$CONFIG_ENV_FILE" ]; then
	set -a
	# The path is an operator knob, so it cannot be constant and ShellCheck
	# cannot follow it. The directive has to sit on the `.` itself: a
	# directive applies to the NEXT command, so above `set -a` it silently
	# covered the wrong line.
	# shellcheck source=/dev/null
	. "$CONFIG_ENV_FILE"
	set +a
	echo "ok    loaded $CONFIG_ENV_FILE"
else
	echo "note  no $CONFIG_ENV_FILE; every knob falls back to its documented default (see .env.example)"
fi

echo
echo "== 4. credentials from OpenBao =="
# Read, hold, deliver. Never printed, never committed, never left behind.
# ADR-0009: a secret is held, not dereferenced — these are read ONCE here, at
# deploy time, and nothing on a request path ever reaches a secret store.
#
# BAO_KEYCLOAK_PATH is REQUIRED and deliberately has NO default. The location of
# the estate's credentials is not repository content: a default would publish it.
# Checked HERE, after step 3, so the operator may set it in $CONFIG_ENV_FILE as
# well as in the environment — a `:?` up at the knob block would fire before
# that file had been read.
: "${BAO_KEYCLOAK_PATH:?is not set. It names the OpenBao KV location holding the Keycloak database and admin material, and has no default because this repository does not record where the estate keeps its credentials. Set it in ./.env (see .env.example) or export it; the operator private runbook holds the value.}"
command -v "$BAO" >/dev/null || die "the '$BAO' client is not on PATH; cannot read $BAO_KEYCLOAK_PATH"
umask 077
: >"$SECRET_ENV_FILE"
cleanup() { rm -f "$SECRET_ENV_FILE"; }
trap cleanup EXIT
{
	echo "# RENDERED AT DEPLOY TIME FROM $BAO_KEYCLOAK_PATH. Not committed; removed on exit."
	for field in db_name db_user db_password admin_user admin_password; do
		case "$field" in
		db_name) key=KC_DB_NAME ;;
		db_user) key=KC_DB_USER ;;
		db_password) key=KC_DB_PASSWORD ;;
		admin_user) key=KC_ADMIN_USER ;;
		admin_password) key=KC_ADMIN_PASSWORD ;;
		esac
		value="$("$BAO" kv get -field="$field" "$BAO_KEYCLOAK_PATH")" ||
			die "could not read field '$field' from $BAO_KEYCLOAK_PATH"
		[ -n "$value" ] || die "field '$field' at $BAO_KEYCLOAK_PATH is empty"
		printf '%s=%s\n' "$key" "$value"
	done
} >>"$SECRET_ENV_FILE"
# The names are logged. The values never are.
echo "ok    rendered $(grep -c '^KC_' "$SECRET_ENV_FILE") knobs from $BAO_KEYCLOAK_PATH (names only: $(grep -o '^KC_[A-Z_]*' "$SECRET_ENV_FILE" | tr '\n' ' '))"

set -a
# Rendered at deploy time from OpenBao; never a constant path. Same placement
# rule as step 3 above.
# shellcheck source=/dev/null
. "$SECRET_ENV_FILE"
set +a

# Both files reach Compose. Neither is ever committed; .gitignore refuses them
# and bin/check-no-secrets.sh refuses a tree that contains one anyway.
compose() {
	local -a envs=()
	# `[ ... ] && envs+=(...)` would return 1 when the file is absent, and under
	# `set -e` that exits the script. An `if` is not stylistic here.
	if [ -r "$CONFIG_ENV_FILE" ]; then envs+=(--env-file "$CONFIG_ENV_FILE"); fi
	envs+=(--env-file "$SECRET_ENV_FILE")
	docker compose "${envs[@]}" -p "$KC_COMPOSE_PROJECT" -f "$KC_COMPOSE_FILE" "$@"
}

echo
echo "== 5. image pins =="
if [ "$REQUIRE_IMAGE_DIGEST" = "true" ]; then
	[ -n "${KEYCLOAK_IMAGE_DIGEST:-}" ] ||
		die "KEYCLOAK_IMAGE_DIGEST is empty and REQUIRE_IMAGE_DIGEST=true. A tag is a moving label; pin the digest or set REQUIRE_IMAGE_DIGEST=false deliberately."
fi
compose pull
for svc in "$KC_SERVICE" "$KC_DB_SERVICE"; do
	img="$(compose config --images "$svc" 2>/dev/null | head -1)"
	digest="$(docker image inspect "$img" --format '{{index .RepoDigests 0}}' 2>/dev/null || echo "unknown")"
	echo "ok    $svc -> $img ($digest)"
done
if [ "$REQUIRE_IMAGE_DIGEST" = "true" ]; then
	kc_img="$(compose config --images "$KC_SERVICE" | head -1)"
	actual="$(docker image inspect "$kc_img" --format '{{index .RepoDigests 0}}' | sed 's/.*@//')"
	[ "$actual" = "$KEYCLOAK_IMAGE_DIGEST" ] ||
		die "the pulled Keycloak image digest is $actual but KEYCLOAK_IMAGE_DIGEST pins $KEYCLOAK_IMAGE_DIGEST"
fi

echo
echo "== 6. bring up =="
compose up -d

echo
echo "== 7. apply desired state =="
"$REPO_ROOT/bin/apply-clients.sh"

echo
echo "== 8. verify the LIVE realm =="
if "$REPO_ROOT/bin/verify.sh"; then
	printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$COMMIT" "verified" "${KEYCLOAK_IMAGE_DIGEST:-unpinned}" >>"$DEPLOY_LOG"
	echo
	echo "deploy.sh: $COMMIT deployed and VERIFIED against the live realm"
	exit 0
fi

printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$COMMIT" "verify-failed" "${KEYCLOAK_IMAGE_DIGEST:-unpinned}" >>"$DEPLOY_LOG"
echo
echo "deploy.sh: the live realm does NOT satisfy the committed policy after deployment." >&2
if [ "$SKIP_ROLLBACK" = "true" ]; then
	echo "deploy.sh: SKIP_ROLLBACK=true, leaving the deployment in place for inspection." >&2
	exit 1
fi
echo "deploy.sh: rolling back." >&2
"$REPO_ROOT/bin/rollback.sh" || echo "deploy.sh: ROLLBACK ALSO FAILED — this is a page, see docs/RECOVERY.md" >&2
exit 1
