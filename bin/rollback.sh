#!/usr/bin/env bash
# rollback.sh — return the control plane to a known-good state.
#
# There are TWO things to roll back and they are independent, which is the
# whole reason this script exists rather than a one-line `git checkout`:
#
#   A. the OPERATIONAL FILES — compose, desired state, policy, verifier. These
#      live in this repository and roll back by deploying an earlier commit.
#   B. the REALM DATABASE — users, credentials, sessions, signing keys. These
#      live in Postgres and roll back only from a backup, which is a DESTRUCTIVE
#      operation with its own decision (docs/RECOVERY.md).
#
# This script does A. It refuses to do B implicitly: restoring a database over
# a live realm silently discards every credential change, disable and MFA
# enrolment made since the backup, and that is a human decision, not a fallback
# path a failed deployment takes on its own.
#
#   ./bin/rollback.sh [commit-sha]
#
# With no argument it rolls back to the last commit this repository recorded as
# `verified` in the deployment log, which is the only local record of a state
# the live verifier actually approved.
#
# Knobs: DEPLOY_LOG (./deploy-log.tsv), plus every knob bin/deploy.sh documents.

set -euo pipefail

if [[ $- == *x* ]]; then
	echo "rollback.sh: refusing to run under xtrace" >&2
	exit 2
fi

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_ROOT"
DEPLOY_LOG="${DEPLOY_LOG:-$REPO_ROOT/deploy-log.tsv}"

die() {
	echo "rollback.sh: $*" >&2
	exit 1
}

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
	[ -r "$DEPLOY_LOG" ] || die "no target given and no deployment log at $DEPLOY_LOG. Name the commit explicitly."
	TARGET="$(awk -F'\t' '$3 == "verified" { c = $2 } END { print c }' "$DEPLOY_LOG")"
	[ -n "$TARGET" ] || die "the deployment log records no verified commit to return to. Name one explicitly."
	echo "rollback: last verified commit is $TARGET"
fi

[[ "$TARGET" =~ ^[0-9a-f]{40}$ ]] || die "'$TARGET' is not a full 40-character commit sha"
git rev-parse --verify "${TARGET}^{commit}" >/dev/null 2>&1 || die "commit $TARGET is not in this repository"

echo "rollback: redeploying operational files from $TARGET"
echo "rollback: the realm DATABASE is deliberately untouched. If the incident is"
echo "          data loss or corruption rather than configuration, stop here and"
echo "          follow docs/RECOVERY.md § 'Restoring the realm database'."

SKIP_ROLLBACK=true exec "$REPO_ROOT/bin/deploy.sh" "$TARGET"
