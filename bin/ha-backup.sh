#!/usr/bin/env bash
# ha-backup.sh — hourly logical backup of the Keycloak database on an IdP HA
# node: pg_dump | age | object store. Installed on all three nodes; ONLY THE
# PATRONI LEADER backs up (the others log "not leader, skip" and exit 0).
#
# The plaintext dump never touches disk: pg_dump streams into age, and only
# ciphertext is staged (root-only, removed on exit) so size and header can be
# checked BEFORE the object is uploaded. The bucket is Object Locked, so an
# upload cannot be taken back; a bad object must never be sent.
#
# DRY-RUN unless --apply / APPLY=1 (the systemd unit passes --apply). Dry-run
# still performs the leader check, which is read-only.
#
# Values (private; see ha/idpha.env.example). Required:
#   NODE_NAME OVERLAY_ADDR BACKUP_MC_ALIAS BACKUP_BUCKET BACKUP_PREFIX
#   BACKUP_AGE_RECIPIENT_FILE   file holding the age recipient(s) (public)
#   PGDUMP_FORMAT_ARGS          MUST match the single-host backup so the existing
#                               validator needs no change; no default on purpose
# Optional: KC_DB_NAME (keycloak) PG_DUMP_USER (postgres) PATRONI_PORT (8008)
#           MIN_CIPHERTEXT_BYTES (1024) IDPHA_STATE_DIR (/var/lib/idpha)
# Object-store credentials arrive as MC_HOST_<alias> in the environment from the
# unit's EnvironmentFile; they are never read from, or written to, this repo.

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

parse_common_flags "$@"
mode_banner
load_values
require NODE_NAME OVERLAY_ADDR BACKUP_MC_ALIAS BACKUP_BUCKET BACKUP_PREFIX BACKUP_AGE_RECIPIENT_FILE PGDUMP_FORMAT_ARGS
is_ipv4 "$OVERLAY_ADDR" || die "OVERLAY_ADDR is not an IPv4 address"
[[ "$NODE_NAME" =~ ^[A-Za-z0-9-]+$ ]] || die "NODE_NAME has unexpected characters"
[[ "$BACKUP_PREFIX" =~ ^[A-Za-z0-9/_-]+$ ]] || die "BACKUP_PREFIX has unexpected characters"

KC_DB_NAME="${KC_DB_NAME:-keycloak}"
PG_DUMP_USER="${PG_DUMP_USER:-postgres}"
PATRONI_PORT="${PATRONI_PORT:-8008}"
MIN_CIPHERTEXT_BYTES="${MIN_CIPHERTEXT_BYTES:-1024}"
IDPHA_STATE_DIR="${IDPHA_STATE_DIR:-/var/lib/idpha}"

# ---- leader guard -----------------------------------------------------------
# Patroni answers 200 on /primary only on the leader. Any other answer (replica,
# unreachable, mid-failover) means: not us, not now.
if ! curl -sf --max-time 3 -o /dev/null "http://${OVERLAY_ADDR}:${PATRONI_PORT}/primary"; then
	note "not leader, skip"
	exit 0
fi
okline "this node is the Patroni leader"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
key="${BACKUP_PREFIX%/}/keycloak-${NODE_NAME}-${stamp}.sql.age"
dest="${BACKUP_MC_ALIAS}/${BACKUP_BUCKET}/${key}"

if ! is_apply; then
	planline "pg_dump ($KC_DB_NAME, args from values) | age -R <recipient file> -> staged ciphertext"
	planline "check ciphertext >= ${MIN_CIPHERTEXT_BYTES} bytes and age header, then mc cp -> ${BACKUP_BUCKET}/${key}"
	exit 0
fi

[ -r "$BACKUP_AGE_RECIPIENT_FILE" ] || die "age recipient file not readable"
umask 077
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
staged="$stage/dump.age"

# shellcheck disable=SC2086 # PGDUMP_FORMAT_ARGS is a reviewed, space-separated flag list
runuser -u "$PG_DUMP_USER" -- pg_dump $PGDUMP_FORMAT_ARGS "$KC_DB_NAME" | age -R "$BACKUP_AGE_RECIPIENT_FILE" >"$staged"

size="$(wc -c <"$staged" | tr -d ' ')"
[ "$size" -ge "$MIN_CIPHERTEXT_BYTES" ] || die "ciphertext is only $size bytes: refusing to upload a truncated backup"
head -c 21 "$staged" | grep -q '^age-encryption.org/v1' || die "staged object has no age header: refusing to upload"

mc cp --quiet "$staged" "$dest" >/dev/null
mkdir -p "$IDPHA_STATE_DIR"
date +%s >"$IDPHA_STATE_DIR/backup.last.tmp"
mv "$IDPHA_STATE_DIR/backup.last.tmp" "$IDPHA_STATE_DIR/backup.last"
echo "uploaded ${key} (${size} bytes)"
