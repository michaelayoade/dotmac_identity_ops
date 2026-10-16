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
# Parameters: the typed params document (sections node, ha-backup). Required there: the store
# alias, bucket, prefix, age recipient file and the dump flags (no default on purpose: they MUST
# match the single-host backup so the existing validator needs no change). Optional: KC_DB_NAME (keycloak) PG_DUMP_USER (postgres) PATRONI_PORT (8008)
#           MIN_CIPHERTEXT_BYTES (10240, the single host's own floor) IDPHA_STATE_DIR (/var/lib/idpha)
# Object-store settings and credentials arrive as RCLONE_CONFIG_<REMOTE>_* (or, for the mc
# fallback, MC_HOST_<alias>) in the environment from the unit's EnvironmentFile (a
# root-600 file named by reference); they are never in this repo or on a command line.

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

parse_common_flags "$@"
idpha_begin ha-backup runtime
mode_banner
is_ipv4 "$OVERLAY_ADDR" || die "OVERLAY_ADDR is not an IPv4 address"
[[ "$NODE_NAME" =~ ^[A-Za-z0-9-]+$ ]] || die "NODE_NAME has unexpected characters"
[[ "$BACKUP_PREFIX" =~ ^[A-Za-z0-9/_-]+$ ]] || die "BACKUP_PREFIX has unexpected characters"

BACKUP_UPLOADER="${BACKUP_UPLOADER:-rclone}"
case "$BACKUP_UPLOADER" in
	rclone) require BACKUP_REMOTE ;;
	mc) require BACKUP_MC_ALIAS ;;
	*) die "BACKUP_UPLOADER must be rclone or mc" ;;
esac
KC_DB_NAME="${KC_DB_NAME:-keycloak}"
PG_DUMP_USER="${PG_DUMP_USER:-postgres}"
PATRONI_PORT="${PATRONI_PORT:-8008}"
MIN_CIPHERTEXT_BYTES="${MIN_CIPHERTEXT_BYTES:-10240}"
IDPHA_STATE_DIR="${IDPHA_STATE_DIR:-/var/lib/idpha}"

# ---- leader guard -----------------------------------------------------------
# Patroni answers 200 on /primary only on the leader. Any other answer (replica,
# unreachable, mid-failover) means: not us, not now.
if ! curl -sf --max-time 3 -o /dev/null "http://${OVERLAY_ADDR}:${PATRONI_PORT}/primary"; then
	note "not leader, skip"
	effect "$(_tab skip "not leader")"
	idpha_end
	exit 0
fi
okline "this node is the Patroni leader"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
key="${BACKUP_PREFIX%/}/keycloak-${NODE_NAME}-${stamp}.sql.age"
if [ "$BACKUP_UPLOADER" = rclone ]; then dest="${BACKUP_REMOTE}:${BACKUP_BUCKET}/${key}"; else dest="${BACKUP_MC_ALIAS}/${BACKUP_BUCKET}/${key}"; fi

if ! is_apply; then
	planline "pg_dump ($KC_DB_NAME, args from values) | age -R <recipient file> -> staged ciphertext"
	planline "check ciphertext >= ${MIN_CIPHERTEXT_BYTES} bytes and age header, then ${BACKUP_UPLOADER} -> ${BACKUP_BUCKET}/${key}"
	effect "$(_tab upload "${BACKUP_BUCKET}/${BACKUP_PREFIX%/}/keycloak-${NODE_NAME}-<UTC>.sql.age")"
	idpha_end
	exit 0
fi

[ -r "$BACKUP_AGE_RECIPIENT_FILE" ] || die "age recipient file not readable"
command -v age >/dev/null 2>&1 || die "age is not installed (ha-install.sh backup-tools)"
command -v "$BACKUP_UPLOADER" >/dev/null 2>&1 || die "$BACKUP_UPLOADER is not installed (ha-install.sh backup-tools)"
umask 077
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
staged="$stage/dump.age"

# shellcheck disable=SC2086 # PGDUMP_FORMAT_ARGS is a reviewed, space-separated flag list
runuser -u "$PG_DUMP_USER" -- pg_dump $PGDUMP_FORMAT_ARGS "$KC_DB_NAME" | age -R "$BACKUP_AGE_RECIPIENT_FILE" >"$staged"

size="$(wc -c <"$staged" | tr -d ' ')"
[ "$size" -ge "$MIN_CIPHERTEXT_BYTES" ] || die "ciphertext is only $size bytes: refusing to upload a truncated backup"
head -c 21 "$staged" | grep -q '^age-encryption.org/v1' || die "staged object has no age header: refusing to upload"

if [ "$BACKUP_UPLOADER" = rclone ]; then
	# Settings and credentials arrive ONLY as RCLONE_CONFIG_<REMOTE>_* variables
	# (the unit's EnvironmentFile): never argv, never a config file. The bucket is
	# write-only/object-locked, so no listing or HEAD is attempted.
	rclone copyto --config /dev/null --s3-no-check-bucket --s3-no-head --quiet "$staged" "$dest" >/dev/null
else
	mkdir -p "$IDPHA_STATE_DIR/mc"
	mc --config-dir "$IDPHA_STATE_DIR/mc" cp --quiet "$staged" "$dest" >/dev/null
fi
mkdir -p "$IDPHA_STATE_DIR"
date +%s >"$IDPHA_STATE_DIR/backup.last.tmp"
mv "$IDPHA_STATE_DIR/backup.last.tmp" "$IDPHA_STATE_DIR/backup.last"
echo "uploaded ${key} (${size} bytes)"
idpha_end
