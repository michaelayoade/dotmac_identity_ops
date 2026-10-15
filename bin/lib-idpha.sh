#!/usr/bin/env bash
# lib-idpha.sh — shared helpers for the IdP HA node scripts. SOURCE it; it does
# nothing on its own.
#
# Conventions every HA script follows (AGENTS.md § 1, § 10):
#   * DRY-RUN by default. Nothing changes unless APPLY=1 (or --apply).
#   * Environment-specific values (addresses, peers, buckets, allowlists) are
#     NEVER in this repository. They come from a root-owned values file, named
#     by IDPHA_VALUES (default /etc/idpha/idpha.env). Its contents are the
#     operator's private runbook; this repo documents only the variable NAMES
#     (ha/idpha.env.example).
#   * Every file replaced is first copied to IDPHA_BACKUP_DIR so rollback is a
#     copy back, never a guess.
#   * No secret value is ever printed. put_file prints a hash, not content.
#
# Bash 3.2 compatible on purpose (tests also run on a workstation shell).

IDPHA_VALUES="${IDPHA_VALUES:-/etc/idpha/idpha.env}"
IDPHA_BACKUP_DIR="${IDPHA_BACKUP_DIR:-/var/lib/idpha/backup}"
IDPHA_ROOT="${IDPHA_ROOT:-}" # test hook: prefix for every host path written
# One stamp per run: every file replaced in this run lands under one backup dir,
# so a rollback of the run is one copy back.
IDPHA_RUN_STAMP="${IDPHA_RUN_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
APPLY="${APPLY:-0}"
IDPHA_REPLACE_EXISTING="${IDPHA_REPLACE_EXISTING:-0}"

die() {
	echo "REFUSING: $*" >&2
	exit 1
}
note() { printf '%s\n' "$*"; }
okline() { printf 'ok    %s\n' "$*"; }
planline() { printf 'PLAN  %s\n' "$*"; }

is_apply() { [ "$APPLY" = "1" ]; }

mode_banner() {
	if is_apply; then
		note "== APPLY mode =="
	else
		note "== DRY-RUN (nothing changes; set APPLY=1 or pass --apply) =="
	fi
}

# file_mode <path> -> octal permission bits (GNU, then BSD stat)
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
# file_owner <path> -> numeric uid
file_owner() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"; }

# load_values: source the private values file, exported. Refuses a values file
# that is group/world accessible or not owned by root (unless the test hook
# IDPHA_ALLOW_UNSAFE_VALUES=1), because it is executed as shell.
load_values() {
	[ -r "$IDPHA_VALUES" ] || die "values file '$IDPHA_VALUES' is not readable. It holds the node's private values; the operator private runbook records where it comes from. This repository never carries them."
	local m o
	m="$(file_mode "$IDPHA_VALUES")"
	o="$(file_owner "$IDPHA_VALUES")"
	if [ "${IDPHA_ALLOW_UNSAFE_VALUES:-0}" != "1" ]; then
		[ "$o" = "0" ] || die "values file is not owned by root (uid $o)"
		case "$m" in 600 | 400) ;; *) die "values file mode is $m; require 600" ;; esac
	fi
	set -a
	# shellcheck disable=SC1090
	. "$IDPHA_VALUES"
	set +a
}

# require VAR... : every named variable must be set and non-empty.
require() {
	local v
	for v in "$@"; do
		[ -n "${!v:-}" ] || die "required value $v is unset or empty in $IDPHA_VALUES"
	done
}

# is_ipv4 / is_cidr: strict shape checks for values that reach firewall rules.
is_ipv4() {
	local ip="$1" o
	[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
	local IFS=.
	# shellcheck disable=SC2086
	set -- $ip
	for o in "$@"; do [ "$o" -le 255 ] || return 1; done
}
is_cidr() {
	local c="$1"
	if [[ "$c" == */* ]]; then
		is_ipv4 "${c%/*}" && [[ "${c#*/}" =~ ^[0-9]+$ ]] && [ "${c#*/}" -le 32 ]
	else
		is_ipv4 "$c"
	fi
}

hostpath() { printf '%s%s' "$IDPHA_ROOT" "$1"; }

sha_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'; else shasum -a 256 | awk '{print $1}'; fi
}

# render <template>: replace @@NAME@@ tokens from the environment. A token with
# no variable is an ERROR (a half-rendered nginx or firewall file must never
# be installed). Values are inserted literally, never re-scanned.
render() {
	awk '
	{
		rest = $0; out = ""
		while (match(rest, /@@[A-Za-z0-9_]+@@/)) {
			name = substr(rest, RSTART + 2, RLENGTH - 4)
			if (!(name in ENVIRON)) { printf "UNRESOLVED @@%s@@ (line %d)\n", name, NR > "/dev/stderr"; bad = 1 }
			out = out substr(rest, 1, RSTART - 1) ENVIRON[name]
			rest = substr(rest, RSTART + RLENGTH)
		}
		print out rest
	}
	END { exit bad }' "$1"
}

# put_file <dest> <mode> [guard]  — content on stdin.
#   dry-run : prints the destination, mode and content hash (never content)
#   apply   : backs up the existing file, installs atomically
#   guard   : "guard" refuses to replace a DIFFERENT existing file unless
#             IDPHA_REPLACE_EXISTING=1 (used where the live content is unknown
#             to this repository, e.g. an existing etcd drop-in).
put_file() {
	local dest mode guard tmp newsum oldsum="" real
	dest="$1"
	mode="$2"
	guard="${3:-}"
	real="$(hostpath "$dest")"
	tmp="$(mktemp)"
	cat >"$tmp"
	newsum="$(sha_of <"$tmp")"
	[ -f "$real" ] && oldsum="$(sha_of <"$real")"
	if [ "$newsum" = "$oldsum" ]; then
		okline "$dest already current (sha256 ${newsum:0:12})"
		rm -f "$tmp"
		return 0
	fi
	if [ -n "$oldsum" ] && [ "$guard" = "guard" ] && [ "$IDPHA_REPLACE_EXISTING" != "1" ]; then
		rm -f "$tmp"
		die "$dest exists with different content; review it, then re-run with IDPHA_REPLACE_EXISTING=1"
	fi
	if ! is_apply; then
		planline "write $dest mode $mode sha256 ${newsum:0:12} ($([ -n "$oldsum" ] && echo replaces || echo new))"
		rm -f "$tmp"
		return 0
	fi
	local bdir
	bdir="$(hostpath "$IDPHA_BACKUP_DIR")/$IDPHA_RUN_STAMP"
	mkdir -p "$bdir"
	if [ -n "$oldsum" ]; then
		mkdir -p "$bdir$(dirname "$dest")"
		cp -p "$real" "$bdir$dest"
		note "      backup -> $bdir$dest"
	else
		echo "$dest" >>"$bdir/.created"
	fi
	mkdir -p "$(dirname "$real")"
	install -m "$mode" "$tmp" "$real"
	rm -f "$tmp"
	okline "wrote $dest mode $mode"
}

# remove_file <dest>: rollback helper, backs up first.
remove_file() {
	local dest="$1" real
	real="$(hostpath "$dest")"
	[ -e "$real" ] || {
		okline "$dest already absent"
		return 0
	}
	if ! is_apply; then
		planline "remove $dest"
		return 0
	fi
	local bdir
	bdir="$(hostpath "$IDPHA_BACKUP_DIR")/$IDPHA_RUN_STAMP"
	mkdir -p "$bdir$(dirname "$dest")"
	cp -p "$real" "$bdir$dest"
	rm -f "$real"
	okline "removed $dest (copy in $bdir)"
}

# run <cmd...>: print in dry-run, execute in apply. Output of the command is
# the command's own; callers never pass secrets as arguments.
run() {
	if is_apply; then
		note "RUN   $*"
		"$@"
	else
		planline "$*"
	fi
}

parse_common_flags() {
	# Consumes --apply / --dry-run; leaves the rest in REST_ARGS (array).
	REST_ARGS=()
	local a
	for a in "$@"; do
		case "$a" in
			--apply) APPLY=1 ;;
			--dry-run) APPLY=0 ;;
			*) REST_ARGS+=("$a") ;;
		esac
	done
}

# ---- shared expectations (used by harden-ha.sh AND host-check.sh so the
# applier and the checker cannot drift apart) ------------------------------

# ufw_allow_args: one rule per line, as arguments to `ufw`. Needs the values
# loaded. Public: ssh/http/https. WireGuard transport only from the two peers.
# Everything else (etcd, Patroni, PostgreSQL, JGroups, ACME peer hops) rides
# the overlay interface, which is allowed as a whole.
ufw_allow_args() {
	echo "allow ${SSH_PORT:-22}/tcp comment ssh"
	echo "allow 80/tcp comment acme+redirect"
	echo "allow 443/tcp comment https"
	echo "allow from ${PEER_PUBLIC_1} to any port ${WG_PORT:-51820} proto udp comment wg"
	echo "allow from ${PEER_PUBLIC_2} to any port ${WG_PORT:-51820} proto udp comment wg"
	echo "allow in on ${WG_IF:-wg0} comment overlay"
}

# Units that must start after the overlay exists (H-F2: the etcd boot race,
# repeated by keepalived). docker is included because the Keycloak container
# joins the overlay through host networking.
# shellcheck disable=SC2034 # used by the scripts that source this file
ORDERED_UNITS="keepalived patroni docker etcd"
# Units needrestart must never restart on its own (H-F1: a daily failover).
# shellcheck disable=SC2034
NO_RESTART_UNITS="patroni haproxy nginx keepalived etcd"

dropin_after_wg() {
	local unit="$1"
	cat <<CONF
# Managed by dotmac_identity_ops (bin/harden-ha.sh). ${unit} must not start
# before the WireGuard overlay exists: it binds or peers over it.
[Unit]
After=${WG_UNIT:-wg-quick@wg0.service} network-online.target
Wants=${WG_UNIT:-wg-quick@wg0.service}
CONF
	if [ "$unit" = "keepalived" ]; then
		cat <<'CONF'

# keepalived exits with a permanent CONFIG error if the interface is missing and
# has no Restart= by default; it then stays dead until a human notices.
[Service]
Restart=on-failure
RestartSec=5s
CONF
	fi
}

# restore_run <stamp>: undo one run — put every backed-up file back and remove
# every file that run created. Refuses an unknown stamp.
restore_run() {
	local stamp="$1" bdir f rel
	[[ "$stamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "backup stamp '$stamp' is not of the form YYYYMMDDTHHMMSSZ"
	bdir="$(hostpath "$IDPHA_BACKUP_DIR")/$stamp"
	[ -d "$bdir" ] || die "no backup run $stamp under $IDPHA_BACKUP_DIR"
	while IFS= read -r f; do
		rel="${f#"$bdir"}"
		if is_apply; then
			mkdir -p "$(dirname "$(hostpath "$rel")")"
			cp -p "$f" "$(hostpath "$rel")"
			okline "restored $rel"
		else
			planline "restore $rel"
		fi
	done < <(find "$bdir" -type f ! -name .created)
	if [ -f "$bdir/.created" ]; then
		while IFS= read -r rel; do
			if is_apply; then
				rm -f "$(hostpath "$rel")"
				okline "removed $rel (created by run $stamp)"
			else
				planline "remove $rel (created by run $stamp)"
			fi
		done <"$bdir/.created"
	fi
}
