#!/usr/bin/env bash
# patroni-sync.sh — apply the reviewed Patroni DCS patch (ha/patroni/dcs-sync.yml)
# and read it back. Run ONCE, from any one node, as a user that can run
# patronictl. DRY-RUN unless APPLY=1 / --apply.
#
#   patroni-sync.sh show        read-only: current values of the three keys + member table
#   patroni-sync.sh apply       preflight, edit-config of exactly the patch keys, readback
#   patroni-sync.sh rollback    synchronous_mode=false (back to asynchronous)
#
# Refuses when the cluster is not healthy: not exactly one Leader, a member not
# running/streaming, non-zero lag, or the patch file contains a key outside the
# allowlist. Changing replication mode on a cluster that is already degraded
# hides the degradation behind a stalled commit.
#
# Parameters: the typed params document (node.patroni_conf, operations.patroni-sync);
#        --plan prints the effect + digest, --apply needs --expect-digest.
# Knobs: PATRONICTL (patronictl)
#        PATCH_FILE (ha/patroni/dcs-sync.yml) SYNC_WAIT_S (45)

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$LIB_DIR/.." && pwd)}"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

PATRONICTL="${PATRONICTL:-patronictl}"
PATRONI_CONF="${PATRONI_CONF:-}"
PATCH_FILE="${PATCH_FILE:-$REPO_ROOT/ha/patroni/dcs-sync.yml}"
SYNC_WAIT_S="${SYNC_WAIT_S:-45}"
ALLOWED_KEYS="synchronous_mode synchronous_mode_strict synchronous_node_count"

parse_common_flags "$@"
set -- ${REST_ARGS[@]+"${REST_ARGS[@]}"}
cmd="${1:-show}"
[ "$cmd" = "show" ] && APPLY=0
idpha_begin patroni-sync
mode_banner
require PATRONI_CONF

pctl() { "$PATRONICTL" -c "$PATRONI_CONF" "$@"; }

# patch_pairs: "key value" per line, validated against the allowlist.
patch_pairs() {
	local line k v
	[ -r "$PATCH_FILE" ] || die "patch file $PATCH_FILE missing"
	while IFS= read -r line; do
		case "$line" in '' | '#'*) continue ;; esac
		[[ "$line" =~ ^([a-z_]+):[[:space:]]*([A-Za-z0-9]+)[[:space:]]*$ ]] || die "unparseable patch line: $line"
		k="${BASH_REMATCH[1]}"
		v="${BASH_REMATCH[2]}"
		case " $ALLOWED_KEYS " in *" $k "*) ;; *) die "patch key '$k' is not in the allowlist ($ALLOWED_KEYS)" ;; esac
		echo "$k $v"
	done <"$PATCH_FILE"
}

# current <key>: value from show-config (top-level keys only), empty if unset
current() {
	pctl show-config 2>/dev/null | awk -v k="$1" '$0 ~ "^"k":" {sub("^"k":[ ]*",""); print; exit}'
}

member_table() { pctl list -f tsv 2>/dev/null; }

# preflight: exactly one Leader, every member running/streaming, lag 0.
preflight() {
	local table
	table="$(member_table)" || die "patronictl list failed"
	[ -n "$table" ] || die "patronictl list returned nothing"
	local verdict
	verdict="$(printf '%s\n' "$table" | awk -F'\t' '
		NR == 1 { for (i = 1; i <= NF; i++) { if ($i == "Role") r = i; if ($i == "State") s = i; if ($i ~ /^Lag/) l = i } next }
		{ n++
		  if ($r ~ /Leader/) leaders++
		  if ($s != "running" && $s != "streaming") bad++
		  if ($r !~ /Leader/ && l && $l != "0" && $l != "") lag++ }
		END { printf "members=%d leaders=%d notok=%d lagging=%d", n, leaders, bad, lag }')"
	note "preflight: $verdict"
	case "$verdict" in
		"members=3 leaders=1 notok=0 lagging=0") okline "cluster healthy" ;;
		*) die "cluster is not in the expected healthy shape (3 members, 1 leader, all running/streaming, lag 0): $verdict" ;;
	esac
}

readback() {
	local k want got rc=0
	[ -n "${PAIRS:-}" ] || die "internal: patch pairs not loaded"
	while read -r k want; do
		got="$(current "$k")"
		if [ "$got" = "$want" ]; then
			okline "$k = $got"
		else
			echo "FAIL  $k is '${got:-unset}', patch wants '$want'"
			rc=1
		fi
	done <<<"$PAIRS"
	return $rc
}

wait_sync_standby() {
	local i=0
	while [ "$i" -lt "$SYNC_WAIT_S" ]; do
		if member_table | grep -q 'Sync Standby'; then
			okline "a Sync Standby is present"
			return 0
		fi
		sleep 3
		i=$((i + 3))
	done
	echo "FAIL  no Sync Standby within ${SYNC_WAIT_S}s: roll back with 'patroni-sync.sh rollback' if it does not appear"
	return 1
}

do_show() {
	local k
	for k in $ALLOWED_KEYS; do printf '  %-26s %s\n' "$k" "$(current "$k")"; done
	member_table | sed 's/^/  /'
}

do_apply() {
	# Load and validate the patch BEFORE touching anything: a die inside a
	# process substitution would not stop this shell.
	PAIRS="$(patch_pairs)" || exit 1
	preflight
	local -a args=()
	local k v
	while read -r k v; do args+=(-s "$k=$v"); done <<<"$PAIRS"
	[ "${#args[@]}" -gt 0 ] || die "patch has no keys"
	note "keys to set: $(printf '%s' "$PAIRS" | tr '\n' ';')"
	run "$PATRONICTL" -c "$PATRONI_CONF" edit-config "${args[@]}" --force
	if is_apply; then
		readback || die "readback differs from the reviewed patch"
		wait_sync_standby || exit 1
	else
		planline "readback of the three keys, then wait up to ${SYNC_WAIT_S}s for a Sync Standby"
	fi
}

do_rollback() {
	run "$PATRONICTL" -c "$PATRONI_CONF" edit-config -s synchronous_mode=false --force
	if is_apply; then
		[ "$(current synchronous_mode)" = "false" ] || die "rollback readback: synchronous_mode is not false"
		okline "synchronous_mode = false"
	fi
}

case "$cmd" in
	show) do_show ;;
	apply) do_apply ;;
	rollback) do_rollback ;;
	*) die "unknown command '$cmd'" ;;
esac
idpha_end
