#!/usr/bin/env bash
# lib-idpha.sh — shared helpers for the IdP HA node scripts. SOURCE it; it does
# nothing on its own.
#
# Conventions every HA script follows (AGENTS.md § 1, § 10):
#   * DRY-RUN by default. Nothing changes unless APPLY=1 (or --apply).
#   * Environment-specific values (addresses, peers, buckets, allowlists) are
#     NEVER in this repository and are NOT hand-authored files. They arrive as
#     ONE typed params document (--params <file|-> or IDPHA_PARAMS), validated
#     against ha/params.schema.json before anything runs. The document carries
#     no confidential content; credentials are named by reference (a root-600 file on the host).
#   * --plan prints the effect summary as JSON with a digest; --apply must carry
#     --expect-digest <digest>, re-plans, and refuses if the digest differs, so
#     an approval binds exactly what was previewed.
#   * Every file replaced is first copied to IDPHA_BACKUP_DIR so rollback is a
#     copy back, never a guess.
#   * No secret value is ever printed. put_file prints a hash, not content.
#
# Bash 3.2 compatible on purpose (tests also run on a workstation shell).

IDPHA_PARAMS="${IDPHA_PARAMS:-}"
IDPHA_EXPECT_DIGEST="${IDPHA_EXPECT_DIGEST:-}"
PLAN_JSON=0
IDPHA_BACKUP_DIR="${IDPHA_BACKUP_DIR:-/var/lib/idpha/backup}"
IDPHA_ROOT="${IDPHA_ROOT:-}" # test hook: prefix for every host path written
# One stamp per run: every file replaced in this run lands under one backup dir,
# so a rollback of the run is one copy back.
IDPHA_RUN_STAMP="${IDPHA_RUN_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)-$$}" # pid suffix: two runs in one second never share a backup dir
APPLY="${APPLY:-0}"
IDPHA_REPLACE_EXISTING="${IDPHA_REPLACE_EXISTING:-0}"

die() {
	echo "REFUSING: $*" >&2
	exit 1
}
note() { printf '%s\n' "$*"; }
okline() { printf 'ok    %s\n' "$*"; }
planline() { printf 'PLAN  %s\n' "$*"; }
_IDPHA_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDPHA_SCHEMA="${IDPHA_SCHEMA:-$_IDPHA_LIB_DIR/../ha/params.schema.json}"
IDPHA_EFFECTS=""

# effect <tab-separated record>: remember what a plan WOULD change. The records
# feed the --plan JSON and its digest; they hold paths, modes, content hashes
# and command lines — never content.
effect() {
	[ -n "$IDPHA_EFFECTS" ] || return 0
	printf '%s\n' "$*" | tr '\n' ' ' >>"$IDPHA_EFFECTS"
	printf '\n' >>"$IDPHA_EFFECTS"
}
_tab() { local IFS=$'\t'; printf '%s' "$*"; }

is_apply() { [ "$APPLY" = "1" ]; }

mode_banner() {
	if [ "$PLAN_JSON" = 1 ]; then
		note "== PLAN (JSON effect summary on stdout) =="
	elif is_apply; then
		note "== APPLY mode =="
	else
		note "== DRY-RUN (nothing changes; set APPLY=1 or pass --apply) =="
	fi
}

# file_mode <path> -> octal permission bits (GNU, then BSD stat)
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
# file_owner <path> -> numeric uid
file_owner() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"; }

# require VAR... : every named variable must be set and non-empty.
require() {
	local v
	for v in "$@"; do
		[ -n "${!v:-}" ] || die "required value $v is unset or empty in the params document"
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
# is_host_cidr: a SINGLE host, spelled with its full-length prefix (/32 or /128).
is_host_cidr() {
	local c="$1"
	if [[ "$c" == */32 ]]; then is_ipv4 "${c%/32}" && [ "${c%/32}" != "0.0.0.0" ]; return; fi
	if [[ "$c" == */128 && "$c" == *:* ]]; then [[ "${c%/128}" =~ ^[0-9a-fA-F:]+$ ]] && [ "${c%/128}" != "::" ]; return; fi
	return 1
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
		effect "$(_tab write "$dest" "$mode" "$newsum" "$oldsum")"
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
	[ -e "$real" ] || [ -L "$real" ] || {
		okline "$dest already absent"
		return 0
	}
	if ! is_apply; then
		planline "remove $dest"
		effect "$(_tab remove "$dest")"
		return 0
	fi
	local bdir
	bdir="$(hostpath "$IDPHA_BACKUP_DIR")/$IDPHA_RUN_STAMP"
	mkdir -p "$bdir$(dirname "$dest")"
	cp -Pp "$real" "$bdir$dest" # -P: a symlink is saved AS a symlink
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
		effect "$(_tab run "$*")"
	fi
}

# parse_common_flags "$@": consumes the flags every HA script shares and leaves
# the rest in REST_ARGS. CHILD_ARGS is the same command line minus the mode
# flags, used to re-plan before an apply.
#   --plan                 dry-run, effect summary as JSON on stdout (human text -> stderr)
#   --dry-run              dry-run, human text (the default)
#   --apply                change things; needs --expect-digest (see idpha_begin)
#   --expect-digest D      the digest of the previewed effect the approval bound
#   --params FILE|-        the typed params document (or IDPHA_PARAMS)
parse_common_flags() {
	REST_ARGS=()
	CHILD_ARGS=()
	local a want=""
	for a in "$@"; do
		if [ -n "$want" ]; then
			case "$want" in
				params)
					if [ "$a" = "-" ]; then
						IDPHA_PARAMS="$(mktemp)"
						cat >"$IDPHA_PARAMS"
						_IDPHA_TMP_PARAMS="$IDPHA_PARAMS"
					else
						IDPHA_PARAMS="$a"
					fi
					CHILD_ARGS+=(--params "$IDPHA_PARAMS")
					;;
				digest) IDPHA_EXPECT_DIGEST="$a" ;;
			esac
			want=""
			continue
		fi
		case "$a" in
			--apply) APPLY=1 ;;
			--dry-run) APPLY=0 ;;
			--plan)
				APPLY=0
				PLAN_JSON=1
				;;
			--params) want=params ;;
			--expect-digest) want=digest ;;
			*)
				REST_ARGS+=("$a")
				CHILD_ARGS+=("$a")
				;;
		esac
	done
	[ -z "$want" ] || die "flag --${want/digest/expect-digest} needs a value"
}

# idpha_begin <operation> [runtime]: load and VALIDATE the params document
# (refusing on anything missing or invalid), export the operation's values, and
# for a state-changing apply insist on the approved digest.
#   runtime  jobs run by a timer (backup, collector) and read-only checks cannot
#            carry a per-run approval; they never take --expect-digest.
idpha_begin() {
	IDPHA_OP="$1"
	local kind="${2:-}" tool="$_IDPHA_LIB_DIR/idpha-params.py" exports
	IDPHA_EFFECTS="$(mktemp)"
	[ -n "$IDPHA_PARAMS" ] || die "no params document: pass --params <file|-> or set IDPHA_PARAMS"
	[ -r "$IDPHA_PARAMS" ] || die "params document is not readable"
	exports="$(python3 -I "$tool" export --schema "$IDPHA_SCHEMA" --params "$IDPHA_PARAMS" --op "$IDPHA_OP")" || exit 1
	eval "$exports"
	# Interface-level defaults that are not topology (named in the schema as optional).
	WG_IF="${WG_IF:-wg0}"
	WG_UNIT="${WG_UNIT:-wg-quick@${WG_IF}.service}"
	WG_PORT="${WG_PORT:-51820}"
	SSH_PORT="${SSH_PORT:-22}"
	PRIMARY_NIC="${PRIMARY_NIC:-eth0}"
	if [ "$PLAN_JSON" = 1 ]; then exec 4>&1 1>&2; fi
	[ "$kind" = runtime ] || host_identity_check
	# IDPHA_CHILD marks the internal re-plan, which always runs as --plan. It is
	# never valid together with --apply: it would be a way around the digest.
	if is_apply && [ -n "${IDPHA_CHILD:-}" ]; then
		die "IDPHA_CHILD is internal to the re-plan and is refused together with --apply"
	fi
	if is_apply && [ "$kind" != runtime ]; then
		if [ -n "$IDPHA_EXPECT_DIGEST" ]; then
			local got
			got="$(IDPHA_CHILD=1 IDPHA_PARAMS="$IDPHA_PARAMS" bash "$0" ${CHILD_ARGS[@]+"${CHILD_ARGS[@]}"} --plan 2>/dev/null | python3 -I "$tool" digest-of)" || die "re-plan before apply failed"
			[ "$got" = "$IDPHA_EXPECT_DIGEST" ] || die "plan digest differs from the approved one (approved $IDPHA_EXPECT_DIGEST, now $got): re-plan and re-approve"
			okline "re-plan matches the approved digest"
		elif [ "${IDPHA_ALLOW_UNBOUND_APPLY:-0}" != 1 ] || [ -z "${IDPHA_ROOT:-}" ]; then
			# The unbound escape exists for the offline tests only: it is honoured
			# solely together with the test prefix IDPHA_ROOT, never on a real host.
			die "--apply needs --expect-digest <digest printed by --plan>: an approval binds the previewed effect"
		fi
	fi
}

# idpha_end: print the --plan JSON (effects + digest). Call as the last step.
idpha_end() {
	if [ "$PLAN_JSON" = 1 ]; then
		# The digest also binds the tool: this script, the lib, the validator, the
		# schema and every template/reviewed file, so a changed commit cannot
		# ride on an old approval.
		local tools_sha script_sha
		script_sha="$(sha_of <"$0")"
		tools_sha="$({
			cat "$_IDPHA_LIB_DIR/lib-idpha.sh" "$_IDPHA_LIB_DIR/idpha-params.py" "$IDPHA_SCHEMA"
			find "$_IDPHA_LIB_DIR/../ha" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do cat "$f"; done
		} 2>/dev/null | sha_of)"
		python3 -I "$_IDPHA_LIB_DIR/idpha-params.py" plan-doc --op "$IDPHA_OP" --node "${NODE_NAME:-unknown}" --effects "$IDPHA_EFFECTS" --params "$IDPHA_PARAMS" --tool "script=$script_sha" --tool "bundle=$tools_sha" >&4
	fi
	if is_apply && [ -d "$(hostpath "$IDPHA_BACKUP_DIR")/$IDPHA_RUN_STAMP" ]; then
		printf '{"operation":"%s","stamp":"%s","approved_digest":"%s"}\n' "$IDPHA_OP" "$IDPHA_RUN_STAMP" "${IDPHA_EXPECT_DIGEST:-unbound}" >"$(hostpath "$IDPHA_BACKUP_DIR")/$IDPHA_RUN_STAMP/applied.json"
	fi
	rm -f "$IDPHA_EFFECTS" "${_IDPHA_TMP_PARAMS:-}"
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
	[[ "$stamp" =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?$ ]] || die "backup stamp '$stamp' is not of the form YYYYMMDDTHHMMSSZ"
	bdir="$(hostpath "$IDPHA_BACKUP_DIR")/$stamp"
	[ -d "$bdir" ] || die "no backup run $stamp under $IDPHA_BACKUP_DIR"
	while IFS= read -r f; do
		rel="${f#"$bdir"}"
		if is_apply; then
			mkdir -p "$(dirname "$(hostpath "$rel")")"
			rm -f "$(hostpath "$rel")"
			cp -Pp "$f" "$(hostpath "$rel")"
			okline "restored $rel"
		else
			planline "restore $rel"
			effect "$(_tab restore "$rel")"
		fi
	done < <(find "$bdir" \( -type f -o -type l \) ! -name .created ! -name applied.json)
	if [ -f "$bdir/.created" ]; then
		while IFS= read -r rel; do
			if is_apply; then
				rm -f "$(hostpath "$rel")"
				okline "removed $rel (created by run $stamp)"
			else
				planline "remove $rel (created by run $stamp)"
				effect "$(_tab remove "$rel")"
			fi
		done <"$bdir/.created"
	fi
}

# on_failure_restore: EXIT trap for state-changing scripts. Any non-zero exit in
# apply mode puts this run's files back (M-7), so a half-applied run never
# survives. Harmless when nothing was written.
on_failure_restore() {
	local rc=$?
	if [ "$rc" -ne 0 ] && is_apply && [ -d "$(hostpath "$IDPHA_BACKUP_DIR")/$IDPHA_RUN_STAMP" ]; then
		echo "run failed (exit $rc): restoring this run's files ($IDPHA_RUN_STAMP)" >&2
		restore_run "$IDPHA_RUN_STAMP" >&2 || true
	fi
	return "$rc"
}

# would_refuse <dest> <guard>: preflight twin of put_file's guard, used to
# validate EVERY write before the first one (M-7). Content on stdin.
guard_violation() {
	local dest="$1" real
	real="$(hostpath "$dest")"
	[ -f "$real" ] || return 1
	[ "$(sha_of <"$real")" = "$(sha_of)" ] && return 1
	return 0
}

# etcd_summary: "<healthy members> <leader count>" from etcdctl's JSON output
# (3.4 rejects -w tsv). Empty output = could not look.
etcd_summary() {
	local ep="${ETCD_ENDPOINT:-http://127.0.0.1:2379}" h st
	command -v etcdctl >/dev/null 2>&1 || return 1
	h="$(ETCDCTL_API=3 etcdctl --endpoints="$ep" endpoint health --cluster -w json 2>/dev/null)" || true
	st="$(ETCDCTL_API=3 etcdctl --endpoints="$ep" endpoint status --cluster -w json 2>/dev/null)" || return 1
	[ -n "$st" ] || return 1
	python3 -I -c '
import json, sys
h = json.loads(sys.argv[1] or "[]")
s = json.loads(sys.argv[2])
healthy = sum(1 for m in h if m.get("health"))
leaders = sum(1 for m in s if m["Status"]["leader"] == m["Status"]["header"]["member_id"])
print(healthy, leaders)
' "$h" "$st"
}

# cluster_health: the HC set — WireGuard handshakes < 150 s, etcd 3/3 with one
# leader, Patroni 3 members / 1 leader / all running-streaming. Prints why on failure.
cluster_health() {
	local es now ts cnt=0 stale=0 table verdict
	es="$(etcd_summary)" || {
		echo "      etcd: could not read status"
		return 1
	}
	[ "$es" = "3 1" ] || {
		echo "      etcd healthy/leaders = $es (want 3 1)"
		return 1
	}
	table="$("${PATRONICTL:-patronictl}" -c "${PATRONI_CONF:?}" list -f tsv 2>/dev/null)" || {
		echo "      patronictl list failed"
		return 1
	}
	verdict="$(printf '%s\n' "$table" | awk -F'\t' '
		NR == 1 { for (i = 1; i <= NF; i++) { if ($i == "Role") r = i; if ($i == "State") s = i } next }
		{ n++; if ($r ~ /Leader/) l++; if ($s != "running" && $s != "streaming") b++ }
		END { printf "%d/%d/%d", n, l + 0, b + 0 }')"
	[ "$verdict" = "3/1/0" ] || {
		echo "      patroni members/leaders/notok = $verdict (want 3/1/0)"
		return 1
	}
	now="$(date +%s)"
	while read -r _ ts; do
		[ -n "${ts:-}" ] || continue
		cnt=$((cnt + 1))
		{ [ "$ts" -gt 0 ] && [ $((now - ts)) -lt 150 ]; } || stale=$((stale + 1))
	done < <(wg show "${WG_IF:-wg0}" latest-handshakes 2>/dev/null)
	[ "$cnt" -ge 2 ] && [ "$stale" = 0 ] || {
		echo "      wireguard: $stale stale of $cnt peers"
		return 1
	}
}

# host_identity_check: the params describe THIS node. The overlay address must be
# on the WireGuard interface here, or the run is aimed at the wrong host.
host_identity_check() {
	[ -n "${OVERLAY_ADDR:-}" ] || return 0
	ip -4 -o addr show dev "${WG_IF:-wg0}" 2>/dev/null | grep -q " ${OVERLAY_ADDR}/" ||
		die "this host does not carry the overlay address ${OVERLAY_ADDR} on ${WG_IF:-wg0}: params are for another node"
}
