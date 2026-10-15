#!/usr/bin/env bash
# tests/ha/lib.sh — shared helpers for the HA behaviour tests. SOURCE it.
#
# What these tests prove: the scripts' LOGIC — dry-run changes nothing, apply
# orders its steps safely, refusals fire, rendered files carry the properties
# they exist to deliver, and no secret value reaches output. They use stub
# commands on PATH and a temporary root (IDPHA_ROOT). No daemon, no network, no
# host.
#
# What they do NOT prove: that nginx accepts the rendered config (nginx -t is a
# stub here; the packet's read-back is the real check), that ufw / Patroni /
# systemd behave as the stubs assume, or anything about a live node.
#
# All addresses are RFC 5737 documentation ranges.

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0
failn=0

ok() {
	pass=$((pass + 1))
	printf 'ok    %s\n' "$1"
}
bad() {
	failn=$((failn + 1))
	printf 'FAIL  %s\n' "$1"
}
expect() { # expect <name> <want-exit> <actual-exit>
	if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (exit $3, want $2)"; fi
}
has() { # has <name> <file> <fixed string>
	if grep -qF -- "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1 (missing: $3)"; fi
}
hasnt() {
	if grep -qF -- "$3" "$2" 2>/dev/null; then bad "$1 (found: $3)"; else ok "$1"; fi
}
section() { printf '== %s ==\n' "$1"; }

# ---- generic recording stubs ----------------------------------------------------
STUB="$T/stubs"
mkdir -p "$STUB"
CALLS="$T/calls.log"
: >"$CALLS"
for c in ufw systemd-run systemctl docker mc runuser needrestart; do
	{
		echo '#!/usr/bin/env bash'
		echo "echo \"$c \$*\" >>\"$CALLS\""
		echo 'exit 0'
	} >"$STUB/$c"
	chmod +x "$STUB/$c"
done
# systemctl: nothing is active unless a test says so
{
	echo '#!/usr/bin/env bash'
	echo "echo \"systemctl \$*\" >>\"$CALLS\""
	echo '[ "$1" = is-active ] && exit 3'
	echo 'exit 0'
} >"$STUB/systemctl"
chmod +x "$STUB/systemctl"
{
	echo '#!/usr/bin/env bash'
	echo "echo \"nginx \$*\" >>\"$CALLS\""
	echo 'if [ "${NGINX_FAIL:-0}" = 1 ] && [ "$1" = "-t" ]; then echo "nginx: [emerg] stub failure" >&2; exit 1; fi'
	echo 'exit 0'
} >"$STUB/nginx"
chmod +x "$STUB/nginx"
export PATH="$STUB:$PATH"
export IDPHA_ALLOW_UNSAFE_VALUES=1 # test values files are owned by the test user

mkvalues() { # mkvalues <file> [extra assignment lines...]
	cat >"$1" <<VALUES
NODE_NAME=node-1
OVERLAY_ADDR=192.0.2.1
PEER_OVERLAY_1=192.0.2.2
PEER_OVERLAY_2=192.0.2.3
PEER_PUBLIC_1=198.51.100.2
PEER_PUBLIC_2=198.51.100.3
VIP_ADDR=203.0.113.10
HA_DIR=/srv/example/ha
BACKUP_ENV_FILE=/srv/example/backup.env
METRICS_TOKEN_FILE=$T/metrics.token
APT_UPGRADE_TIME=01:15:00
LINKS_ROOT=/srv/example/links
GATE_ALLOW="198.51.100.77/32 198.51.100.78/32"
METRICS_ALLOW="198.51.100.79/32"
BACKUP_MC_ALIAS=store
BACKUP_BUCKET=example-bucket
BACKUP_PREFIX=ha
BACKUP_AGE_RECIPIENT_FILE=$T/recipient.age
PGDUMP_FORMAT_ARGS="--no-owner --no-acl"
VALUES
	if [ $# -ge 2 ]; then printf '%s\n' "${@:2}" >>"$1"; fi
	chmod 600 "$1"
}
V="$T/values.env"
mkvalues "$V"
newroot() {
	R="$T/root.$RANDOM"
	mkdir -p "$R"
}
runit() { # runit <script> args... ; sets OUT (file) and RC
	OUT="$T/out.$RANDOM"
	"$@" >"$OUT" 2>&1
	# shellcheck disable=SC2034 # read by the test files that source this
	RC=$?
}
finish() {
	echo
	echo "$1: $pass passed, $failn failed"
	[ "$failn" = 0 ]
}
