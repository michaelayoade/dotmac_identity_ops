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
for c in ufw systemd-run systemctl docker mc runuser needrestart apt-get; do
	{
		echo '#!/usr/bin/env bash'
		echo "echo \"$c \$*\" >>\"$CALLS\""
		echo 'exit 0'
	} >"$STUB/$c"
	chmod +x "$STUB/$c"
done
FIX="$REPO_ROOT/tests/ha/fixtures"
cat >"$STUB/ip" <<'STUBEOF'
#!/usr/bin/env bash
echo "3: wg0    inet 192.0.2.1/24 scope global wg0"
STUBEOF
cat >"$STUB/wg" <<'STUBEOF'
#!/usr/bin/env bash
now="$(date +%s)"
case "$*" in
	*endpoints*) printf 'KEYA\t198.51.100.2:51820\nKEYB\t198.51.100.3:51820\n' ;;
	*latest-handshakes*) printf 'KEYA\t%s\nKEYB\t%s\n' "$((now - 30))" "$((now - 70))" ;;
esac
STUBEOF
# etcdctl 3.4.30: "-w tsv" is rejected, JSON is replayed from the fixtures.
{
	echo '#!/usr/bin/env bash'
	echo 'case "$*" in *"-w tsv"*) echo "Error: unsupported output format" >&2; exit 1 ;; esac'
	echo "FIXDIR='$FIX'"
	echo 'mode="${ETCD_MODE:-ok}"'
	echo '[ "$mode" = missing ] && exit 127'
	echo 'case "$*" in'
	echo '  *"endpoint health"*) if [ "$mode" = degraded ]; then sed "s/\"health\":true/\"health\":false/" "$FIXDIR/etcd-3.4-endpoint-health.json" | sed "s/false/true/2g"; else cat "$FIXDIR/etcd-3.4-endpoint-health.json"; fi ;;'
	echo '  *"endpoint status"*) if [ "$mode" = noleader ]; then sed "s/\"leader\":[0-9]*/\"leader\":1/g" "$FIXDIR/etcd-3.4-endpoint-status.json"; else cat "$FIXDIR/etcd-3.4-endpoint-status.json"; fi ;;'
	echo 'esac'
} >"$STUB/etcdctl"
printf 'Cluster\tMember\tHost\tRole\tState\tTL\tLag in MB\nc\tn1\th\tLeader\trunning\t5\t\nc\tn2\th\tSync Standby\tstreaming\t5\t0\nc\tn3\th\tReplica\tstreaming\t5\t0\n' >"$T/default-patroni.list"
{
	echo '#!/usr/bin/env bash'
	echo "echo \"patronictl \$*\" >>\"$CALLS\""
	echo "case \"\$*\" in *'list -f tsv'*) cat '$T/default-patroni.list' ;; esac"
} >"$STUB/patronictl"
chmod +x "$STUB/ip" "$STUB/wg" "$STUB/etcdctl" "$STUB/patronictl"
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
export IDPHA_ALLOW_UNSAFE_VALUES=1 # token/credential reference files in tests are owned by the test user
export IDPHA_ALLOW_UNBOUND_APPLY=1 # most tests apply directly; t-params.sh covers the digest binding

# mkvalues <file> [jq filter...]: write a VALID params document (documentation
# ranges only), then apply each jq filter to make a variant.
mkvalues() {
	cat >"$1" <<PARAMS
{
  "schema_version": 1,
  "node": {
    "name": "node-1",
    "overlay_addr": "192.0.2.1",
    "vip_addr": "203.0.113.10",
    "peers": [
      {"overlay_addr": "192.0.2.2", "public_addr": "198.51.100.2"},
      {"overlay_addr": "192.0.2.3", "public_addr": "198.51.100.3"}
    ],
    "ha_dir": "/srv/example/ha",
    "patroni_conf": "/srv/example/patroni.yml"
  },
  "operations": {
    "harden-ha": {"apt_upgrade_time": "01:15:00"},
    "ha-install": {
      "kc_hostname": "idp.example.test",
      "links_hostname": "links.example.test",
      "idp_cert_dir": "/srv/example/tls/idp",
      "links_cert_dir": "/srv/example/tls/links",
      "links_root": "/srv/example/links",
      "gate_allow": ["198.51.100.77/32", "198.51.100.78/32"],
      "legacy_vhost_files": ["/srv/example/nginx/sites-enabled/idp.conf", "/srv/example/nginx/sites-enabled/links.conf"],
      "metrics_allow": ["198.51.100.79/32"],
      "metrics_token_file": "$T/metrics.token",
      "backup_env_file": "/srv/example/backup.env"
    },
    "patroni-sync": {},
    "ha-backup": {
      "backup_mc_alias": "store",
      "backup_bucket": "example-bucket",
      "backup_prefix": "ha",
      "backup_age_recipient_file": "$T/recipient.age",
      "pgdump_format_args": "--no-owner --clean --if-exists"
    },
    "collector": {"idpha_prom_file": "/srv/example/idpha.prom"},
    "host-check": {},
    "verify-ha": {"ha_verify_env": "/srv/example/verify.env"},
    "rolling-maint": {"maint_on_calendar": "Sun *-*-* 02:30:00 UTC"}
  }
}
PARAMS
	local f
	for f in "${@:2}"; do
		jq "$f" "$1" >"$1.new" && mv "$1.new" "$1"
	done
	chmod 600 "$1"
}
V="$T/values.env"
mkvalues "$V"
export IDPHA_PARAMS="$V" # default params document; tests override per command
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
