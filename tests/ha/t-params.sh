#!/usr/bin/env bash
# t-params.sh — the typed params contract: schema validation, refusal on
# missing/invalid values, secrets-by-reference, --plan effect JSON + digest, and
# the --apply re-plan that refuses when the previewed effect changed.
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=bin/lib-idpha.sh
. "$REPO_ROOT/bin/lib-idpha.sh"
H="$REPO_ROOT/bin/harden-ha.sh"
TOOL="$REPO_ROOT/bin/idpha-params.py"
SCHEMA="$REPO_ROOT/ha/params.schema.json"

section "schema accepts the example and nothing else"
if python3 -I "$TOOL" validate --schema "$SCHEMA" --params "$REPO_ROOT/ha/params.example.json" 2>/dev/null; then ok "ha/params.example.json validates"; else bad "example does not validate"; fi
refuse() { # refuse <name> <jq filter>
	mkvalues "$T/p.json" "$2"
	IDPHA_PARAMS="$T/p.json" runit "$H" preview
	expect "refused: $1" 1 "$RC"
}
refuse "unknown top-level key" '.extra=1'
refuse "unknown parameter (a secret value is not a parameter)" '.operations["ha-backup"].db_pass''word="x"'
refuse "unknown parameter in node" '.node.root_pass''word="x"'
refuse "wrong schema_version" '.schema_version=2'
refuse "missing required node.name" 'del(.node.name)'
refuse "missing required peers" 'del(.node.peers)'
refuse "one peer only" 'del(.node.peers[1])'
refuse "peer is not an address" '.node.peers[0].public_addr="example.test"'
refuse "peer is the unspecified address" '.node.peers[0].public_addr="0.0.0.0"'
refuse "overlay address out of range" '.node.overlay_addr="192.0.2.999"'
refuse "relative ha_dir" '.node.ha_dir="srv/ha"'
refuse "path with traversal characters" '.node.ha_dir="/srv/../etc"'
refuse "port as a string" '.node.ssh_port="22"'
refuse "missing own section" 'del(.operations["harden-ha"])'
refuse "bad apt time" '.operations["harden-ha"].apt_upgrade_time="25:00:00"'
refuse "missing required apt time" 'del(.operations["harden-ha"].apt_upgrade_time)'
mkvalues "$T/p.json" 'del(.operations["ha-install"].gate_allow)'
IDPHA_PARAMS="$T/p.json" runit "$REPO_ROOT/bin/ha-install.sh" nginx
expect "ha-install refuses a missing gate_allow" 1 "$RC"
for bad_cidr in '0.0.0.0/0' '198.51.100.0/24' '198.51.100.7' '::/0' '2001:db8::/32' '198.51.100.7/31'; do
	mkvalues "$T/p.json" ".operations[\"ha-install\"].gate_allow=[\"$bad_cidr\"]"
	IDPHA_PARAMS="$T/p.json" runit "$REPO_ROOT/bin/ha-install.sh" nginx
	expect "gate_allow refuses $bad_cidr (single hosts only)" 1 "$RC"
	mkvalues "$T/p.json" ".operations[\"ha-install\"].metrics_allow=[\"$bad_cidr\"]"
	IDPHA_PARAMS="$T/p.json" runit "$REPO_ROOT/bin/ha-install.sh" nginx
	expect "metrics_allow refuses $bad_cidr" 1 "$RC"
done
mkvalues "$T/p.json" '.operations["ha-install"].gate_extra_allow=["203.0.113.0/24"]'
IDPHA_PARAMS="$T/p.json" runit "$REPO_ROOT/bin/ha-install.sh" nginx
expect "gate_extra_allow refuses a range" 1 "$RC"
mkvalues "$T/p.json" '.operations["ha-install"].gate_allow=["2001:db8::7/128"]'
if python3 -I "$TOOL" validate --schema "$SCHEMA" --params "$T/p.json" 2>/dev/null; then ok "a /128 IPv6 host is accepted"; else bad "/128 refused"; fi
mkvalues "$T/p.json" '.operations["ha-install"].kc_hostname="IDP_Example"'
IDPHA_PARAMS="$T/p.json" runit "$REPO_ROOT/bin/ha-install.sh" nginx
expect "hostname with uppercase/underscore refused" 1 "$RC"
mkvalues "$T/p.json" '.operations["rolling-maint"].restart_allowlist=["bash"]'
IDPHA_PARAMS="$T/p.json" runit "$REPO_ROOT/bin/idpha-rolling-maint.sh"
expect "restart allowlist only takes known services" 1 "$RC"
IDPHA_PARAMS="" runit "$H" preview
expect "no params document at all is refused" 1 "$RC"
has "...with a clear message" "$OUT" "no params document"
IDPHA_PARAMS="$T/does-not-exist.json" runit "$H" preview
expect "an unreadable params path is refused" 1 "$RC"
printf '{not json' >"$T/broken.json"
IDPHA_PARAMS="$T/broken.json" runit "$H" preview
expect "malformed JSON is refused" 1 "$RC"
OUT="$T/stdin.out"
IDPHA_PARAMS="" "$H" preview --params - <"$V" >"$OUT" 2>&1
expect "--params - reads the document from stdin" 0 $?
printf '{"type":"object","oneOf":[{}]}' >"$T/odd-schema.json"
IDPHA_SCHEMA="$T/odd-schema.json" IDPHA_PARAMS="$V" runit "$H" preview
expect "an unsupported schema keyword fails closed" 1 "$RC"
has "...and names the keyword" "$OUT" "unsupported keyword"
printf '{"type":"object","properties":{"a":{"type":"string","format":"made-up"}}}' >"$T/odd-schema2.json"
printf '{"a":"x"}' >"$T/odd-doc.json"
python3 -I "$TOOL" validate --schema "$T/odd-schema2.json" --params "$T/odd-doc.json" 2>/dev/null
expect "an unknown format fails closed" 2 $?

section "secrets are references, never parameters"
names="$(jq -r '[.. | objects | .properties? // empty | keys[]] | .[]' "$SCHEMA")"
leaky=""
for n in $names; do
	case "$n" in
		*password* | *secret* | *token* | *key*) case "$n" in *_file | *_dir) ;; *) leaky="$leaky $n" ;; esac ;;
	esac
done
if [ -z "$leaky" ]; then ok "no schema property can carry a secret value (only *_file references)"; else bad "secret-like properties:$leaky"; fi
if grep -qiE 'BEGIN [A-Z ]*PRIVATE|AKIA|secret_key|password"' "$REPO_ROOT/ha/params.example.json"; then bad "example carries secret-looking content"; else ok "example carries no secret-looking content"; fi

section "--plan: effect summary + digest"
newroot
plan() { # plan <params> <args...> -> JSON in $PLANOUT, exit in RC
	local prm="$1"
	shift
	PLANOUT="$T/plan.$RANDOM"
	IDPHA_PARAMS="$prm" IDPHA_ROOT="$R" "$H" "$@" --plan >"$PLANOUT" 2>"$PLANOUT.err"
	RC=$?
}
plan "$V" dropins
expect "--plan exits 0" 0 "$RC"
if jq -e '.digest | test("^sha256:[0-9a-f]{64}$")' "$PLANOUT" >/dev/null 2>&1; then ok "plan is JSON with a sha256 digest on stdout"; else bad "plan is not the expected JSON"; fi
if jq -e '.effects | map(select(.kind=="write" and (.path|test("keepalived.service.d")))) | length == 1' "$PLANOUT" >/dev/null 2>&1; then ok "plan lists the keepalived drop-in write"; else bad "effect missing"; fi
if jq -e '.node == "node-1" and .operation == "harden-ha" and (.tool.bundle|length>10) and (.params_sha256|length==64)' "$PLANOUT" >/dev/null 2>&1; then ok "plan names node, operation, tool bundle hash and params hash"; else bad "plan header incomplete"; fi
if [ -z "$(find "$R" -type f 2>/dev/null)" ]; then ok "--plan writes nothing"; else bad "--plan wrote files"; fi
D1="$(jq -r .digest "$PLANOUT")"
plan "$V" dropins
if [ "$D1" = "$(jq -r .digest "$PLANOUT")" ]; then ok "the digest is deterministic"; else bad "digest differs between identical plans"; fi
mkvalues "$T/p2.json" '.node.name="node-9"'
plan "$T/p2.json" dropins
if [ "$D1" != "$(jq -r .digest "$PLANOUT")" ]; then ok "the digest changes with the params"; else bad "digest ignores params"; fi
if ! grep -q '192\.0\.2\.' "$PLANOUT"; then ok "the plan carries no addresses (paths, modes and hashes only)"; else bad "plan leaks params content"; fi

section "--apply is bound to the previewed digest"
export IDPHA_ALLOW_UNBOUND_APPLY=0
newroot
plan "$V" dropins
D="$(jq -r .digest "$PLANOUT")"
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
expect "apply without --expect-digest is refused" 1 "$RC"
has "...saying why" "$OUT" "--expect-digest"
if [ -z "$(find "$R" -type f 2>/dev/null)" ]; then ok "...and nothing was written"; else bad "unbound apply wrote files"; fi
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply --expect-digest "sha256:0000000000000000000000000000000000000000000000000000000000000000"
expect "apply with the wrong digest is refused" 1 "$RC"
has "...naming the mismatch" "$OUT" "plan digest differs"
if [ -z "$(find "$R" -type f 2>/dev/null)" ]; then ok "...and nothing was written either"; else bad "mismatched apply wrote files"; fi
plan "$V" upgrade-policy
DU="$(jq -r .digest "$PLANOUT")"
mkvalues "$T/p3.json" '.operations["harden-ha"].apt_upgrade_time="02:15:00"'
IDPHA_PARAMS="$T/p3.json" IDPHA_ROOT="$R" runit "$H" upgrade-policy --apply --expect-digest "$DU"
expect "params changed after the preview: refused" 1 "$RC"
mkdir -p "$R/etc/systemd/system/keepalived.service.d"
echo "# someone edited it" >"$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf"
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply --expect-digest "$D"
expect "pre-state changed between plan and apply: refused" 1 "$RC"
rm -f "${R:?}/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf"
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply --expect-digest "$D"
expect "apply with the matching digest succeeds" 0 "$RC"
has "...after re-planning" "$OUT" "re-plan matches the approved digest"
if [ -f "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf" ]; then ok "...and the change is made"; else bad "approved apply did nothing"; fi
rec="$(find "$R/var/lib/idpha/backup" -name applied.json 2>/dev/null | head -1)"
if [ -n "$rec" ] && grep -q "$D" "$rec"; then ok "the approved digest and run stamp are recorded on the host"; else bad "no applied.json record"; fi
CS="$T/cs"
mkdir -p "$CS"
printf '#!/usr/bin/env bash\nexit 22\n' >"$CS/curl"
chmod +x "$CS/curl"
mkvalues "$T/pc.json" ".operations.collector.idpha_prom_file=\"$R/prom/idpha.prom\""
PATH="$CS:$PATH" IDPHA_STATE_DIR="$R/state" IDPHA_PARAMS="$T/pc.json" runit "$REPO_ROOT/bin/idpha-collect.sh" --apply
expect "a timer-run job (collector) applies without a digest" 0 "$RC"
export IDPHA_ALLOW_UNBOUND_APPLY=1

section "the unbound-apply escapes are test-only"
n1() { # n1 <env assignments...>: idpha_begin as --apply WITHOUT the test prefix
	OUT="$T/n1.$RANDOM"
	env -u IDPHA_ROOT "$@" bash -c ". '$REPO_ROOT/bin/lib-idpha.sh'; APPLY=1; IDPHA_PARAMS='$V'; idpha_begin harden-ha" >"$OUT" 2>&1
	RC=$?
}
n1 IDPHA_ALLOW_UNBOUND_APPLY=1
expect "IDPHA_ALLOW_UNBOUND_APPLY=1 without the test prefix is refused" 1 "$RC"
has "...demanding the digest" "$OUT" "--expect-digest"
n1 IDPHA_CHILD=1
expect "IDPHA_CHILD=1 together with --apply is refused" 1 "$RC"
has "...as internal" "$OUT" "IDPHA_CHILD is internal"
n1 IDPHA_CHILD=1 IDPHA_ROOT="$T" IDPHA_ALLOW_UNBOUND_APPLY=1
expect "IDPHA_CHILD=1 is refused even with the test prefix" 1 "$RC"
OUT="$T/n1b"
env IDPHA_ROOT="$T" IDPHA_ALLOW_UNBOUND_APPLY=1 bash -c ". '$REPO_ROOT/bin/lib-idpha.sh'; APPLY=1; IDPHA_PARAMS='$V'; idpha_begin harden-ha" >"$OUT" 2>&1
expect "the escape still works WITH the test prefix (tests only)" 0 $?

section "the params must describe THIS host"
mkvalues "$T/p4.json" '.node.overlay_addr="192.0.2.99"'
IDPHA_PARAMS="$T/p4.json" runit "$H" preview
expect "params for another node are refused" 1 "$RC"
has "...saying so" "$OUT" "params are for another node"

section "ufw: peers must be the WireGuard endpoints; confirm is health-gated"
newroot
: >"$CALLS"
mkvalues "$T/p5.json" '.node.peers[0].public_addr="198.51.100.9"'
IDPHA_PARAMS="$T/p5.json" IDPHA_ROOT="$R" UFW_BIN=ufw runit "$H" ufw
expect "a peer address that differs from 'wg show endpoints' is refused" 1 "$RC"
has "...saying so" "$OUT" "differ from the WireGuard endpoints"
: >"$CALLS"
ETCD_MODE=degraded IDPHA_ROOT="$R" runit "$H" ufw-confirm --fresh-login-confirmed --apply
expect "ufw-confirm refuses while etcd is degraded" 1 "$RC"
hasnt "...and the dead-man timer is NOT stopped" "$CALLS" "systemctl stop idpha-deadman"
ETCD_MODE=noleader IDPHA_ROOT="$R" runit "$H" ufw-confirm --fresh-login-confirmed --apply
expect "ufw-confirm refuses with no etcd leader" 1 "$RC"
IDPHA_ROOT="$R" runit "$H" ufw-confirm --fresh-login-confirmed --apply
expect "ufw-confirm passes on a healthy cluster" 0 "$RC"
has "...stops the timer and its service" "$CALLS" "systemctl stop idpha-deadman.timer idpha-deadman.service"
has "...and clears the failed state" "$CALLS" "systemctl reset-failed idpha-deadman.service"
etcdctl --endpoints=x endpoint status -w tsv >/dev/null 2>&1
expect "the etcdctl stub rejects '-w tsv' like etcd 3.4.30" 1 $?

section "rolling maintenance"
RM="$REPO_ROOT/bin/idpha-rolling-maint.sh"
LS="$T/ls"
mkdir -p "$LS"
printf '#!/usr/bin/env bash\ncase "$*" in *"/primary"*) exit "${STUB_PRIMARY:-22}" ;; esac\nexit 0\n' >"$LS/curl"
printf '#!/usr/bin/env bash\nprintf "NEEDRESTART-VER: 3.6\\nNEEDRESTART-SVC: nginx.service\\n"\n' >"$LS/needrestart"
chmod +x "$LS"/*
PATH="$LS:$PATH" IDPHA_ROOT="$R" runit "$RM"
expect "maintenance dry-run on a healthy replica exits 0" 0 "$RC"
has "plans the allowlisted restart" "$OUT" "systemctl restart nginx"
has "upgrades the excluded cluster packages by default" "$OUT" "apt-get install --only-upgrade -y"
hasnt "never reboots without --allow-reboot" "$OUT" "systemctl reboot"
PATH="$LS:$PATH" STUB_PRIMARY=0 IDPHA_ROOT="$R" runit "$RM"
expect "on the leader it refuses to upgrade cluster packages" 1 "$RC"
has "...after planning a switchover to the sync standby" "$OUT" "switchover --candidate node-2"
RN="$T/rn"
mkdir -p "$RN"
cp "$LS/curl" "$RN/curl"
printf '#!/usr/bin/env bash\ncat "%s/tests/ha/fixtures/needrestart-b-rl.txt"\n' "$REPO_ROOT" >"$RN/needrestart"
chmod +x "$RN"/*
PATH="$RN:$PATH" IDPHA_ROOT="$R" runit "$RM"
expect "real needrestart output (pending kernel, no listed cluster service) plans cleanly" 0 "$RC"
has "...and says the reboot is needed and needs the flag" "$OUT" "re-run with --allow-reboot"
hasnt "...services outside the allowlist are never restarted" "$OUT" "systemctl restart dbus"
PATH="$RN:$PATH" IDPHA_ROOT="$R" runit "$RM" --allow-reboot
has "with --allow-reboot the reboot is planned" "$OUT" "systemctl reboot"
PATH="$LS:$PATH" ETCD_MODE=degraded IDPHA_ROOT="$R" runit "$RM"
expect "maintenance refuses a degraded cluster" 1 "$RC"

finish "t-params"
