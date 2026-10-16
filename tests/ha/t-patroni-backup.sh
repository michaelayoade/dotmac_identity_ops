#!/usr/bin/env bash
# t-patroni-backup.sh — bin/patroni-sync.sh and bin/ha-backup.sh.
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=bin/lib-idpha.sh
. "$REPO_ROOT/bin/lib-idpha.sh"

mkdir -p "$T/proot"
export IDPHA_ROOT="$T/proot" # test prefix: the unbound-apply escape is honoured only with it

section "patroni-sync"
PSTUB="$T/pstub"
mkdir -p "$PSTUB"
PSTATE="$T/patroni.state"
cat >"$PSTUB/patronictl" <<STUBEOF
#!/usr/bin/env bash
echo "patronictl \$*" >>"$CALLS"
state="$PSTATE"
args="\$*"
case "\$args" in
	*show-config*) cat "\$state.config" ;;
	*"list -f tsv"*) cat "\$state.list" ;;
	*edit-config*)
		printf 'synchronous_mode: true\nsynchronous_mode_strict: false\nsynchronous_node_count: 1\nttl: 30\n' >"\$state.config"
		sed 's/Replica/Sync Standby/' "\$state.list" | awk 'BEGIN{n=0} /Sync Standby/ {n++; if (n>1) sub(/Sync Standby/, "Replica")} {print}' >"\$state.list.new"
		mv "\$state.list.new" "\$state.list"
		;;
esac
STUBEOF
chmod +x "$PSTUB/patronictl"
HEALTHY=$'Cluster\tMember\tHost\tRole\tState\tTL\tLag in MB\nc\tn1\th\tLeader\trunning\t5\t\nc\tn2\th\tReplica\tstreaming\t5\t0\nc\tn3\th\tReplica\tstreaming\t5\t0\n'
printf 'ttl: 30\nmaximum_lag_on_failover: 1048576\n' >"$PSTATE.config"
printf '%s' "$HEALTHY" >"$PSTATE.list"
export PATRONICTL="$PSTUB/patronictl"
P="$REPO_ROOT/bin/patroni-sync.sh"

: >"$CALLS"
runit "$P" apply
expect "dry-run exits 0" 0 "$RC"
hasnt "dry-run never calls edit-config" "$CALLS" "edit-config"
has "dry-run shows the three reviewed keys" "$OUT" "synchronous_mode=true -s synchronous_mode_strict=false -s synchronous_node_count=1"
: >"$CALLS"
runit "$P" apply --apply
expect "apply on a healthy cluster exits 0" 0 "$RC"
has "applies exactly the reviewed keys" "$CALLS" "edit-config -s synchronous_mode=true -s synchronous_mode_strict=false -s synchronous_node_count=1 --force"
has "reads the keys back" "$OUT" "synchronous_mode = true"
has "strict stays false" "$OUT" "synchronous_mode_strict = false"
has "finds a sync standby" "$OUT" "a Sync Standby is present"

printf 'ttl: 30\n' >"$PSTATE.config"
printf 'Cluster\tMember\tHost\tRole\tState\tTL\tLag in MB\nc\tn1\th\tLeader\trunning\t5\t\nc\tn2\th\tReplica\tstreaming\t5\t12\nc\tn3\th\tReplica\tstreaming\t5\t0\n' >"$PSTATE.list"
: >"$CALLS"
runit "$P" apply --apply
expect "refuses a lagging cluster" 1 "$RC"
hasnt "...and changes nothing" "$CALLS" "edit-config"
printf 'Cluster\tMember\tHost\tRole\tState\tTL\tLag in MB\nc\tn1\th\tLeader\trunning\t5\t\nc\tn2\th\tLeader\trunning\t5\t0\nc\tn3\th\tReplica\tstreaming\t5\t0\n' >"$PSTATE.list"
runit "$P" apply --apply
expect "refuses two leaders" 1 "$RC"
printf 'Cluster\tMember\tHost\tRole\tState\tTL\tLag in MB\nc\tn1\th\tLeader\trunning\t5\t\nc\tn2\th\tReplica\tstopped\t5\t0\nc\tn3\th\tReplica\tstreaming\t5\t0\n' >"$PSTATE.list"
runit "$P" apply --apply
expect "refuses a member that is not running/streaming" 1 "$RC"
printf '%s' "$HEALTHY" >"$PSTATE.list"
printf 'synchronous_mode: true\nsynchronous_mode_strict: false\nsynchronous_node_count: 1\nttl: 1\n' >"$T/bad-patch.yml"
PATCH_FILE="$T/bad-patch.yml" runit "$P" apply
expect "a patch key outside the allowlist is refused" 1 "$RC"
: >"$CALLS"
runit "$P" rollback --apply
has "rollback sets synchronous_mode=false" "$CALLS" "edit-config -s synchronous_mode=false --force"
has "the reviewed repository patch is non-strict" "$REPO_ROOT/ha/patroni/dcs-sync.yml" "synchronous_mode_strict: false"
unset PATRONICTL

section "ha-backup"
BSTUB="$T/bstub"
mkdir -p "$BSTUB"
cat >"$BSTUB/curl" <<'STUBEOF'
#!/usr/bin/env bash
case "$*" in *"/primary"*) [ "${STUB_LEADER:-1}" = 1 ] && exit 0 || exit 22 ;; esac
exit 0
STUBEOF
cat >"$BSTUB/runuser" <<STUBEOF
#!/usr/bin/env bash
echo "runuser \$*" >>"$CALLS"
printf -- '-- dump\n'
STUBEOF
cat >"$BSTUB/age" <<STUBEOF
#!/usr/bin/env bash
echo "age \$*" >>"$CALLS"
cat >/dev/null
case "\${STUB_AGE:-ok}" in
	nohdr) head -c 12000 /dev/zero ;;
	small) printf 'age-encryption.org/v1\n' ;;
	*) printf 'age-encryption.org/v1\n'; head -c 12000 /dev/zero ;;
esac
STUBEOF
cat >"$BSTUB/rclone" <<STUBEOF
#!/usr/bin/env bash
echo "rclone \$*" >>"$CALLS"
STUBEOF
cat >"$BSTUB/mc" <<STUBEOF
#!/usr/bin/env bash
echo "mc \$*" >>"$CALLS"
STUBEOF
chmod +x "$BSTUB"/*
echo "age1example" >"$T/recipient.age"
newroot
B="$REPO_ROOT/bin/ha-backup.sh"
export IDPHA_STATE_DIR="$R/state"
: >"$CALLS"
PATH="$BSTUB:$PATH" STUB_LEADER=0 IDPHA_PARAMS="$V" runit "$B" --apply
expect "replica exits 0" 0 "$RC"
has "replica logs the skip" "$OUT" "not leader, skip"
hasnt "replica never dumps" "$CALLS" "runuser"
hasnt "replica never uploads" "$CALLS" "rclone "
: >"$CALLS"
PATH="$BSTUB:$PATH" IDPHA_PARAMS="$V" runit "$B"
expect "leader dry-run exits 0" 0 "$RC"
hasnt "dry-run does not dump" "$CALLS" "runuser"
hasnt "dry-run does not upload" "$CALLS" "rclone "
: >"$CALLS"
PATH="$BSTUB:$PATH" IDPHA_PARAMS="$V" runit "$B" --apply
expect "leader apply exits 0" 0 "$RC"
has "dump runs as the postgres user with the configured flags" "$CALLS" "runuser -u postgres -- pg_dump --no-owner --clean --if-exists keycloak"
has "encrypts to the recipient file" "$CALLS" "age -R $T/recipient.age"
has "rclone uploads with no config file and no listing or HEAD" "$CALLS" "rclone copyto --config /dev/null --s3-no-check-bucket --s3-no-head --quiet"
has "...under the write-only prefix" "$CALLS" "store:example-bucket/ha/keycloak-node-1-"
hasnt "no credential-looking argument on the uploader's command line" "$CALLS" "SECRET"
has "prints the uploaded key" "$OUT" "uploaded ha/keycloak-node-1-"
if [ -s "$R/state/backup.last" ]; then ok "success timestamp recorded for the collector"; else bad "no backup.last"; fi
rm -f "$R/state/backup.last"
: >"$CALLS"
PATH="$BSTUB:$PATH" STUB_AGE=small IDPHA_PARAMS="$V" runit "$B" --apply
expect "a truncated ciphertext is refused" 1 "$RC"
hasnt "...and never uploaded" "$CALLS" "rclone "
PATH="$BSTUB:$PATH" STUB_AGE=nohdr IDPHA_PARAMS="$V" runit "$B" --apply
expect "output without the age header is refused" 1 "$RC"
hasnt "...and never uploaded either" "$CALLS" "rclone "
if [ ! -e "$R/state/backup.last" ]; then ok "failure records no success timestamp"; else bad "success recorded for a failed backup"; fi
mkvalues "$T/v-nofmt2.env" 'del(.operations["ha-backup"].pgdump_format_args)'
PATH="$BSTUB:$PATH" IDPHA_PARAMS="$T/v-nofmt2.env" runit "$B" --apply
expect "backup refuses without an explicit dump format (no silent default)" 1 "$RC"
mkvalues "$T/v-mc.json" '.operations["ha-backup"].backup_uploader="mc"' '.operations["ha-backup"].backup_mc_alias="kc"'
: >"$CALLS"
PATH="$BSTUB:$PATH" IDPHA_PARAMS="$T/v-mc.json" runit "$B" --apply
expect "the mc fallback uploader still works when selected" 0 "$RC"
has "...with its own config dir" "$CALLS" "mc --config-dir $R/state/mc cp --quiet"
mkvalues "$T/v-badup.json" '.operations["ha-backup"].backup_uploader="s3cmd"'
PATH="$BSTUB:$PATH" IDPHA_PARAMS="$T/v-badup.json" runit "$B" --apply
expect "an unknown uploader is refused" 1 "$RC"
mkvalues "$T/v-noremote.json" 'del(.operations["ha-backup"].backup_remote)'
PATH="$BSTUB:$PATH" IDPHA_PARAMS="$T/v-noremote.json" runit "$B" --apply
expect "rclone mode without a remote name is refused" 1 "$RC"
unset IDPHA_STATE_DIR

finish "t-patroni-backup"
