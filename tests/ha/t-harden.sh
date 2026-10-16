#!/usr/bin/env bash
# t-harden.sh — bin/harden-ha.sh and the shared lib (offline; see lib.sh).
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=bin/lib-idpha.sh
. "$REPO_ROOT/bin/lib-idpha.sh"
H="$REPO_ROOT/bin/harden-ha.sh"

section "render"
printf 'a @@ONE@@ b @@TWO@@\n' >"$T/tmpl"
ONE='x&y\z' TWO='@@ONE@@' bash -c ". '$REPO_ROOT/bin/lib-idpha.sh'; export ONE TWO; render '$T/tmpl'" >"$T/r.out" 2>&1
has "render inserts values literally (& and backslash, no re-scan)" "$T/r.out" 'a x&y\z b @@ONE@@'
env -u ONE -u TWO bash -c ". '$REPO_ROOT/bin/lib-idpha.sh'; render '$T/tmpl'" >"$T/r2.out" 2>&1
expect "render refuses an unresolved token" 1 $?
has "render names the unresolved token" "$T/r2.out" 'UNRESOLVED @@ONE@@'

section "harden-ha preview / ufw"
newroot
: >"$CALLS"
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" preview
expect "plan exits 0" 0 "$RC"
has "plan says dry-run" "$OUT" "DRY-RUN"
if [ -z "$(find "$R" -type f 2>/dev/null)" ]; then ok "plan writes no file"; else bad "plan wrote files"; fi
if [ ! -s "$CALLS" ]; then ok "plan runs no command"; else bad "plan ran commands: $(cat "$CALLS")"; fi
n="$(grep -c 'ufw allow' "$OUT")"
if [ "$n" = 6 ]; then ok "plan lists exactly six allow rules"; else bad "allow rule count $n"; fi
has "plan: ssh allowed" "$OUT" "allow 22/tcp"
has "plan: wg only from peer A" "$OUT" "allow from 198.51.100.2 to any port 51820 proto udp"
has "plan: wg only from peer B" "$OUT" "allow from 198.51.100.3 to any port 51820 proto udp"
has "plan: overlay interface" "$OUT" "allow in on wg0"

: >"$CALLS"
UFW_BIN=ufw IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" ufw --apply
expect "ufw apply exits 0" 0 "$RC"
dm="$(grep -n 'systemd-run' "$CALLS" | head -1 | cut -d: -f1)"
en="$(grep -n 'ufw --force enable' "$CALLS" | head -1 | cut -d: -f1)"
sshl="$(grep -n 'ufw allow 22/tcp' "$CALLS" | head -1 | cut -d: -f1)"
if [ -n "$dm" ] && [ -n "$en" ] && [ -n "$sshl" ] && [ "$dm" -lt "$sshl" ] && [ "$sshl" -lt "$en" ]; then ok "order: dead-man timer, ssh rule, enable"; else bad "ufw step order wrong (dm=$dm ssh=$sshl enable=$en)"; fi
has "dead-man timer reverts with ufw disable" "$CALLS" "--unit=idpha-deadman ufw --force disable"
has "dead-man is 10 minutes" "$CALLS" "--on-active=10min"
hasnt "no sshd change" "$CALLS" "sshd"
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" ufw-confirm
expect "ufw-confirm refuses without the fresh-login flag" 1 "$RC"
: >"$CALLS"
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" ufw-confirm --fresh-login-confirmed --apply
has "ufw-confirm stops the timer" "$CALLS" "systemctl stop idpha-deadman.timer"
mkvalues "$T/v-badpeer.env" '.node.peers[0].public_addr="not-an-address"'
IDPHA_PARAMS="$T/v-badpeer.env" IDPHA_ROOT="$R" runit "$H" ufw
expect "ufw refuses a malformed peer address" 1 "$RC"
mkvalues "$T/v-nopeer.env" 'del(.node.peers[1])'
IDPHA_PARAMS="$T/v-nopeer.env" IDPHA_ROOT="$R" runit "$H" ufw
expect "ufw refuses a missing peer" 1 "$RC"
mkdir -p "$T/stubs2"
printf '#!/usr/bin/env bash\nexit 0\n' >"$T/stubs2/systemctl"
chmod +x "$T/stubs2/systemctl"
PATH="$T/stubs2:$PATH" UFW_BIN=ufw IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" ufw --apply
expect "ufw refuses while a previous dead-man timer is pending" 1 "$RC"

section "harden-ha dropins"
newroot
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
expect "dropins apply exits 0" 0 "$RC"
for u in keepalived patroni docker etcd; do
	has "$u starts after wg" "$R/etc/systemd/system/$u.service.d/10-after-wireguard.conf" "After=wg-quick@wg0.service network-online.target"
done
has "keepalived restarts on failure" "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf" "Restart=on-failure"
hasnt "patroni drop-in leaves its own Restart alone" "$R/etc/systemd/system/patroni.service.d/10-after-wireguard.conf" "Restart="
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
has "dropins are idempotent" "$OUT" "already current"
# etcd: the pre-existing drop-in (the 2026-08 boot-race fix) is assert-only
echo "# pre-existing, unknown content" >"$R/etc/systemd/system/etcd.service.d/10-after-wireguard.conf"
rm -f "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf" "$R/etc/systemd/system/patroni.service.d/10-after-wireguard.conf" "$R/etc/systemd/system/docker.service.d/10-after-wireguard.conf"
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
expect "an etcd drop-in that does not order after the overlay is refused" 1 "$RC"
if [ ! -e "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf" ]; then ok "...and NOTHING else was written (validated before the first write)"; else bad "partial write before the etcd refusal"; fi
printf '[Unit]\nAfter=wg-quick@wg0.service\n# august fix\n' >"$R/etc/systemd/system/etcd.service.d/10-after-wireguard.conf"
before_etcd="$(sha_of <"$R/etc/systemd/system/etcd.service.d/10-after-wireguard.conf")"
IDPHA_REPLACE_EXISTING=1 IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
expect "a correct existing etcd drop-in is accepted" 0 "$RC"
if [ "$before_etcd" = "$(sha_of <"$R/etc/systemd/system/etcd.service.d/10-after-wireguard.conf")" ]; then ok "...and left byte-for-byte untouched even with IDPHA_REPLACE_EXISTING=1"; else bad "etcd drop-in was rewritten"; fi
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" rollback dropins --apply
if [ ! -e "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf" ]; then ok "rollback removes the drop-ins this tool owns"; else bad "rollback left the drop-in"; fi
if [ -f "$R/etc/systemd/system/etcd.service.d/10-after-wireguard.conf" ]; then ok "rollback NEVER deletes the pre-existing etcd drop-in"; else bad "rollback deleted the etcd drop-in"; fi
echo "# changed" >>"$R/etc/systemd/system/patroni.service.d/10-after-wireguard.conf" 2>/dev/null || true

section "harden-ha upgrade policy"
newroot
IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$H" upgrade-policy --apply
expect "upgrade-policy apply exits 0" 0 "$RC"
NR="$R/etc/needrestart/conf.d/90-dotmac-idpha.conf"
has "needrestart is list-only" "$NR" "\$nrconf{restart} = 'l';"
for u in patroni haproxy nginx keepalived etcd; do has "needrestart never restarts $u" "$NR" "qr(^${u}\\.service\$)"; done
TM="$R/etc/systemd/system/apt-daily-upgrade.timer.d/90-dotmac-idpha.conf"
has "apt timer is staggered" "$TM" "OnCalendar=*-*-* 01:15:00 UTC"
has "apt timer has no random delay" "$TM" "RandomizedDelaySec=0"
has "cluster packages are excluded from unattended upgrades BY DEFAULT" "$R/etc/apt/apt.conf.d/52-dotmac-idpha-blacklist" '"etcd-server";'
for pk in patroni haproxy keepalived; do has "blacklist names $pk" "$R/etc/apt/apt.conf.d/52-dotmac-idpha-blacklist" "\"$pk\";"; done
newroot
mkvalues "$T/v-noexcl.json" '.operations["harden-ha"].exclude_cluster_packages=false'
IDPHA_PARAMS="$T/v-noexcl.json" IDPHA_ROOT="$R" runit "$H" upgrade-policy --apply
if [ ! -e "$R/etc/apt/apt.conf.d/52-dotmac-idpha-blacklist" ]; then ok "the exclusion can be switched off explicitly"; else bad "exclusion written although switched off"; fi
mkvalues "$T/v-0430.env" '.operations["harden-ha"].apt_upgrade_time="04:30:00"'
IDPHA_PARAMS="$T/v-0430.env" IDPHA_ROOT="$R" runit "$H" upgrade-policy
expect "upgrade-policy refuses the legacy 04:xx window" 1 "$RC"
mkvalues "$T/v-badtime.env" '.operations["harden-ha"].apt_upgrade_time="25:99:00"'
IDPHA_PARAMS="$T/v-badtime.env" IDPHA_ROOT="$R" runit "$H" upgrade-policy
expect "upgrade-policy refuses a malformed time" 1 "$RC"

finish "t-harden"
