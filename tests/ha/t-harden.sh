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

section "harden-ha plan / ufw"
newroot
: >"$CALLS"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" plan
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
UFW_BIN=ufw IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" ufw --apply
expect "ufw apply exits 0" 0 "$RC"
dm="$(grep -n 'systemd-run' "$CALLS" | head -1 | cut -d: -f1)"
en="$(grep -n 'ufw --force enable' "$CALLS" | head -1 | cut -d: -f1)"
sshl="$(grep -n 'ufw allow 22/tcp' "$CALLS" | head -1 | cut -d: -f1)"
if [ -n "$dm" ] && [ -n "$en" ] && [ -n "$sshl" ] && [ "$dm" -lt "$sshl" ] && [ "$sshl" -lt "$en" ]; then ok "order: dead-man timer, ssh rule, enable"; else bad "ufw step order wrong (dm=$dm ssh=$sshl enable=$en)"; fi
has "dead-man timer reverts with ufw disable" "$CALLS" "--unit=idpha-deadman ufw --force disable"
has "dead-man is 10 minutes" "$CALLS" "--on-active=10min"
hasnt "no sshd change" "$CALLS" "sshd"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" ufw-confirm
expect "ufw-confirm refuses without the fresh-login flag" 1 "$RC"
: >"$CALLS"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" ufw-confirm --fresh-login-confirmed --apply
has "ufw-confirm stops the timer" "$CALLS" "systemctl stop idpha-deadman.timer"
mkvalues "$T/v-badpeer.env" "PEER_PUBLIC_1=not-an-address"
IDPHA_VALUES="$T/v-badpeer.env" IDPHA_ROOT="$R" runit "$H" ufw
expect "ufw refuses a malformed peer address" 1 "$RC"
grep -v PEER_PUBLIC_2 "$V" >"$T/v-nopeer.env"
chmod 600 "$T/v-nopeer.env"
IDPHA_VALUES="$T/v-nopeer.env" IDPHA_ROOT="$R" runit "$H" ufw
expect "ufw refuses a missing peer" 1 "$RC"
mkdir -p "$T/stubs2"
printf '#!/usr/bin/env bash\nexit 0\n' >"$T/stubs2/systemctl"
chmod +x "$T/stubs2/systemctl"
PATH="$T/stubs2:$PATH" UFW_BIN=ufw IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" ufw --apply
expect "ufw refuses while a previous dead-man timer is pending" 1 "$RC"

section "harden-ha dropins"
newroot
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
expect "dropins apply exits 0" 0 "$RC"
for u in keepalived patroni docker etcd; do
	has "$u starts after wg" "$R/etc/systemd/system/$u.service.d/10-after-wireguard.conf" "After=wg-quick@wg0.service network-online.target"
done
has "keepalived restarts on failure" "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf" "Restart=on-failure"
hasnt "patroni drop-in leaves its own Restart alone" "$R/etc/systemd/system/patroni.service.d/10-after-wireguard.conf" "Restart="
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
has "dropins are idempotent" "$OUT" "already current"
echo "# pre-existing, unknown content" >"$R/etc/systemd/system/etcd.service.d/10-after-wireguard.conf"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
expect "a different existing drop-in is not overwritten silently" 1 "$RC"
IDPHA_REPLACE_EXISTING=1 IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" dropins --apply
expect "...but can be replaced deliberately" 0 "$RC"
if [ -n "$(find "$R/var/lib/idpha/backup" -name 10-after-wireguard.conf 2>/dev/null)" ]; then ok "replaced file was backed up"; else bad "no backup of the replaced drop-in"; fi
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" rollback dropins --apply
if [ ! -e "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf" ]; then ok "rollback removes the drop-in"; else bad "rollback left the drop-in"; fi

section "harden-ha upgrade policy"
newroot
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$H" upgrade-policy --apply
expect "upgrade-policy apply exits 0" 0 "$RC"
NR="$R/etc/needrestart/conf.d/90-dotmac-idpha.conf"
has "needrestart is list-only" "$NR" "\$nrconf{restart} = 'l';"
for u in patroni haproxy nginx keepalived etcd; do has "needrestart never restarts $u" "$NR" "qr(^${u}\\.service\$)"; done
TM="$R/etc/systemd/system/apt-daily-upgrade.timer.d/90-dotmac-idpha.conf"
has "apt timer is staggered" "$TM" "OnCalendar=*-*-* 01:15:00 UTC"
has "apt timer has no random delay" "$TM" "RandomizedDelaySec=0"
mkvalues "$T/v-0430.env" "APT_UPGRADE_TIME=04:30:00"
IDPHA_VALUES="$T/v-0430.env" IDPHA_ROOT="$R" runit "$H" upgrade-policy
expect "upgrade-policy refuses the legacy 04:xx window" 1 "$RC"
mkvalues "$T/v-badtime.env" "APT_UPGRADE_TIME=25:99:00"
IDPHA_VALUES="$T/v-badtime.env" IDPHA_ROOT="$R" runit "$H" upgrade-policy
expect "upgrade-policy refuses a malformed time" 1 "$RC"

section "values file safety"
cp "$V" "$T/v-open.env"
chmod 644 "$T/v-open.env"
IDPHA_ALLOW_UNSAFE_VALUES=0 IDPHA_VALUES="$T/v-open.env" IDPHA_ROOT="$R" runit "$H" plan
expect "a values file that is not root-owned 600 is refused" 1 "$RC"
IDPHA_VALUES="$T/missing.env" runit "$H" plan
expect "a missing values file is refused" 1 "$RC"

finish "t-harden"
