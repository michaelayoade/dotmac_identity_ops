#!/usr/bin/env bash
# idpha-rolling-maint.sh — planned maintenance of ONE IdP HA node (D-H3). Replaces
# the old behaviour where an unattended upgrade restarted the Patroni leader on
# all three nodes at once (H-F1). Run on the node being maintained, as root, one
# node at a time, replicas first; never from a timer until packet H5 has proven it.
#
#   idpha-rolling-maint.sh --params FILE [--plan | --apply --expect-digest D] [--allow-reboot]
#
# Steps (dry-run prints them, changing nothing):
#   1. preflight: 3 healthy etcd members, Patroni healthy, WireGuard handshakes fresh
#   2. needrestart -b -r l -> the services that need a restart (allowlist only)
#   3. if this node is the Patroni leader: switchover to a healthy replica FIRST
#   4. restart each listed service, health re-checked after every one
#   3b. (param upgrade_cluster_packages, default ON) upgrade patroni, etcd-server, haproxy,
#      keepalived here, on a node that is not the leader
#   5. reboot only with --allow-reboot, and only if /var/run/reboot-required
#      exists; after the reboot, run this script again (it then just checks health)
#
# Any failed health check stops the run with the node as it is. It never loops,
# never restarts a service outside the allowlist, never touches a second node.
#
# Knobs: PATRONICTL PATRONI_CONF  RESTART_ALLOWLIST (patroni haproxy nginx keepalived etcd fail2ban)
#        HEALTH_WAIT_S (120)  Parameters: the typed params document (--params, --plan, --expect-digest)

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

PATRONICTL="${PATRONICTL:-patronictl}"
PATRONI_CONF="${PATRONI_CONF:-}"
RESTART_ALLOWLIST="${RESTART_ALLOWLIST:-patroni haproxy nginx keepalived etcd fail2ban}"
HEALTH_WAIT_S="${HEALTH_WAIT_S:-120}"
ALLOW_REBOOT=0
parse_common_flags "$@"
for a in ${REST_ARGS[@]+"${REST_ARGS[@]}"}; do
	case "$a" in
		--allow-reboot) ALLOW_REBOOT=1 ;;
		*) die "unknown argument '$a'" ;;
	esac
done
idpha_begin rolling-maint
mode_banner
require OVERLAY_ADDR PATRONI_CONF
WG_IF="${WG_IF:-wg0}"
if is_apply && [ "${IDPHA_ROOT:-}" = "" ] && [ "$(id -u)" != "0" ]; then die "APPLY needs root"; fi

health() { cluster_health; } # the shared HC set (lib-idpha.sh)

wait_healthy() {
	local i=0
	while [ "$i" -lt "$HEALTH_WAIT_S" ]; do
		health >/dev/null 2>&1 && return 0
		sleep 5
		i=$((i + 5))
	done
	health || true
	die "node did not return to healthy within ${HEALTH_WAIT_S}s; stopping with the node as it is"
}

note "-- 1. preflight"
if health; then okline "cluster healthy"; else die "preflight failed: not touching a node while the cluster is degraded"; fi

note "-- 2. services needrestart lists"
nr_out="$(needrestart -b -r l 2>/dev/null || true)"
pending="$(printf '%s\n' "$nr_out" | sed -n 's/^NEEDRESTART-SVC: //p' | sed 's/\.service$//' || true)"
# NEEDRESTART-KSTA: 2 = ABI-compatible kernel update waiting, 3 = new kernel version waiting.
# A new kernel needs a reboot even when /var/run/reboot-required is absent.
kernel_pending=0
case "$(printf '%s\n' "$nr_out" | sed -n 's/^NEEDRESTART-KSTA: //p')" in 2 | 3) kernel_pending=1 ;; esac
todo=""
for svc in $pending; do
	case " $RESTART_ALLOWLIST " in
		*" $svc "*) todo="$todo $svc" ;;
		*) note "      skip $svc (not in the restart allowlist)" ;;
	esac
done
note "      to restart:${todo:- none}"

if [ -n "$todo" ] || { { [ -f "$(hostpath /var/run/reboot-required)" ] || [ "$kernel_pending" = 1 ]; } && [ "$ALLOW_REBOOT" = 1 ]; }; then
	note "-- 3. leader check"
	if curl -sf --max-time 3 -o /dev/null "http://${OVERLAY_ADDR}:${PATRONI_PORT:-8008}/primary"; then
		cand="$("$PATRONICTL" -c "$PATRONI_CONF" list -f tsv 2>/dev/null | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++){if($i=="Role")r=i;if($i=="Member")m=i}next} $r ~ /Sync Standby/ {print $m; exit} $r ~ /Replica/ && c=="" {c=$m} END{if(!found && c!="") print c}' | head -1)"
		[ -n "$cand" ] || die "this node is the leader and no healthy candidate was found"
		note "      this node is the leader; switching over to $cand first"
		run "$PATRONICTL" -c "$PATRONI_CONF" switchover --candidate "$cand" --force
		if is_apply; then wait_healthy; fi
	else
		okline "not the leader"
	fi
fi

if [ "${UPGRADE_CLUSTER_PACKAGES:-1}" = 1 ]; then
	note "-- 3b. cluster packages (this node is not the leader now)"
	if curl -sf --max-time 3 -o /dev/null "http://${OVERLAY_ADDR}:${PATRONI_PORT:-8008}/primary"; then
		die "refusing to upgrade cluster packages on the leader: switchover first"
	fi
	run apt-get install --only-upgrade -y -o Dpkg::Options::=--force-confold patroni etcd-server haproxy keepalived
	if is_apply; then wait_healthy; okline "cluster packages current; cluster healthy"; fi
fi

note "-- 4. restarts"
for svc in $todo; do
	run systemctl restart "$svc"
	if is_apply; then wait_healthy; okline "$svc restarted; cluster healthy"; fi
done

note "-- 5. reboot"
if [ -f "$(hostpath /var/run/reboot-required)" ] || [ "$kernel_pending" = 1 ]; then
	if [ "$ALLOW_REBOOT" = 1 ]; then
		run systemctl reboot
		note "after the node returns, run this script again (preflight only) before touching the next node"
	else
		note "      reboot required (pending kernel); re-run with --allow-reboot when ready: the first maintenance on a node with a pending kernel needs it"
	fi
else
	okline "no reboot required"
fi
idpha_end
