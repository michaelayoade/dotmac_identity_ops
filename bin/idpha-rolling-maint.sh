#!/usr/bin/env bash
# idpha-rolling-maint.sh — planned maintenance of ONE IdP HA node (D-H3). Replaces
# the old behaviour where an unattended upgrade restarted the Patroni leader on
# all three nodes at once (H-F1). Run on the node being maintained, as root, one
# node at a time, replicas first; never from a timer until packet H5 has proven it.
#
#   idpha-rolling-maint.sh [--apply] [--allow-reboot]
#
# Steps (dry-run prints them, changing nothing):
#   1. preflight: 3 healthy etcd members, Patroni healthy, WireGuard handshakes fresh
#   2. needrestart -b -> the services that need a restart (allowlist only)
#   3. if this node is the Patroni leader: switchover to a healthy replica FIRST
#   4. restart each listed service, health re-checked after every one
#   5. reboot only with --allow-reboot, and only if /var/run/reboot-required
#      exists; after the reboot, run this script again (it then just checks health)
#
# Any failed health check stops the run with the node as it is. It never loops,
# never restarts a service outside the allowlist, never touches a second node.
#
# Knobs: PATRONICTL PATRONI_CONF  RESTART_ALLOWLIST (patroni haproxy nginx keepalived etcd fail2ban)
#        HEALTH_WAIT_S (120)  Values (private): OVERLAY_ADDR WG_IF

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

PATRONICTL="${PATRONICTL:-patronictl}"
PATRONI_CONF="${PATRONI_CONF:-/etc/patroni/config.yml}"
RESTART_ALLOWLIST="${RESTART_ALLOWLIST:-patroni haproxy nginx keepalived etcd fail2ban}"
HEALTH_WAIT_S="${HEALTH_WAIT_S:-120}"
ALLOW_REBOOT=0
args=()
for a in "$@"; do
	case "$a" in
		--allow-reboot) ALLOW_REBOOT=1 ;;
		*) args+=("$a") ;;
	esac
done
parse_common_flags ${args[@]+"${args[@]}"}
mode_banner
load_values
require OVERLAY_ADDR
WG_IF="${WG_IF:-wg0}"
if is_apply && [ "${IDPHA_ROOT:-}" = "" ] && [ "$(id -u)" != "0" ]; then die "APPLY needs root"; fi

health() { # 0 healthy, 1 not (prints why)
	local healthy table verdict now stale=0 ts cnt=0
	healthy="$(ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 endpoint health --cluster 2>&1 | grep -c 'is healthy' || true)"
	[ "$healthy" = "3" ] || {
		echo "      etcd healthy members: $healthy (want 3)"
		return 1
	}
	table="$("$PATRONICTL" -c "$PATRONI_CONF" list -f tsv 2>/dev/null)" || {
		echo "      patronictl list failed"
		return 1
	}
	verdict="$(printf '%s\n' "$table" | awk -F'\t' '
		NR == 1 { for (i = 1; i <= NF; i++) { if ($i == "Role") r = i; if ($i == "State") s = i } next }
		{ n++; if ($r ~ /Leader/) l++; if ($s != "running" && $s != "streaming") b++ }
		END { printf "%d/%d/%d", n, l, b }')"
	[ "$verdict" = "3/1/" ] || [ "$verdict" = "3/1/0" ] || {
		echo "      patroni members/leaders/notok = $verdict (want 3/1/0)"
		return 1
	}
	now="$(date +%s)"
	while read -r _ ts; do
		[ -n "${ts:-}" ] || continue
		cnt=$((cnt + 1))
		{ [ "$ts" -gt 0 ] && [ $((now - ts)) -lt 150 ]; } || stale=$((stale + 1))
	done < <(wg show "$WG_IF" latest-handshakes 2>/dev/null)
	[ "$cnt" -ge 2 ] && [ "$stale" = 0 ] || {
		echo "      wireguard: $stale stale of $cnt peers"
		return 1
	}
}

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
pending="$(needrestart -b 2>/dev/null | sed -n 's/^NEEDRESTART-SVC: //p' | sed 's/\.service$//' || true)"
todo=""
for svc in $pending; do
	case " $RESTART_ALLOWLIST " in
		*" $svc "*) todo="$todo $svc" ;;
		*) note "      skip $svc (not in the restart allowlist)" ;;
	esac
done
note "      to restart:${todo:- none}"

if [ -n "$todo" ] || { [ -f "$(hostpath /var/run/reboot-required)" ] && [ "$ALLOW_REBOOT" = 1 ]; }; then
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

note "-- 4. restarts"
for svc in $todo; do
	run systemctl restart "$svc"
	if is_apply; then wait_healthy; okline "$svc restarted; cluster healthy"; fi
done

note "-- 5. reboot"
if [ -f "$(hostpath /var/run/reboot-required)" ]; then
	if [ "$ALLOW_REBOOT" = 1 ]; then
		run systemctl reboot
		note "after the node returns, run this script again (preflight only) before touching the next node"
	else
		note "      reboot required; re-run with --allow-reboot when ready"
	fi
else
	okline "no reboot required"
fi
