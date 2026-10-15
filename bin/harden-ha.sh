#!/usr/bin/env bash
# harden-ha.sh — the H1 host/network parity layer for an IdP HA node.
# Reproducible from Git so a rebuilt node gets the same drop-ins (packet rule 7).
# Run as root ON the node, one node at a time, replica first, never during an
# apt-daily-upgrade window. DRY-RUN unless APPLY=1 / --apply.
#
#   harden-ha.sh plan                     show everything (always dry)
#   harden-ha.sh ufw                      firewall behind a 10 minute dead-man timer
#   harden-ha.sh ufw-confirm --fresh-login-confirmed
#                                         cancel the dead-man timer
#   harden-ha.sh dropins                  After=wg-quick + Restart drop-ins
#   harden-ha.sh upgrade-policy           needrestart list-only + staggered apt timer
#   harden-ha.sh wait-online              (optional) scope networkd wait-online to the NIC
#   harden-ha.sh rollback <ufw|dropins|upgrade-policy|wait-online>
#
# Values (private, never in Git): see ha/idpha.env.example. Required here:
#   PEER_PUBLIC_1 PEER_PUBLIC_2  the two peers' public addresses (wg transport)
#   APT_UPGRADE_TIME             HH:MM:SS UTC, distinct per node
# Optional: SSH_PORT (22) WG_IF (wg0) WG_PORT (51820) WG_UNIT (wg-quick@wg0.service)
#           PRIMARY_NIC (eth0) DEADMAN_MINUTES (10)
#
# It does NOT touch sshd settings (fleet-access S6 owns those) and never
# restarts patroni, etcd, haproxy or nginx.

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

DEADMAN_UNIT="${DEADMAN_UNIT:-idpha-deadman}"
DEADMAN_MINUTES="${DEADMAN_MINUTES:-10}"
UFW_BIN="${UFW_BIN:-/usr/sbin/ufw}"

parse_common_flags "$@"
set -- ${REST_ARGS[@]+"${REST_ARGS[@]}"}
cmd="${1:-plan}"
shift || true

if [ "$cmd" = "plan" ]; then APPLY=0; fi
if is_apply && [ "${IDPHA_ROOT:-}" = "" ] && [ "$(id -u)" != "0" ]; then die "APPLY needs root"; fi

mode_banner
load_values

do_ufw() {
	require PEER_PUBLIC_1 PEER_PUBLIC_2
	local p
	for p in "$PEER_PUBLIC_1" "$PEER_PUBLIC_2"; do
		is_cidr "$p" || die "peer public value '$p' is not an IPv4 address or CIDR"
	done
	[[ "${SSH_PORT:-22}" =~ ^[0-9]+$ ]] || die "SSH_PORT is not numeric"
	if is_apply; then
		command -v "$UFW_BIN" >/dev/null 2>&1 || [ -x "$UFW_BIN" ] || die "ufw is not installed at $UFW_BIN"
		if systemctl is-active --quiet "$DEADMAN_UNIT.timer" 2>/dev/null; then
			die "a dead-man timer ($DEADMAN_UNIT) is already running: a previous ufw step was never confirmed. Verify access from a fresh login, run 'ufw-confirm', then retry."
		fi
		if "$UFW_BIN" status 2>/dev/null | grep -q '^Status: active'; then
			die "ufw is already active. Run host-check.sh; use 'rollback ufw' first if the rule set must be re-applied"
		fi
	fi
	note "-- ufw: ssh port ${SSH_PORT:-22} is allowed BEFORE enabling; dead-man timer first"
	run systemd-run "--on-active=${DEADMAN_MINUTES}min" "--unit=$DEADMAN_UNIT" "$UFW_BIN" --force disable
	run "$UFW_BIN" default deny incoming
	run "$UFW_BIN" default allow outgoing
	run "$UFW_BIN" default deny routed
	local line
	while IFS= read -r line; do
		# shellcheck disable=SC2086 # the rule line is deliberately word-split
		run "$UFW_BIN" $line
	done < <(ufw_allow_args)
	run "$UFW_BIN" --force enable
	note "NEXT: open a NEW terminal (ssh -o ControlMaster=no -o ControlPath=none), run host-check.sh,"
	note "      then:  harden-ha.sh ufw-confirm --fresh-login-confirmed   (else ufw disables itself in ${DEADMAN_MINUTES} min)"
}

do_ufw_confirm() {
	[ "${1:-}" = "--fresh-login-confirmed" ] || die "ufw-confirm needs --fresh-login-confirmed (a NEW ssh session worked, with ControlMaster off)"
	run systemctl stop "$DEADMAN_UNIT.timer"
}

do_dropins() {
	local u
	for u in $ORDERED_UNITS; do
		# etcd already carries a drop-in with this name from the 2026-08 fix whose
		# content this repo has not seen: guard it.
		dropin_after_wg "$u" | put_file "/etc/systemd/system/$u.service.d/10-after-wireguard.conf" 644 guard
	done
	run systemctl daemon-reload
	note "NEXT (first run on a node whose keepalived is failed): systemctl reset-failed keepalived && systemctl start keepalived"
}

do_upgrade_policy() {
	require APT_UPGRADE_TIME
	[[ "$APT_UPGRADE_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$ ]] || die "APT_UPGRADE_TIME '$APT_UPGRADE_TIME' is not HH:MM:SS"
	# Never schedule inside the window the old stock timer used (04:00-05:00Z):
	# the point is to stagger away from it.
	case "$APT_UPGRADE_TIME" in 04:* ) die "APT_UPGRADE_TIME falls in the legacy 04:00-05:00 window" ;; esac
	{
		echo "# Managed by dotmac_identity_ops (bin/harden-ha.sh). H-F1: package upgrades must never"
		echo "# restart the Patroni leader, haproxy, nginx, keepalived or etcd on their own."
		echo "# List-only: the weekly rolling-maintenance run restarts them, one node at a time."
		echo "\$nrconf{restart} = 'l';"
		local u
		for u in $NO_RESTART_UNITS; do
			echo "\$nrconf{override_rc}{qr(^${u}\\.service\$)} = 0;"
		done
	} | put_file /etc/needrestart/conf.d/90-dotmac-idpha.conf 644
	cat <<CONF | put_file /etc/systemd/system/apt-daily-upgrade.timer.d/90-dotmac-idpha.conf 644
# Managed by dotmac_identity_ops. Each HA node upgrades at a DIFFERENT time so one
# bad package can never take all three down together (H-F1 correlated failure).
[Timer]
OnCalendar=
OnCalendar=*-*-* ${APT_UPGRADE_TIME} UTC
RandomizedDelaySec=0
CONF
	run systemctl daemon-reload
	note "Read back: systemctl list-timers apt-daily-upgrade.timer ; needrestart -b"
}

do_wait_online() {
	cat <<CONF | put_file /etc/systemd/system/systemd-networkd-wait-online.service.d/90-dotmac-idpha.conf 644
# Managed by dotmac_identity_ops. Without this, network-online.target waits on
# interfaces that never come up and means nothing. Scope it to the NIC.
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --interface=${PRIMARY_NIC:-eth0} --timeout=60
CONF
	run systemctl daemon-reload
}

do_rollback() {
	case "${1:-}" in
		ufw) run "$UFW_BIN" --force disable ;;
		dropins)
			local u
			for u in $ORDERED_UNITS; do
				[ "$u" = etcd ] && [ "$IDPHA_REPLACE_EXISTING" != "1" ] && {
					note "keeping etcd drop-in (pre-existing since the 2026-08 fix); set IDPHA_REPLACE_EXISTING=1 to remove"
					continue
				}
				remove_file "/etc/systemd/system/$u.service.d/10-after-wireguard.conf"
			done
			run systemctl daemon-reload
			;;
		upgrade-policy)
			remove_file /etc/needrestart/conf.d/90-dotmac-idpha.conf
			remove_file /etc/systemd/system/apt-daily-upgrade.timer.d/90-dotmac-idpha.conf
			run systemctl daemon-reload
			;;
		wait-online)
			remove_file /etc/systemd/system/systemd-networkd-wait-online.service.d/90-dotmac-idpha.conf
			run systemctl daemon-reload
			;;
		*) die "rollback needs one of: ufw dropins upgrade-policy wait-online" ;;
	esac
}

case "$cmd" in
	plan)
		do_ufw
		do_dropins
		do_upgrade_policy
		;;
	ufw) do_ufw ;;
	ufw-confirm) do_ufw_confirm "${1:-}" ;;
	dropins) do_dropins ;;
	upgrade-policy) do_upgrade_policy ;;
	wait-online) do_wait_online ;;
	rollback) do_rollback "${1:-}" ;;
	*) die "unknown command '$cmd' (see header)" ;;
esac
