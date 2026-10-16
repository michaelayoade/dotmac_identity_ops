#!/usr/bin/env bash
# harden-ha.sh — the H1 host/network parity layer for an IdP HA node.
# Reproducible from Git so a rebuilt node gets the same drop-ins (packet rule 7).
# Run as root ON the node, one node at a time, replica first, never during an
# apt-daily-upgrade window. DRY-RUN unless APPLY=1 / --apply.
#
#   harden-ha.sh preview                  show everything (always dry)
#   harden-ha.sh ufw                      firewall behind a 10 minute dead-man timer
#   harden-ha.sh ufw-confirm --fresh-login-confirmed
#                                         cancel the dead-man timer
#   harden-ha.sh dropins                  After=wg-quick + Restart drop-ins
#   harden-ha.sh upgrade-policy           needrestart list-only + staggered apt timer
#   harden-ha.sh wait-online              (optional) scope networkd wait-online to the NIC
#   harden-ha.sh rollback <ufw|dropins|upgrade-policy|wait-online>
#
# Parameters: the typed params document (--params FILE|-, see ha/params.schema.json),
# sections `node` and `operations.harden-ha`. Preview the effect with --plan (JSON +
# digest); --apply needs --expect-digest <that digest> and re-plans first.
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
cmd="${1:-preview}"
shift || true

if [ "$cmd" = "preview" ]; then APPLY=0; fi
if is_apply && [ "${IDPHA_ROOT:-}" = "" ] && [ "$(id -u)" != "0" ]; then die "APPLY needs root"; fi

idpha_begin harden-ha
mode_banner
trap on_failure_restore EXIT

# peers_match_wg: the two peer addresses in the params must be the endpoints
# WireGuard is actually using. A wrong address does not bite while the existing
# UDP flow sits in conntrack; it bites at the next reboot (M-9).
peers_match_wg() {
	local want got
	want="$(printf '%s\n%s\n' "$PEER_PUBLIC_1" "$PEER_PUBLIC_2" | LC_ALL=C sort)"
	got="$(wg show "$WG_IF" endpoints 2>/dev/null | awk '{sub(/:[0-9]+$/, "", $2); print $2}' | LC_ALL=C sort)" || true
	[ -n "$got" ] || die "cannot read 'wg show $WG_IF endpoints': refusing to firewall WireGuard blind"
	[ "$want" = "$got" ] || die "peer public addresses in the params differ from the WireGuard endpoints on this host"
}

do_ufw() {
	require PEER_PUBLIC_1 PEER_PUBLIC_2
	local p
	for p in "$PEER_PUBLIC_1" "$PEER_PUBLIC_2"; do
		is_ipv4 "$p" || die "peer public value '$p' is not an IPv4 address"
	done
	peers_match_wg
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
	# The flag is necessary, not sufficient: the overlay and the cluster must be
	# healthy WITH the firewall on before the safety net is removed.
	require PATRONI_CONF
	cluster_health || die "cluster health check failed with ufw active: leaving the dead-man timer running"
	run systemctl stop "$DEADMAN_UNIT.timer" "$DEADMAN_UNIT.service"
	run systemctl reset-failed "$DEADMAN_UNIT.service"
}

dropin_path() { echo "/etc/systemd/system/$1.service.d/10-after-wireguard.conf"; }

do_dropins() {
	local u f
	# Preflight EVERY unit before the first write (M-7). etcd already carries the
	# 2026-08 boot-race fix: it is assert-only, never replaced (M-8).
	f="$(hostpath "$(dropin_path etcd)")"
	if [ -f "$f" ]; then
		grep -q "^After=.*${WG_UNIT:-wg-quick@wg0.service}" "$f" || die "the existing etcd drop-in does not order etcd after ${WG_UNIT:-wg-quick@wg0.service}; fix it by hand (this tool never replaces it)"
	fi
	for u in keepalived patroni docker; do
		if dropin_after_wg "$u" | guard_violation "$(dropin_path "$u")" && [ "$IDPHA_REPLACE_EXISTING" != "1" ]; then
			die "$(dropin_path "$u") exists with different content; review it, then re-run with IDPHA_REPLACE_EXISTING=1"
		fi
	done
	for u in keepalived patroni docker; do
		dropin_after_wg "$u" | put_file "$(dropin_path "$u")" 644 guard
	done
	if [ -f "$f" ]; then okline "etcd drop-in present and orders after the overlay (left untouched)"; else dropin_after_wg etcd | put_file "$(dropin_path etcd)" 644; fi
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
	if [ "${EXCLUDE_CLUSTER_PACKAGES:-1}" = 1 ]; then
		# APPROVED WIDENING (patch latency; Michael, 2026-10-16), ON by default. These packages' maintainer scripts
		# restart the service on upgrade whatever needrestart says, so a leader
		# upgrade fails over; rolling-maint upgrades them per node after a switchover.
		cat <<'CONF' | put_file /etc/apt/apt.conf.d/52-dotmac-idpha-blacklist 644
// Managed by dotmac_identity_ops (bin/harden-ha.sh, exclude_cluster_packages=true).
Unattended-Upgrade::Package-Blacklist {
	"patroni";
	"etcd-server";
	"haproxy";
	"keepalived";
};
CONF
	else
		note "cluster packages stay in unattended upgrades (exclude_cluster_packages=false)"
	fi
	run systemctl daemon-reload
	note "Read back: systemctl list-timers apt-daily-upgrade.timer ; needrestart -b -r l"
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
			# etcd's drop-in predates this tool and is never removed here; a run
			# that CREATED it is undone by the run-stamp restore instead.
			for u in keepalived patroni docker; do
				remove_file "$(dropin_path "$u")"
			done
			run systemctl daemon-reload
			;;
		upgrade-policy)
			remove_file /etc/apt/apt.conf.d/52-dotmac-idpha-blacklist
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
	preview)
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
idpha_end
