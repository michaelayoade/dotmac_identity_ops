#!/usr/bin/env bash
# idpha-collect.sh — H4 per-node collector. Reads LOCAL state only and writes a
# node_exporter textfile (idpha.prom), atomically. It never writes anywhere
# else, changes nothing, and emits only numbers.
#
# A check that cannot be taken emits NO sample for its metric, and
# idpha_collect_check_ok{check=...} 0 — so "the collector could not look" is
# distinguishable from "the thing is down". Alert rules treat both.
#
# Without --apply it prints the exposition to stdout and writes no file.
#
# Parameters: the typed params document (sections node, collector; cert_files and vip_addr
# on the node). KC_CLUSTER_SIZE_METRIC is optional until the metric name is confirmed.
# Knobs: IDPHA_PROM_FILE (/var/lib/prometheus/node-exporter/idpha.prom)
#        IDPHA_STATE_DIR (/var/lib/idpha)  SLOW_TTL_S (600)

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

parse_common_flags "$@"
idpha_begin collector runtime
require NODE_NAME OVERLAY_ADDR
PRIMARY_NIC="${PRIMARY_NIC:-eth0}"
WG_IF="${WG_IF:-wg0}"
PATRONI_PORT="${PATRONI_PORT:-8008}"
IDPHA_PROM_FILE="${IDPHA_PROM_FILE:-/var/lib/prometheus/node-exporter/idpha.prom}"
IDPHA_STATE_DIR="${IDPHA_STATE_DIR:-/var/lib/idpha}"
SLOW_TTL_S="${SLOW_TTL_S:-600}"
[[ "$NODE_NAME" =~ ^[A-Za-z0-9-]+$ ]] || die "NODE_NAME has unexpected characters"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
declare_metric() { printf '# HELP %s %s\n# TYPE %s gauge\n' "$1" "$2" "$1" >>"$out"; }
emit() { # emit <name> <labels or ""> <value>
	if [ -n "$2" ]; then printf '%s{%s} %s\n' "$1" "$2" "$3" >>"$out"; else printf '%s %s\n' "$1" "$3" >>"$out"; fi
}
checkok() { emit idpha_collect_check_ok "check=\"$1\"" "$2"; }
nl="node=\"$NODE_NAME\""

declare_metric idpha_collect_check_ok "1 if the collector could take this check, 0 if not"

# ---- Patroni (one REST call: /cluster lists every member) -------------------
declare_metric idpha_patroni_is_leader "1 if this node is the Patroni leader"
declare_metric idpha_patroni_is_sync_standby "1 if this node is the synchronous standby"
declare_metric idpha_patroni_timeline "current timeline as seen by this node"
declare_metric idpha_patroni_lag_bytes "replication lag of this node in bytes"
if cluster="$(curl -sf --max-time 4 "http://${OVERLAY_ADDR}:${PATRONI_PORT}/cluster")" &&
	parsed="$(printf '%s' "$cluster" | python3 -c '
import json, sys
c = json.load(sys.stdin)
me = [m for m in c.get("members", []) if m.get("name") == sys.argv[1]]
if not me:
    sys.exit(3)
m = me[0]
lag = m.get("lag", 0)
print(int(m.get("role") == "leader"), int(m.get("role") == "sync_standby"), int(m.get("timeline", 0)), int(lag) if isinstance(lag, int) else 0)
' "$NODE_NAME")"; then
	set -- $parsed
	emit idpha_patroni_is_leader "$nl" "$1"
	emit idpha_patroni_is_sync_standby "$nl" "$2"
	emit idpha_patroni_timeline "$nl" "$3"
	emit idpha_patroni_lag_bytes "$nl" "$4"
	checkok patroni 1
else
	checkok patroni 0
fi

# ---- etcd --------------------------------------------------------------------
declare_metric idpha_etcd_members_healthy "members answering the health check"
declare_metric idpha_etcd_has_leader "1 if exactly one member reports itself leader"
# etcdctl 3.4 rejects "-w tsv": JSON output, parsed by lib-idpha.sh (etcd_summary).
if es="$(etcd_summary)" && [ -n "$es" ]; then
	set -- $es
	emit idpha_etcd_members_healthy "$nl" "$1"
	emit idpha_etcd_has_leader "$nl" "$([ "$2" = "1" ] && echo 1 || echo 0)"
	checkok etcd 1
else
	checkok etcd 0
fi

# ---- keepalived / VIP / Keycloak ------------------------------------------------
declare_metric idpha_keepalived_active "1 if keepalived is active"
if systemctl is-active --quiet keepalived; then emit idpha_keepalived_active "$nl" 1; else emit idpha_keepalived_active "$nl" 0; fi
declare_metric idpha_vip_present "1 if this node currently holds the VIP"
if [ -n "${VIP_ADDR:-}" ]; then
	if ip -4 -o addr show dev "$PRIMARY_NIC" 2>/dev/null | grep -q " ${VIP_ADDR}/"; then emit idpha_vip_present "$nl" 1; else emit idpha_vip_present "$nl" 0; fi
	checkok vip 1
else
	checkok vip 0
fi
declare_metric idpha_keycloak_ready "1 if Keycloak readiness answers 200 locally"
if curl -sf --max-time 3 -o /dev/null http://127.0.0.1:9000/health/ready; then emit idpha_keycloak_ready "$nl" 1; else emit idpha_keycloak_ready "$nl" 0; fi
if [ -n "${KC_CLUSTER_SIZE_METRIC:-}" ]; then
	declare_metric idpha_keycloak_cluster_size "Infinispan view size seen by this node"
	if sz="$(curl -sf --max-time 4 http://127.0.0.1:9000/metrics | awk -v m="$KC_CLUSTER_SIZE_METRIC" '$1 ~ "^"m {print int($2); exit}')" && [ -n "$sz" ]; then
		emit idpha_keycloak_cluster_size "$nl" "$sz"
		checkok kc_cluster_size 1
	else
		checkok kc_cluster_size 0
	fi
fi

# ---- host posture ---------------------------------------------------------------
declare_metric idpha_ufw_active "1 if ufw is active"
if ufw status 2>/dev/null | head -1 | grep -q 'Status: active'; then emit idpha_ufw_active "$nl" 1; else emit idpha_ufw_active "$nl" 0; fi
declare_metric idpha_reboot_required "1 if a reboot is pending"
if [ -f /var/run/reboot-required ]; then emit idpha_reboot_required "$nl" 1; else emit idpha_reboot_required "$nl" 0; fi

# ---- WireGuard ---------------------------------------------------------------------
declare_metric idpha_wg_handshake_age_seconds "seconds since the latest handshake per peer (peer = index)"
if hs="$(wg show "$WG_IF" latest-handshakes 2>/dev/null)"; then
	now="$(date +%s)"
	i=0
	while read -r _ ts; do
		[ -n "${ts:-}" ] || continue
		i=$((i + 1))
		if [ "$ts" = "0" ]; then age=999999; else age=$((now - ts)); fi
		emit idpha_wg_handshake_age_seconds "$nl,peer=\"$i\"" "$age"
	done <<<"$hs"
	checkok wireguard 1
else
	checkok wireguard 0
fi

# ---- backup freshness (written by ha-backup.sh on success) ---------------------------
declare_metric idpha_backup_last_success_seconds "unix time of the last successful upload from this node"
if [ -r "$IDPHA_STATE_DIR/backup.last" ]; then emit idpha_backup_last_success_seconds "$nl" "$(tr -dc '0-9' <"$IDPHA_STATE_DIR/backup.last")"; fi

# ---- slow checks, cached ----------------------------------------------------------------
cache_fresh() { # <file>
	[ -f "$1" ] || return 1
	local m now
	m="$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1")"
	now="$(date +%s)"
	[ $((now - m)) -lt "$SLOW_TTL_S" ]
}
mkdir -p "$IDPHA_STATE_DIR/cache" 2>/dev/null || true
declare_metric idpha_needrestart_pending "services needrestart would restart"
nrc="$IDPHA_STATE_DIR/cache/needrestart"
if ! cache_fresh "$nrc"; then
	needrestart -b -r l 2>/dev/null | grep -c '^NEEDRESTART-SVC:' >"$nrc" || true
fi
if [ -r "$nrc" ]; then emit idpha_needrestart_pending "$nl" "$(tr -dc '0-9' <"$nrc")"; fi

# Excluded cluster packages with a security update waiting (they are upgraded by
# the weekly rolling maintenance, not by unattended upgrades). The age is tracked
# from the first run that saw the update, so "pending > 8 days" is alertable.
declare_metric idpha_cluster_pkg_pending_age_seconds "seconds a security update has been pending for an excluded cluster package (0 = none)"
pk_cache="$IDPHA_STATE_DIR/cache/pkgpending"
if ! cache_fresh "$pk_cache.stamp"; then
	sim="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null || true)"
	for pkg in patroni etcd-server haproxy keepalived; do
		if printf '%s\n' "$sim" | grep -E "^Inst $pkg " | grep -qi security; then
			[ -f "$pk_cache.$pkg" ] || date +%s >"$pk_cache.$pkg"
		else
			rm -f "$pk_cache.$pkg"
		fi
	done
	touch "$pk_cache.stamp"
fi
for pkg in patroni etcd-server haproxy keepalived; do
	if [ -f "$pk_cache.$pkg" ]; then
		emit idpha_cluster_pkg_pending_age_seconds "$nl,pkg=\"$pkg\"" "$(( $(date +%s) - $(tr -dc '0-9' <"$pk_cache.$pkg") ))"
	else
		emit idpha_cluster_pkg_pending_age_seconds "$nl,pkg=\"$pkg\"" 0
	fi
done

declare_metric idpha_cert_not_after_seconds "certificate notAfter as unix time"
for pair in ${CERT_FILES:-}; do
	cname="${pair%%=*}"
	cpath="${pair#*=}"
	[[ "$cname" =~ ^[A-Za-z0-9_-]+$ ]] || continue
	if end="$(openssl x509 -enddate -noout -in "$cpath" 2>/dev/null | sed 's/^notAfter=//')" && [ -n "$end" ]; then
		epoch="$(date -d "$end" +%s 2>/dev/null || date -j -f '%b %e %T %Y %Z' "$end" +%s 2>/dev/null || true)"
		if [ -n "$epoch" ]; then emit idpha_cert_not_after_seconds "$nl,name=\"$cname\"" "$epoch"; fi
	fi
done

declare_metric idpha_collect_timestamp_seconds "unix time this exposition was produced"
emit idpha_collect_timestamp_seconds "$nl" "$(date +%s)"

if is_apply; then
	mkdir -p "$(dirname "$IDPHA_PROM_FILE")"
	cp "$out" "$IDPHA_PROM_FILE.tmp"
	chmod 644 "$IDPHA_PROM_FILE.tmp"
	mv "$IDPHA_PROM_FILE.tmp" "$IDPHA_PROM_FILE"
else
	cat "$out"
	effect "$(_tab write "$IDPHA_PROM_FILE" 644 - 0)"
fi
idpha_end
