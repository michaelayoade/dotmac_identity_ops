#!/usr/bin/env bash
# host-check.sh — READ-ONLY posture check for an IdP HA node (packets H1.8, H2.6).
# Changes nothing, prints no secret, needs root only to read ufw/sshd -T state.
# One JSON document on stdout (and to --out, mode 600); exit 1 if any check FAILs.
#
#   host-check.sh --params FILE [--phase pre-keycloak|running] [--gate closed|open] [--out FILE]
#
# --phase pre-keycloak  Keycloak is stopped (H1/H2 window): listener checks for
#                       8080/9000 are SKIPPED, not passed.
# --phase running       Keycloak is up (H5 onward): 8080 must be loopback-only.
# --gate                the vhost allowlist state this phase expects (default closed).
#
# Statuses: PASS | FAIL | WARN | SKIP. WARN never fails the run but is reported;
# SKIP means "could not be judged here" and is never counted as a pass.
#
# Parameters: the typed params document (sections node, host-check, plus the apt time
# from harden-ha and the hostname from ha-install when present). Read-only: no digest.

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$LIB_DIR/.." && pwd)}"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

phase="pre-keycloak"
gate="closed"
outfile=""
while [ $# -gt 0 ]; do
	case "$1" in
		--phase)
			phase="${2:-}"
			shift 2
			;;
		--gate)
			gate="${2:-}"
			shift 2
			;;
		--params)
			IDPHA_PARAMS="${2:-}"
			shift 2
			;;
		--out)
			outfile="${2:-}"
			shift 2
			;;
		*) die "unknown argument '$1'" ;;
	esac
done
case "$phase" in pre-keycloak | running) ;; *) die "--phase must be pre-keycloak or running" ;; esac
case "$gate" in closed | open) ;; *) die "--gate must be closed or open" ;; esac

idpha_begin host-check runtime
require NODE_NAME PEER_PUBLIC_1 PEER_PUBLIC_2 OVERLAY_ADDR APT_UPGRADE_TIME KC_HOSTNAME

WG_IF="${WG_IF:-wg0}"
WG_UNIT="${WG_UNIT:-wg-quick@wg0.service}"
require HA_DIR
PROVIDER_CRED_FILE="${PROVIDER_CRED_FILE:-}"
COMPOSE_DEST="${COMPOSE_DEST:-$HA_DIR/compose.yml}"
CACHE_FILE="${CACHE_FILE:-$HA_DIR/cache-ispn.xml}"
GATE_DEST="${GATE_DEST:-/etc/nginx/snippets/idpha-gate.conf}"
CERT_MIN_DAYS="${CERT_MIN_DAYS:-21}"
pin_ref="$(sed -n 's/^KC_IMAGE_REF=//p' "$REPO_ROOT/ha/image.pin" 2>/dev/null || true)"

results="$(mktemp)"
trap 'rm -f "$results"' EXIT
fails=0
warns=0
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n\t' '  '; }
rec() { # rec <PASS|FAIL|WARN|SKIP> <name> <detail>
	case "$1" in FAIL) fails=$((fails + 1)) ;; WARN) warns=$((warns + 1)) ;; esac
	printf '{"name":"%s","status":"%s","detail":"%s"}\n' "$(json_escape "$2")" "$1" "$(json_escape "$3")" >>"$results"
}
check() { # check <name> <detail-on-fail> <command...>
	local name="$1" detail="$2"
	shift 2
	if "$@" >/dev/null 2>&1; then rec PASS "$name" ""; else rec FAIL "$name" "$detail"; fi
}
hp() { hostpath "$1"; }

# ---- H1: firewall ------------------------------------------------------------
ufw_v="$(ufw status verbose 2>/dev/null || true)"
if printf '%s' "$ufw_v" | grep -q '^Status: active'; then
	rec PASS ufw.active ""
	printf '%s' "$ufw_v" | grep -q 'Default: deny (incoming), allow (outgoing), deny (routed)' && rec PASS ufw.defaults "" || rec FAIL ufw.defaults "defaults are not deny/allow/deny(routed)"
	v4="$(printf '%s\n' "$ufw_v" | grep 'ALLOW IN' | grep -v '(v6)' || true)"
	n="$(printf '%s' "$v4" | grep -c . || true)"
	expect=6
	[ "$n" = "$expect" ] && rec PASS ufw.rule_count "" || rec FAIL ufw.rule_count "expected $expect IPv4 allow rules, found $n"
	for pat in "^${SSH_PORT:-22}/tcp " "^80/tcp " "^443/tcp " "^${WG_PORT:-51820}/udp .*${PEER_PUBLIC_1}" "^${WG_PORT:-51820}/udp .*${PEER_PUBLIC_2}" "^Anywhere on ${WG_IF} "; do
		if printf '%s\n' "$v4" | grep -Eq "$pat"; then rec PASS "ufw.rule" ""; else rec FAIL "ufw.rule" "missing rule matching '${pat%% *}'"; fi
	done
else
	rec FAIL ufw.active "ufw is not active"
fi

# ---- H1: listeners -------------------------------------------------------------
ss_out="$(ss -H -ltnu 2>/dev/null || true)"
ufw_on=0
printf '%s' "$ufw_v" | grep -q '^Status: active' && ufw_on=1
wild='^(0\.0\.0\.0|\*|\[::\])$'
bad=""
while read -r proto _ _ _ laddr _; do
	[ -n "${laddr:-}" ] || continue
	addr="${laddr%:*}"
	port="${laddr##*:}"
	if [[ "$addr" =~ $wild ]]; then
		case "$proto/$port" in
			tcp/22 | tcp/80 | tcp/443 | udp/51820 | udp/"${WG_PORT:-51820}" | tcp/"${SSH_PORT:-22}") ;;
			tcp/57800 | tcp/9000)
				if [ "$ufw_on" = 1 ]; then rec WARN "listener.$proto/$port" "wildcard bind; contained only by ufw (overlay-only rule)"; else bad="$bad $proto/$port"; fi
				;;
			*) bad="$bad $proto/$port" ;;
		esac
	fi
done <<<"$ss_out"
[ -z "$bad" ] && rec PASS listeners.public "only ssh/http/https/wg are wildcard-bound" || rec FAIL listeners.public "unexpected wildcard listeners:$bad"
for p in 2379 2380 5432 8008 7800; do
	if printf '%s\n' "$ss_out" | awk '{print $5}' | grep -Eq "^(0\.0\.0\.0|\*|\[::\]):$p\$"; then
		rec FAIL "listener.$p" "port $p is wildcard-bound; it must stay on the overlay/loopback"
	fi
done
if [ "$phase" = "running" ]; then
	if printf '%s\n' "$ss_out" | awk '{print $5}' | grep -q '^127\.0\.0\.1:8080$' && ! printf '%s\n' "$ss_out" | awk '{print $5}' | grep -Eq "^(0\.0\.0\.0|\*|\[::\]):8080\$"; then
		rec PASS listener.8080 "loopback only"
	else
		rec FAIL listener.8080 "Keycloak HTTP is not loopback-only"
	fi
else
	rec SKIP listener.8080 "phase pre-keycloak: Keycloak is stopped"
fi

# ---- H1: drop-ins, upgrade policy ------------------------------------------------
for u in $ORDERED_UNITS; do
	f="$(hp "/etc/systemd/system/$u.service.d/10-after-wireguard.conf")"
	if [ -f "$f" ] && grep -q "^After=.*${WG_UNIT}" "$f"; then
		after="$(systemctl show "$u" -p After 2>/dev/null || true)"
		case "$after" in *"$WG_UNIT"*) rec PASS "dropin.$u" "" ;; *) rec FAIL "dropin.$u" "file present but systemd does not list $WG_UNIT in After= (daemon-reload?)" ;; esac
	else
		rec FAIL "dropin.$u" "10-after-wireguard.conf missing or without After=$WG_UNIT"
	fi
done
restart="$(systemctl show keepalived -p Restart 2>/dev/null || true)"
[ "$restart" = "Restart=on-failure" ] && rec PASS keepalived.restart "" || rec FAIL keepalived.restart "keepalived has '$restart', want Restart=on-failure"
systemctl is-active --quiet keepalived && rec PASS keepalived.active "" || rec FAIL keepalived.active "keepalived is not active"
check needrestart.conf "needrestart is not list-only" grep -q "^\\\$nrconf{restart} = 'l';" "$(hp /etc/needrestart/conf.d/90-dotmac-idpha.conf)"
tf="$(hp /etc/systemd/system/apt-daily-upgrade.timer.d/90-dotmac-idpha.conf)"
if [ -f "$tf" ] && grep -q "^OnCalendar=\*-\*-\* ${APT_UPGRADE_TIME} UTC\$" "$tf" && grep -q '^RandomizedDelaySec=0$' "$tf"; then rec PASS apt.timer "staggered at $APT_UPGRADE_TIME UTC"; else rec FAIL apt.timer "staggered apt-daily-upgrade drop-in missing or wrong"; fi

# ---- H1: ssh / fail2ban baseline ----------------------------------------------------
sshd_t="$(sshd -T 2>/dev/null || true)"
if [ -n "$sshd_t" ]; then
	printf '%s\n' "$sshd_t" | grep -qi '^passwordauthentication no$' && rec PASS sshd.password "" || rec FAIL sshd.password "password authentication is not off"
	printf '%s\n' "$sshd_t" | grep -qi '^kbdinteractiveauthentication no$' && rec PASS sshd.kbd "" || rec FAIL sshd.kbd "keyboard-interactive is not off"
	printf '%s\n' "$sshd_t" | grep -Eqi '^permitrootlogin (prohibit-password|without-password)$' && rec PASS sshd.root "" || rec FAIL sshd.root "root login is not key-only"
else
	rec SKIP sshd.effective "sshd -T not available (not root?)"
fi
[ -f "$(hp /etc/ssh/sshd_config.d/00-dotmac-hardening.conf)" ] && rec PASS sshd.dropin "" || rec FAIL sshd.dropin "00-dotmac-hardening.conf missing"
fail2ban-client status sshd >/dev/null 2>&1 && rec PASS fail2ban.sshd "" || rec FAIL fail2ban.sshd "sshd jail not active"

# ---- H1: certificates, provider credential -----------------------------------------
if [ -n "${CERT_FILES:-}" ]; then
	for pair in $CERT_FILES; do
		cn="${pair%%=*}"
		cp="${pair#*=}"
		if openssl x509 -checkend $((CERT_MIN_DAYS * 86400)) -noout -in "$cp" >/dev/null 2>&1; then rec PASS "cert.$cn" ">${CERT_MIN_DAYS} days left"; else rec FAIL "cert.$cn" "expires within ${CERT_MIN_DAYS} days or unreadable"; fi
	done
else
	rec SKIP cert "CERT_FILES not set"
fi
if [ -n "$PROVIDER_CRED_FILE" ] && [ -e "$(hp "$PROVIDER_CRED_FILE")" ]; then
	m="$(file_mode "$(hp "$PROVIDER_CRED_FILE")")"
	o="$(file_owner "$(hp "$PROVIDER_CRED_FILE")")"
	[ "$m" = "600" ] && [ "$o" = "0" ] && rec PASS provider_cred.perms "root 600" || rec FAIL provider_cred.perms "mode $m owner $o, want root 600"
else
	rec SKIP provider_cred.perms "no provider credential file on this node"
fi

# ---- overlay / cluster health (the HC set) ------------------------------------------
if hs="$(wg show "$WG_IF" latest-handshakes 2>/dev/null)"; then
	now="$(date +%s)"
	stale=0
	cnt=0
	while read -r _ ts; do
		[ -n "${ts:-}" ] || continue
		cnt=$((cnt + 1))
		[ "$ts" -gt 0 ] && [ $((now - ts)) -lt 150 ] || stale=$((stale + 1))
	done <<<"$hs"
	[ "$cnt" -ge 2 ] && [ "$stale" = 0 ] && rec PASS wg.handshakes "" || rec FAIL wg.handshakes "$stale of $cnt peers stale or fewer than 2 peers"
else
	rec SKIP wg.handshakes "wg not available"
fi
failed="$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | grep -v '^systemd-networkd-wait-online' || true)"
[ -z "$failed" ] && rec PASS systemd.failed "" || rec FAIL systemd.failed "failed units: $(printf '%s' "$failed" | tr '\n' ' ')"

# ---- H2: Keycloak runtime and nginx parity ---------------------------------------------
if [ -r "$(hp "$COMPOSE_DEST")" ]; then
	c="$(hp "$COMPOSE_DEST")"
	[ -n "$pin_ref" ] && grep -qF "image: $pin_ref" "$c" && rec PASS compose.image_pin "digest-pinned, equals ha/image.pin" || rec FAIL compose.image_pin "compose image is not the reviewed digest pin"
	grep -q 'KC_HTTP_HOST: "127.0.0.1"' "$c" && rec PASS compose.loopback "" || rec FAIL compose.loopback "KC_HTTP_HOST is not 127.0.0.1"
	grep -q 'KC_HOSTNAME_STRICT: "true"' "$c" && rec PASS compose.hostname_strict "" || rec FAIL compose.hostname_strict "KC_HOSTNAME_STRICT is not true"
	grep -qF "KC_HOSTNAME: \"https://${KC_HOSTNAME}\"" "$c" && rec PASS compose.hostname "" || rec FAIL compose.hostname "KC_HOSTNAME differs from the permanent issuer host"
	[ "$(file_mode "$c")" = "600" ] && rec PASS compose.perms "" || rec FAIL compose.perms "compose file is not mode 600"
else
	rec SKIP compose "compose file not readable"
fi
if [ -n "${CACHE_SHA256:-}" ] && [ -r "$(hp "$CACHE_FILE")" ]; then
	[ "$(sha_of <"$(hp "$CACHE_FILE")")" = "$CACHE_SHA256" ] && rec PASS cache.hash "" || rec FAIL cache.hash "cache-ispn.xml differs from the pinned hash"
else
	rec SKIP cache.hash "CACHE_SHA256 not set or file unreadable"
fi
if [ "$phase" = "running" ] && command -v docker >/dev/null 2>&1; then
	img="$(docker inspect keycloak --format '{{.Config.Image}}' 2>/dev/null || true)"
	[ -n "$pin_ref" ] && [ "$img" = "$pin_ref" ] && rec PASS runtime.image "" || rec FAIL runtime.image "running image '$img' is not the pin"
else
	rec SKIP runtime.image "phase pre-keycloak or docker unavailable"
fi
gf="$(hp "$GATE_DEST")"
if [ -f "$gf" ]; then
	if grep -q 'default 0;' "$gf"; then g=closed; elif grep -q 'default 1;' "$gf"; then g=open; else g=unknown; fi
	[ "$g" = "$gate" ] && rec PASS gate.state "gate is $g" || rec FAIL gate.state "gate is $g, this phase expects $gate"
else
	rec FAIL gate.state "gate file missing"
fi
if command -v curl >/dev/null 2>&1; then
	code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "${KC_HOSTNAME}:443:127.0.0.1" "https://${KC_HOSTNAME}/admin/" 2>/dev/null || true)"
	[ "$code" = "404" ] && rec PASS nginx.admin_404 "" || rec FAIL nginx.admin_404 "/admin/ answered $code, want 404"
	hdr="$(curl -skI --max-time 5 --resolve "${KC_HOSTNAME}:443:127.0.0.1" "https://${KC_HOSTNAME}/admin/" 2>/dev/null | tr 'A-Z' 'a-z' || true)"
	missing=""
	for h in strict-transport-security x-content-type-options referrer-policy x-frame-options; do
		printf '%s' "$hdr" | grep -q "^$h:" || missing="$missing $h"
	done
	[ -z "$missing" ] && rec PASS nginx.headers "" || rec FAIL nginx.headers "missing headers:$missing"
	# Closed-by-default: an unlisted name must get no certificate/answer.
	ucode="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "unlisted.invalid:443:127.0.0.1" "https://unlisted.invalid/" 2>/dev/null || true)"
	case "$ucode" in
		000*) rec PASS nginx.default_closed "unlisted name refused at the handshake" ;;
		*) rec FAIL nginx.default_closed "an unlisted name was answered ($ucode)" ;;
	esac
fi

# ---- output ------------------------------------------------------------------------------
doc="{\"node\":\"$(json_escape "$NODE_NAME")\",\"phase\":\"$phase\",\"gate\":\"$gate\",\"fails\":$fails,\"warns\":$warns,\"checks\":[$(paste -sd, "$results")]}"
printf '%s\n' "$doc"
if [ -n "$outfile" ]; then
	(
		umask 077
		printf '%s\n' "$doc" >"$outfile"
	)
fi
[ "$fails" = 0 ]
