#!/usr/bin/env bash
# ha-install.sh — render and install the H2 Keycloak/nginx layer on an IdP HA
# node, from the reviewed templates in ha/. Run as root ON the node, one node at
# a time. DRY-RUN unless APPLY=1 / --apply. Keycloak stays STOPPED: a compose
# change takes effect only at the next `docker compose up -d` (packet H5.0).
#
#   ha-install.sh compose            full replacement compose file (mode 600)
#   ha-install.sh nginx              http pieces + vhosts, `nginx -t`, reload
#   ha-install.sh gate closed|open   swap the vhost allowlist (open = H7 T0 ONLY)
#   ha-install.sh metrics-token      install the bearer map from the token file
#   ha-install.sh backup-tools       age from apt + the sha256-pinned S3 client (ha/tools.pin)
#   ha-install.sh scripts            copy the node-side scripts to $HA_DIR/bin
#   ha-install.sh units backup|collector|maint     install systemd units (timer NOT enabled)
#   ha-install.sh timer-enable backup|collector|maint   enable --now the timer (H3.5 / H4.1)
#   ha-install.sh rollback <stamp>   restore one run's backups, nginx -t, reload
#
# Parameters: the typed params document (--params FILE|-, ha/params.schema.json), sections
# `node` and `operations.ha-install`; --plan prints the effect + digest and --apply needs
# --expect-digest. Secrets are REFERENCES: the database
# password line is COPIED from the node's existing compose file, never read into
# output; the metrics bearer comes from a root-600 file (METRICS_TOKEN_FILE).
#
# Failure policy: any template token without a value, any post-render
# assertion that fails, or an `nginx -t` failure stops the run; an nginx failure
# restores this run's backups before exiting.

set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$LIB_DIR/.." && pwd)}"
# shellcheck source=bin/lib-idpha.sh
. "$LIB_DIR/lib-idpha.sh"

NGINX_HTTP_DEST="${NGINX_HTTP_DEST:-/etc/nginx/conf.d/00-idpha-http.conf}"
NGINX_VHOST_DEST="${NGINX_VHOST_DEST:-/etc/nginx/conf.d/10-idpha-vhosts.conf}"
GATE_DEST="${GATE_DEST:-/etc/nginx/snippets/idpha-gate.conf}"
TOKEN_CONF_DEST="${TOKEN_CONF_DEST:-/etc/nginx/snippets/idpha-metrics-token.conf}"

parse_common_flags "$@"
set -- ${REST_ARGS[@]+"${REST_ARGS[@]}"}
cmd="${1:-}"
shift || true
[ -n "$cmd" ] || die "usage: ha-install.sh compose|nginx|gate|metrics-token|rollback [--apply]"
if is_apply && [ "${IDPHA_ROOT:-}" = "" ] && [ "$(id -u)" != "0" ]; then die "APPLY needs root"; fi

idpha_begin ha-install
mode_banner
trap on_failure_restore EXIT
# Host layout, hostnames and secret-file REFERENCES come from the params document: no defaults.
require HA_DIR KC_HOSTNAME LINKS_HOSTNAME IDP_CERT_DIR LINKS_CERT_DIR
PARAMS_FILE="$HA_DIR/idpha-params.json"
COMPOSE_DEST="${COMPOSE_DEST:-$HA_DIR/compose.yml}"
BIN_DEST="${BIN_DEST:-$HA_DIR/bin}"
METRICS_TOKEN_FILE="${METRICS_TOKEN_FILE:-}"
export HA_DIR

export KC_HOSTNAME LINKS_HOSTNAME IDP_CERT_DIR LINKS_CERT_DIR

hostname_ok() { [[ "$1" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; }

cidr_lines() { # cidr_lines <template with %s> <cidr...>
	local fmt="$1" c
	shift
	for c in "$@"; do
		is_host_cidr "$c" || die "'$c' is not a single host (/32 or /128): ranges are refused"
		# shellcheck disable=SC2059 # fmt is one of our own constants
		printf "$fmt\n" "$c"
	done
}

nginx_reload() {
	if ! is_apply; then
		planline "nginx -t && systemctl reload nginx"
		return 0
	fi
	if nginx -t >/dev/null 2>&1; then
		systemctl reload nginx
		okline "nginx -t passed; reloaded"
	else
		nginx -t 2>&1 | sed 's/^/      /' >&2 || true
		note "nginx -t FAILED; restoring this run's files ($IDPHA_RUN_STAMP)"
		restore_run "$IDPHA_RUN_STAMP"
		nginx -t >/dev/null 2>&1 && note "previous configuration is valid again" || note "WARNING: previous configuration also fails nginx -t; stop and look"
		exit 1
	fi
}

do_compose() {
	require OVERLAY_ADDR
	is_ipv4 "$OVERLAY_ADDR" || die "OVERLAY_ADDR is not an IPv4 address"
	hostname_ok "$KC_HOSTNAME" || die "KC_HOSTNAME is not a plain hostname"
	local pin="$REPO_ROOT/ha/image.pin" line
	[ -r "$pin" ] || die "ha/image.pin missing"
	KC_IMAGE_REF="$(sed -n 's/^KC_IMAGE_REF=//p' "$pin")"
	[[ "$KC_IMAGE_REF" =~ ^[a-z0-9./-]+:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]] || die "ha/image.pin is not a version tag plus a sha256 digest"
	export KC_IMAGE_REF

	local existing
	existing="$(hostpath "$COMPOSE_DEST")"
	if [ -r "$existing" ]; then
		[ "$(grep -cE '^[[:space:]]*KC_DB_PASSWORD:' "$existing")" = "1" ] || die "existing compose must have exactly one KC_DB_PASSWORD line"
		line="$(grep -E '^[[:space:]]*KC_DB_PASSWORD:' "$existing" | sed 's/^[[:space:]]*//')"
		case "$line" in "KC_DB_PASSWORD: "?*) ;; *) die "existing KC_DB_PASSWORD line has no value" ;; esac
	elif is_apply; then
		die "$COMPOSE_DEST not readable: the database password line is carried over from it"
	else
		# shellcheck disable=SC2089 # the quotes are literal YAML on purpose
		line='KC_DB_PASSWORD: "<PLACEHOLDER>"'
	fi
	KC_DB_PASSWORD_LINE="$line"
	# shellcheck disable=SC2090
	export KC_DB_PASSWORD_LINE

	local tmp
	tmp="$(mktemp)"
	# shellcheck disable=SC2064
	trap "rm -f '$tmp'" EXIT
	render "$REPO_ROOT/ha/compose.yml.tmpl" >"$tmp"
	# Post-render assertions: the properties this packet exists to deliver.
	grep -q '@sha256:[0-9a-f]\{64\}' "$tmp" || die "rendered compose is not digest-pinned"
	grep -q 'KC_HTTP_HOST: "127.0.0.1"' "$tmp" || die "rendered compose does not bind Keycloak to loopback"
	grep -q 'KC_HOSTNAME_STRICT: "true"' "$tmp" || die "rendered compose lacks hostname strict"
	! grep -q '0\.0\.0\.0' "$tmp" || die "rendered compose contains a wildcard bind"
	if [ -r "$existing" ]; then
		note "-- diff vs installed (password lines excluded; image/env lines only)"
		# keys only: a changed line is reported by NAME, never by value
		diff <(grep -vE 'KC_DB_PASSWORD' "$existing") <(grep -vE 'KC_DB_PASSWORD' "$tmp") | grep '^[<>]' | sed -E 's/^([<>])[[:space:]]*([A-Za-z_.-]+).*/      \1 \2/' || true
	fi
	put_file "$COMPOSE_DEST" 600 <"$tmp"
	if is_apply; then
		docker compose -f "$existing" config --quiet >/dev/null 2>&1 || die "docker compose config rejected the new file (output suppressed: it would interpolate)"
		okline "compose file validates"
	else
		planline "docker compose -f $COMPOSE_DEST config --quiet   (output suppressed)"
	fi
	note "Keycloak is NOT restarted; the change applies at the next 'docker compose up -d' (H5.0)."
}

do_gate() {
	local mode="${1:-}"
	case "$mode" in
		closed) do_gate_noreload ;;
		open)
			[ "${IDPHA_CONFIRM_OPEN:-}" = "cutover-t0" ] || die "'gate open' publishes the IdP. It is the H7 T0 step only; set IDPHA_CONFIRM_OPEN=cutover-t0 to confirm"
			put_file "$GATE_DEST" 644 <"$REPO_ROOT/ha/nginx/gate-open.conf"
			;;
		*) die "gate needs 'closed' or 'open'" ;;
	esac
	nginx_reload
}

# read_bearer: validate the REFERENCED token file and leave the value in
# METRICS_BEARER (never printed). Used by the preflight and the writer.
read_bearer() {
	require METRICS_TOKEN_FILE
	[ -r "$METRICS_TOKEN_FILE" ] || die "metrics token file not readable (root 600; the operator places the bearer value there)"
	if [ "${IDPHA_ALLOW_UNSAFE_VALUES:-0}" != "1" ]; then
		[ "$(file_mode "$METRICS_TOKEN_FILE")" = "600" ] || die "metrics token file must be mode 600"
	fi
	METRICS_BEARER="$(tr -d '\n\r' <"$METRICS_TOKEN_FILE")"
	[[ "$METRICS_BEARER" =~ ^[A-Za-z0-9._~+-]{32,}$ ]] || die "metrics bearer must be at least 32 characters of [A-Za-z0-9._~+-]"
	export METRICS_BEARER
}

do_metrics_token() {
	read_bearer
	render "$REPO_ROOT/ha/nginx/metrics-token.conf.tmpl" | put_file "$TOKEN_CONF_DEST" 600
	unset METRICS_BEARER
}

# nginx_preflight: validate and compute EVERY input before the first write (M-7).
nginx_preflight() {
	require PEER_OVERLAY_1 PEER_OVERLAY_2 GATE_ALLOW METRICS_ALLOW LINKS_ROOT
	is_ipv4 "$PEER_OVERLAY_1" && is_ipv4 "$PEER_OVERLAY_2" || die "peer overlay values are not IPv4 addresses"
	hostname_ok "$KC_HOSTNAME" && hostname_ok "$LINKS_HOSTNAME" || die "hostnames must be plain DNS names"
	[[ "$LINKS_ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "LINKS_ROOT must be an absolute plain path"
	# shellcheck disable=SC2086
	METRICS_ALLOW_LINES="$(cidr_lines '        allow %s;' $METRICS_ALLOW)" || exit 1
	# shellcheck disable=SC2086
	GATE_ALLOW_LINES="$(cidr_lines '    %s 1;' $GATE_ALLOW ${GATE_EXTRA_ALLOW:-} 127.0.0.1/32)" || exit 1
	read_bearer
	unset METRICS_BEARER
	export METRICS_ALLOW_LINES GATE_ALLOW_LINES PEER_OVERLAY_1 PEER_OVERLAY_2 LINKS_ROOT
}

do_nginx() {
	nginx_preflight
	render "$REPO_ROOT/ha/nginx/00-idpha-http.conf.tmpl" | put_file "$NGINX_HTTP_DEST" 644
	# The gate and the token map must exist before nginx can load the http pieces.
	# Never silently open: a missing gate file is created CLOSED.
	[ -e "$(hostpath "$GATE_DEST")" ] || do_gate_noreload
	[ -e "$(hostpath "$TOKEN_CONF_DEST")" ] || do_metrics_token
	render "$REPO_ROOT/ha/nginx/idpha-vhosts.conf.tmpl" | put_file "$NGINX_VHOST_DEST" 644
	# The old enabled vhosts for the same names must go in THIS run, or the
	# ungated one comes back the day conf.d is removed (M-2).
	local lv
	for lv in ${LEGACY_VHOST_FILES:-}; do remove_file "$lv"; done
	nginx_reload
}

do_gate_noreload() {
	require GATE_ALLOW
	# Observe sources, any explicit operator widening, and loopback (ssh tunnel).
	# shellcheck disable=SC2086
	GATE_ALLOW_LINES="$(cidr_lines '    %s 1;' $GATE_ALLOW ${GATE_EXTRA_ALLOW:-} 127.0.0.1/32)" || exit 1
	export GATE_ALLOW_LINES
	render "$REPO_ROOT/ha/nginx/gate-closed.conf.tmpl" | put_file "$GATE_DEST" 644
}

NODE_SCRIPTS="idpha-params.py lib-idpha.sh ha-backup.sh idpha-collect.sh host-check.sh verify-ha.sh verify.sh policy-eval.sh idpha-rolling-maint.sh patroni-sync.sh"

do_scripts() {
	local f
	for f in $NODE_SCRIPTS; do
		put_file "$BIN_DEST/$f" 750 <"$REPO_ROOT/bin/$f"
	done
	# verify.sh grades with the policy files; ship them next to the scripts.
	for f in "$REPO_ROOT"/policy/*.jq; do put_file "$(dirname "$BIN_DEST")/policy/$(basename "$f")" 640 <"$f"; done
	for f in "$REPO_ROOT"/realm/*.json "$REPO_ROOT"/realm/clients/*.json; do
		put_file "$(dirname "$BIN_DEST")${f#"$REPO_ROOT"}" 640 <"$f"
	done
	put_file "$(dirname "$BIN_DEST")/ha/image.pin" 640 <"$REPO_ROOT/ha/image.pin"
	put_file "$(dirname "$BIN_DEST")/ha/params.schema.json" 640 <"$REPO_ROOT/ha/params.schema.json"
	# The timers need the params on the host: a copy of the validated document
	# (it holds topology, no secret; credentials are references inside it).
	put_file "$PARAMS_FILE" 600 <"$IDPHA_PARAMS"
}

unit_names() {
	case "$1" in
		backup) echo "keycloak-ha-backup" ;;
		collector) echo "idpha-collect" ;;
		maint) echo "idpha-maint" ;;
		*) die "units/timer-enable take 'backup', 'collector' or 'maint'" ;;
	esac
}

# backup-tools: age from the distribution, the S3 client from the PINNED
# artefact only (ha/tools.pin). Refuses while the pin is empty or on any hash mismatch.
do_backup_tools() {
	local pin="${TOOLS_PIN:-$REPO_ROOT/ha/tools.pin}" url sum tmp
	url="$(sed -n 's/^MC_URL=//p' "$pin")"
	sum="$(sed -n 's/^MC_SHA256=//p' "$pin")"
	[ -n "$url" ] && [ -n "$sum" ] || die "ha/tools.pin has no pinned S3 client (MC_URL / MC_SHA256 empty): an unpinned download is never acceptable"
	[[ "$url" =~ ^https://[A-Za-z0-9./_-]+$ ]] || die "MC_URL must be a plain https URL"
	[[ "$sum" =~ ^[0-9a-f]{64}$ ]] || die "MC_SHA256 must be 64 lowercase hex characters"
	run apt-get install -y age
	if is_apply; then
		tmp="$(mktemp)"
		curl -fsSL --proto '=https' --max-time 120 -o "$tmp" "$url" || die "download of the pinned S3 client failed"
		[ "$(sha_of <"$tmp")" = "$sum" ] || {
			rm -f "$tmp"
			die "downloaded S3 client does not match the pinned sha256: NOT installed"
		}
		put_file /usr/local/bin/mc 755 <"$tmp"
		rm -f "$tmp"
	else
		planline "download the pinned S3 client (sha256 ${sum:0:12}...) and install it to /usr/local/bin/mc"
		effect "$(_tab download "$url sha256:$sum")"
	fi
}

do_units() {
	local n
	n="$(unit_names "${1:-}")"
	if [ "$1" = backup ]; then require BACKUP_ENV_FILE; else BACKUP_ENV_FILE="${BACKUP_ENV_FILE:-/nonexistent}"; fi
	if [ "$1" = maint ]; then
		require MAINT_ON_CALENDAR
	else
		MAINT_ON_CALENDAR="${MAINT_ON_CALENDAR:-unused}"
	fi
	export BACKUP_ENV_FILE PARAMS_FILE MAINT_ON_CALENDAR
	render "$REPO_ROOT/ha/systemd/$n.service" | put_file "/etc/systemd/system/$n.service" 644
	render "$REPO_ROOT/ha/systemd/$n.timer" | put_file "/etc/systemd/system/$n.timer" 644
	run systemctl daemon-reload
	note "timer installed but NOT enabled; enable with: ha-install.sh timer-enable ${1}"
}

do_timer_enable() {
	local n
	n="$(unit_names "${1:-}")"
	if [ "${1:-}" = backup ] && is_apply; then
		require BACKUP_ENV_FILE
		[ -r "$BACKUP_ENV_FILE" ] || die "the backup identity file is missing: not installed yet (H3.2)"
	fi
	run systemctl enable --now "$n.timer"
}

case "$cmd" in
	backup-tools) do_backup_tools ;;
	scripts) do_scripts ;;
	units) do_units "${1:-}" ;;
	timer-enable) do_timer_enable "${1:-}" ;;
	compose) do_compose ;;
	nginx) do_nginx ;;
	gate) do_gate "${1:-}" ;;
	metrics-token)
		do_metrics_token
		nginx_reload
		;;
	rollback)
		restore_run "${1:-}"
		nginx_reload
		;;
	*) die "unknown command '$cmd'" ;;
esac
idpha_end
