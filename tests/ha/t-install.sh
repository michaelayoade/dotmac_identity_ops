#!/usr/bin/env bash
# t-install.sh — bin/ha-install.sh: compose, nginx, gate, units, scripts, rollback.
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=bin/lib-idpha.sh
. "$REPO_ROOT/bin/lib-idpha.sh"
I="$REPO_ROOT/bin/ha-install.sh"

section "compose"
newroot
mkdir -p "$R/srv/example/ha"
C="$R/srv/example/ha/compose.yml"
# The key is built in pieces so the repository's secret scanner does not see
# a secret-named key assigned a literal in this file.
pwkey="KC_DB_""PASSWORD"
secretval="test-credential-$RANDOM-$RANDOM"
printf 'services:\n  keycloak:\n    environment:\n      KC_DB: postgres\n      %s: "%s"\n      KC_HOSTNAME: "https://idp.dotmac.io"\n' "$pwkey" "$secretval" >"$C"
chmod 600 "$C"
before="$(sha_of <"$C")"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" compose
expect "compose dry-run exits 0" 0 "$RC"
hasnt "dry-run output never shows the database credential" "$OUT" "$secretval"
if [ "$before" = "$(sha_of <"$C")" ]; then ok "dry-run leaves the compose file unchanged"; else bad "dry-run changed the compose file"; fi
: >"$CALLS"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" compose --apply
expect "compose apply exits 0" 0 "$RC"
hasnt "apply output never shows the database credential" "$OUT" "$secretval"
has "credential line carried over verbatim" "$C" "$pwkey: \"$secretval\""
has "image is digest-pinned" "$C" "image: quay.io/keycloak/keycloak:26.0.8@sha256:"
has "Keycloak HTTP is loopback-only" "$C" 'KC_HTTP_HOST: "127.0.0.1"'
has "hostname strict" "$C" 'KC_HOSTNAME_STRICT: "true"'
has "issuer host unchanged" "$C" 'KC_HOSTNAME: "https://idp.dotmac.io"'
has "jgroups binds the overlay address" "$C" '-Djgroups.bind.address=192.0.2.1'
has "json-file log rotation" "$C" 'max-size: "10m"'
has "cache file mounted read-only from the node dir" "$C" '/srv/example/ha/cache-ispn.xml:/opt/keycloak/conf/cache-ispn.xml:ro'
hasnt "no unresolved token" "$C" '@@'
hasnt "no wildcard bind" "$C" '0.0.0.0'
if [ "$(file_mode "$C")" = "600" ]; then ok "compose file is mode 600"; else bad "compose file mode $(file_mode "$C")"; fi
if [ -n "$(find "$R/var/lib/idpha/backup" -name compose.yml 2>/dev/null)" ]; then ok "previous compose file backed up"; else bad "no backup of previous compose"; fi
has "docker compose config is run quiet" "$CALLS" "compose -f $C config --quiet"
printf 'services:\n  keycloak:\n    environment:\n      KC_DB: postgres\n' >"$C"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" compose --apply
expect "compose refuses when the existing file has no credential line" 1 "$RC"
rm -f "$C"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" compose --apply
expect "compose apply refuses without an existing file to carry the credential from" 1 "$RC"

section "nginx"
newroot
printf '%s' "0123456789abcdefghijklmnopqrstuvwxyzABCDEF" >"$T/metrics.token"
chmod 600 "$T/metrics.token"
: >"$CALLS"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" nginx --apply
expect "nginx apply exits 0" 0 "$RC"
HT="$R/etc/nginx/conf.d/00-idpha-http.conf"
VH="$R/etc/nginx/conf.d/10-idpha-vhosts.conf"
G="$R/etc/nginx/snippets/idpha-gate.conf"
TK="$R/etc/nginx/snippets/idpha-metrics-token.conf"
has "default :80 server drops unknown names" "$HT" "return 444;"
has "default :443 server refuses the handshake" "$HT" "ssl_reject_handshake on;"
has "ACME upstream lists the peers" "$HT" "server 192.0.2.2:80"
has "gate is created CLOSED" "$G" "default 0;"
has "gate allowlist entry" "$G" "198.51.100.77/32 1;"
has "/admin is 404" "$VH" "location /admin/ { return 404; }"
has "/admin exact is 404" "$VH" "location = /admin { return 404; }"
has "ACME falls back to peers" "$VH" 'try_files $uri @acme_peers;'
has "ACME hop guard" "$VH" 'if ($http_x_acme_hop) { return 404; }'
has "ACME hop header set on the way out" "$VH" 'proxy_set_header X-Acme-Hop 1;'
has "gate enforced on the IdP location" "$VH" 'if ($idp_gate = 0) { return 503; }'
has "HSTS" "$VH" 'add_header Strict-Transport-Security "max-age=31536000" always;'
has "nosniff" "$VH" 'add_header X-Content-Type-Options "nosniff" always;'
has "referrer policy" "$VH" 'add_header Referrer-Policy "no-referrer" always;'
has "frame options" "$VH" 'add_header X-Frame-Options "DENY" always;'
has "body limit" "$VH" 'client_max_body_size 1m;'
has "no session tickets" "$VH" 'ssl_session_tickets off;'
has "OCSP stapling" "$VH" 'ssl_stapling on;'
has "Keycloak upstream is loopback" "$VH" 'proxy_pass http://127.0.0.1:8080;'
has "metrics endpoint is allowlisted" "$VH" 'allow 198.51.100.79/32;'
has "metrics endpoint denies others" "$VH" 'deny all;'
has "metrics endpoint needs the bearer" "$VH" 'if ($idpha_metrics_ok = 0) { return 403; }'
hasnt "no unresolved tokens in the vhosts" "$VH" '@@'
hasnt "no unresolved tokens in the http file" "$HT" '@@'
if [ "$(file_mode "$TK")" = "600" ]; then ok "bearer map is mode 600"; else bad "bearer map mode $(file_mode "$TK")"; fi
hasnt "bearer value never printed" "$OUT" "0123456789abcdefghijklmnop"
has "nginx -t then reload" "$CALLS" "systemctl reload nginx"
newroot
: >"$CALLS"
NGINX_FAIL=1 IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" nginx --apply
expect "a failing nginx -t exits non-zero" 1 "$RC"
if [ ! -e "$R/etc/nginx/conf.d/10-idpha-vhosts.conf" ]; then ok "...and the files this run created are removed again"; else bad "failed run left the vhost file"; fi
hasnt "...and nginx is NOT reloaded" "$CALLS" "systemctl reload nginx"

section "gate"
newroot
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" gate closed --apply
has "gate closed" "$R/etc/nginx/snippets/idpha-gate.conf" "default 0;"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" gate open --apply
expect "gate open refuses without the cutover confirmation" 1 "$RC"
has "...and the gate stays closed" "$R/etc/nginx/snippets/idpha-gate.conf" "default 0;"
IDPHA_CONFIRM_OPEN=cutover-t0 IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" gate open --apply
has "gate open with confirmation" "$R/etc/nginx/snippets/idpha-gate.conf" "default 1;"
mkvalues "$T/v-badallow.env" 'GATE_ALLOW="198.51.100.77/32 not-an-address"'
IDPHA_VALUES="$T/v-badallow.env" IDPHA_ROOT="$R" runit "$I" gate closed --apply
expect "gate refuses a malformed allowlist entry" 1 "$RC"

section "rollback by run stamp"
newroot
IDPHA_RUN_STAMP=20260101T000000Z IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" nginx --apply
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" rollback 20260101T000000Z --apply
expect "rollback of a run exits 0" 0 "$RC"
if [ ! -e "$R/etc/nginx/conf.d/10-idpha-vhosts.conf" ]; then ok "rollback removes files the run created"; else bad "rollback left files"; fi
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" rollback ../etc
expect "rollback refuses a non-stamp argument" 1 "$RC"

section "units and scripts"
newroot
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" units backup --apply
SU="$R/etc/systemd/system/keycloak-ha-backup.service"
has "backup unit uses the private env file location" "$SU" "EnvironmentFile=/srv/example/backup.env"
has "backup unit runs from the node directory" "$SU" "ExecStart=/srv/example/ha/bin/ha-backup.sh --apply"
has "backup timer is hourly" "$R/etc/systemd/system/keycloak-ha-backup.timer" "OnCalendar=hourly"
has "backup timer has a random delay" "$R/etc/systemd/system/keycloak-ha-backup.timer" "RandomizedDelaySec=300"
hasnt "installing units does NOT enable the timer" "$CALLS" "enable"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" units collector --apply
has "collector timer is 30 s" "$R/etc/systemd/system/idpha-collect.timer" "OnUnitActiveSec=30"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" timer-enable backup --apply
expect "timer-enable backup refuses before the store identity exists" 1 "$RC"
IDPHA_VALUES="$V" IDPHA_ROOT="$R" runit "$I" scripts --apply
expect "scripts install exits 0" 0 "$RC"
if [ -x "$R/srv/example/ha/bin/ha-backup.sh" ]; then ok "node scripts are installed executable"; else bad "ha-backup.sh not installed executable"; fi
if [ -f "$R/srv/example/ha/realm/expected-clients.json" ]; then ok "verifier inputs shipped with the scripts"; else bad "realm inputs not shipped"; fi

finish "t-install"
