#!/usr/bin/env bash
# t-collect-hostcheck.sh — bin/idpha-collect.sh and bin/host-check.sh.
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=bin/lib-idpha.sh
. "$REPO_ROOT/bin/lib-idpha.sh"

section "collector"
CSTUB="$T/cstub"
mkdir -p "$CSTUB"
cat >"$CSTUB/curl" <<'STUBEOF'
#!/usr/bin/env bash
case "$*" in
	*"/cluster"*) printf '{"members":[{"name":"node-1","role":"leader","state":"running","timeline":7},{"name":"node-2","role":"sync_standby","state":"streaming","timeline":7,"lag":0}]}' ;;
	*"/health/ready"*) [ "${STUB_KC:-1}" = 1 ] && exit 0 || exit 22 ;;
esac
exit 0
STUBEOF
cat >"$CSTUB/ip" <<'STUBEOF'
#!/usr/bin/env bash
echo "2: eth0    inet 203.0.113.10/32 scope global eth0"
STUBEOF
cat >"$CSTUB/wg" <<'STUBEOF'
#!/usr/bin/env bash
printf 'KEYA\t%s\nKEYB\t%s\n' "$(( $(date +%s) - 30 ))" "$(( $(date +%s) - 70 ))"
STUBEOF
printf '#!/usr/bin/env bash\necho "Status: active"\n' >"$CSTUB/ufw"
printf '#!/usr/bin/env bash\nprintf "NEEDRESTART-VER: 3.6\\nNEEDRESTART-SVC: nginx.service\\nNEEDRESTART-SVC: patroni.service\\n"\n' >"$CSTUB/needrestart"
printf '#!/usr/bin/env bash\nexit 0\n' >"$CSTUB/systemctl"
chmod +x "$CSTUB"/*
newroot
CV="$T/cvalues.env"
mkvalues "$CV" '.node.cert_files=[{"name":"idp","path":"/nonexistent/x.pem"}]'
C="$REPO_ROOT/bin/idpha-collect.sh"
mkvalues "$T/cvp.json" ".operations.collector.idpha_prom_file=\"$R/prom/idpha.prom\""
CVP="$T/cvp.json"
PATH="$CSTUB:$PATH" IDPHA_STATE_DIR="$R/state" IDPHA_PARAMS="$CV" runit "$C"
expect "collector prints and exits 0" 0 "$RC"
has "leader detected" "$OUT" 'idpha_patroni_is_leader{node="node-1"} 1'
has "timeline read" "$OUT" 'idpha_patroni_timeline{node="node-1"} 7'
has "etcd healthy members" "$OUT" 'idpha_etcd_members_healthy{node="node-1"} 3'
has "etcd has one leader" "$OUT" 'idpha_etcd_has_leader{node="node-1"} 1'
has "keepalived active" "$OUT" 'idpha_keepalived_active{node="node-1"} 1'
has "VIP present" "$OUT" 'idpha_vip_present{node="node-1"} 1'
has "keycloak ready" "$OUT" 'idpha_keycloak_ready{node="node-1"} 1'
has "ufw active" "$OUT" 'idpha_ufw_active{node="node-1"} 1'
has "needrestart pending counted" "$OUT" 'idpha_needrestart_pending{node="node-1"} 2'
has "wg handshake age per peer" "$OUT" 'idpha_wg_handshake_age_seconds{node="node-1",peer="1"} '
has "collector reports which checks it could take" "$OUT" 'idpha_collect_check_ok{check="patroni"} 1'
hasnt "no cluster-size sample without a confirmed metric name" "$OUT" 'idpha_keycloak_cluster_size{'
PATH="$CSTUB:$PATH" STUB_KC=0 IDPHA_STATE_DIR="$R/state2" IDPHA_PARAMS="$CV" runit "$C"
has "keycloak down is reported as 0" "$OUT" 'idpha_keycloak_ready{node="node-1"} 0'
PATH="$CSTUB:$PATH" IDPHA_STATE_DIR="$R/state3" IDPHA_PARAMS="$CVP" runit "$C"
if [ ! -e "$R/prom/idpha.prom" ]; then ok "dry-run writes no textfile"; else bad "dry-run wrote the textfile"; fi
PATH="$CSTUB:$PATH" IDPHA_STATE_DIR="$R/state3" IDPHA_PARAMS="$CVP" runit "$C" --apply
if [ -s "$R/prom/idpha.prom" ] && [ ! -e "$R/prom/idpha.prom.tmp" ]; then ok "apply writes the textfile atomically"; else bad "textfile missing or tmp left"; fi
ETCD_MODE=missing PATH="$CSTUB:$PATH" IDPHA_STATE_DIR="$R/state4" IDPHA_PARAMS="$CV" runit "$C"
has "a missing etcdctl is 'could not look' (check_ok 0)" "$OUT" 'idpha_collect_check_ok{check="etcd"} 0'
hasnt "...and not a false 'unhealthy' sample" "$OUT" 'idpha_etcd_members_healthy{'

section "host-check"
HSTUB="$T/hstub"
mkdir -p "$HSTUB"
cat >"$HSTUB/ufw" <<'STUBEOF'
#!/usr/bin/env bash
if [ "${HC_UFW:-on}" = off ]; then echo "Status: inactive"; exit 0; fi
cat <<'X'
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere                   # ssh
80/tcp                     ALLOW IN    Anywhere                   # acme+redirect
443/tcp                    ALLOW IN    Anywhere                   # https
51820/udp                  ALLOW IN    198.51.100.2               # wg
51820/udp                  ALLOW IN    198.51.100.3               # wg
Anywhere on wg0            ALLOW IN    Anywhere                   # overlay
22/tcp (v6)                ALLOW IN    Anywhere (v6)              # ssh
80/tcp (v6)                ALLOW IN    Anywhere (v6)              # acme
443/tcp (v6)               ALLOW IN    Anywhere (v6)              # https
Anywhere (v6) on wg0       ALLOW IN    Anywhere (v6)              # overlay
X
STUBEOF
cat >"$HSTUB/ss" <<'STUBEOF'
#!/usr/bin/env bash
printf 'tcp LISTEN 0 511 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\ntcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nudp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\ntcp LISTEN 0 5 192.0.2.1:2379 0.0.0.0:*\ntcp LISTEN 0 5 *:57800 *:*\n'
if [ "${HC_8080:-lo}" = wild ]; then printf 'tcp LISTEN 0 5 *:8080 *:*\n'; else printf 'tcp LISTEN 0 5 127.0.0.1:8080 0.0.0.0:*\ntcp LISTEN 0 5 127.0.0.1:9000 0.0.0.0:*\n'; fi
STUBEOF
cat >"$HSTUB/systemctl" <<'STUBEOF'
#!/usr/bin/env bash
case "$*" in
	*"-p Restart"*) echo "Restart=on-failure" ;;
	*"-p After"*) echo "After=wg-quick@wg0.service network-online.target" ;;
esac
exit 0
STUBEOF
printf '#!/usr/bin/env bash\nprintf "passwordauthentication no\\nkbdinteractiveauthentication no\\npermitrootlogin prohibit-password\\n"\n' >"$HSTUB/sshd"
printf '#!/usr/bin/env bash\nexit 0\n' >"$HSTUB/fail2ban-client"
cat >"$HSTUB/nginx" <<'STUBEOF'
#!/usr/bin/env bash
if [ "$1" = "-T" ]; then
	printf '    server_name idp.example.test links.example.test;\n    server_name idp.example.test;\n    server_name links.example.test;\n'
fi
exit 0
STUBEOF
printf '#!/usr/bin/env bash\nexit 0\n' >"$HSTUB/openssl"
printf '#!/usr/bin/env bash\necho "%s"\n' "$(sed -n 's/^KC_IMAGE_REF=//p' "$REPO_ROOT/ha/image.pin")" >"$HSTUB/docker"
cp "$CSTUB/wg" "$HSTUB/wg"
cat >"$HSTUB/curl" <<'STUBEOF'
#!/usr/bin/env bash
case "$*" in
	*"unlisted.invalid"*) printf '000'; exit 35 ;;
	*-skI*) printf 'HTTP/2 404\r\nStrict-Transport-Security: x\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\n' ;;
	*) printf '404' ;;
esac
STUBEOF
chmod +x "$HSTUB"/*
newroot
for u in keepalived patroni docker etcd; do
	mkdir -p "$R/etc/systemd/system/$u.service.d"
	printf '[Unit]\nAfter=wg-quick@wg0.service network-online.target\nWants=wg-quick@wg0.service\n' >"$R/etc/systemd/system/$u.service.d/10-after-wireguard.conf"
done
mkdir -p "$R/etc/needrestart/conf.d" "$R/etc/systemd/system/apt-daily-upgrade.timer.d" "$R/etc/ssh/sshd_config.d" "$R/etc/nginx/snippets" "$R/srv/example/ha"
printf "\$nrconf{restart} = 'l';\n" >"$R/etc/needrestart/conf.d/90-dotmac-idpha.conf"
printf '[Timer]\nOnCalendar=\nOnCalendar=*-*-* 01:15:00 UTC\nRandomizedDelaySec=0\n' >"$R/etc/systemd/system/apt-daily-upgrade.timer.d/90-dotmac-idpha.conf"
: >"$R/etc/ssh/sshd_config.d/00-dotmac-hardening.conf"
printf 'geo $idp_gate {\n    default 0;\n}\n' >"$R/etc/nginx/snippets/idpha-gate.conf"
pin="$(sed -n 's/^KC_IMAGE_REF=//p' "$REPO_ROOT/ha/image.pin")"
printf 'services:\n  keycloak:\n    image: %s\n    environment:\n      KC_HOSTNAME: "https://idp.example.test"\n      KC_HOSTNAME_STRICT: "true"\n      KC_HTTP_HOST: "127.0.0.1"\n' "$pin" >"$R/srv/example/ha/compose.yml"
chmod 600 "$R/srv/example/ha/compose.yml"
HC="$REPO_ROOT/bin/host-check.sh"
PATH="$HSTUB:$PATH" IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase running --gate closed
expect "a conforming node passes" 0 "$RC"; [ "$RC" = 0 ] || grep -o "{[^}]*FAIL[^}]*}" "$OUT"
has "JSON reports zero fails" "$OUT" '"fails":0'
has "port 57800 is reported as contained by ufw, not passed silently" "$OUT" 'contained only by ufw'
PATH="$HSTUB:$PATH" HC_UFW=off IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase running --gate closed
expect "fails when ufw is inactive" 1 "$RC"
has "...and names the check" "$OUT" '"name":"ufw.active","status":"FAIL"'
PATH="$HSTUB:$PATH" HC_8080=wild IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase running --gate closed
expect "fails when Keycloak HTTP is wildcard-bound" 1 "$RC"
PATH="$HSTUB:$PATH" IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase running --gate open
expect "fails when the gate is not in the state the phase expects" 1 "$RC"
PATH="$HSTUB:$PATH" HC_8080=wild IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase pre-keycloak --gate closed
has "pre-keycloak phase SKIPs (not passes) the 8080 check" "$OUT" '"name":"listener.8080","status":"SKIP"'
PATH="$HSTUB:$PATH" IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase nonsense
expect "an unknown phase is refused" 1 "$RC"
sed 's/KC_HTTP_HOST: "127.0.0.1"/KC_HTTP_HOST: "0.0.0.0"/' "$R/srv/example/ha/compose.yml" >"$R/c.new"
mv "$R/c.new" "$R/srv/example/ha/compose.yml"
chmod 600 "$R/srv/example/ha/compose.yml"
PATH="$HSTUB:$PATH" IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase running --gate closed
expect "fails a compose file that is not loopback-only" 1 "$RC"
rm -f "$R/etc/systemd/system/keepalived.service.d/10-after-wireguard.conf"
PATH="$HSTUB:$PATH" IDPHA_PARAMS="$V" IDPHA_ROOT="$R" runit "$HC" --phase running --gate closed
has "a missing boot-ordering drop-in is a FAIL" "$OUT" '"name":"dropin.keepalived","status":"FAIL"'

finish "t-collect-hostcheck"
