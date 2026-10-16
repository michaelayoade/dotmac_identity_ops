#!/usr/bin/env bash
# t-static.sh — static properties of the committed HA artefacts: alert rules are
# well-formed and only reference metrics the collector emits; reviewed files say
# what the plan decided; and NOTHING environment-specific leaked into the tree.
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

section "alert rules"
RULES="$REPO_ROOT/ha/prometheus/idpha-alerts.rules.yml"
n_alert="$(grep -c '^      - alert:' "$RULES")"
n_expr="$(grep -c '^        expr:' "$RULES")"
n_sev="$(grep -c 'severity: ' "$RULES")"
n_sum="$(grep -c 'summary:' "$RULES")"
if [ "$n_alert" -gt 0 ] && [ "$n_alert" = "$n_expr" ] && [ "$n_alert" = "$n_sev" ] && [ "$n_alert" = "$n_sum" ]; then ok "every alert has expr, severity and summary ($n_alert alerts)"; else bad "alert structure: alerts=$n_alert expr=$n_expr sev=$n_sev summary=$n_sum"; fi
dups="$(grep '^      - alert:' "$RULES" | sort | uniq -d)"
if [ -z "$dups" ]; then ok "alert names are unique"; else bad "duplicate alerts: $dups"; fi
missing=""
for m in $(grep -o 'idpha_[a-z_]*' "$RULES" | sort -u); do
	grep -q "$m" "$REPO_ROOT/bin/idpha-collect.sh" || missing="$missing $m"
done
if [ -z "$missing" ]; then ok "every metric an alert uses is produced by the collector"; else bad "alerts reference metrics the collector does not emit:$missing"; fi
if python3 -c 'import yaml' 2>/dev/null; then
	if python3 -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); assert all("expr" in r for g in d["groups"] for r in g["rules"])' "$RULES"; then ok "rules file parses as YAML"; else bad "rules file is not valid YAML"; fi
	if python3 -c 'import sys,yaml; yaml.safe_load(__import__("re").sub("@@[A-Z_]+@@","x",open(sys.argv[1]).read().replace("@@HA_NODE_TARGETS@@","        - x")))' "$REPO_ROOT/ha/prometheus/scrape.yml.tmpl" 2>/dev/null; then ok "scrape template parses once tokens are filled"; else bad "scrape template does not parse"; fi
else
	echo "skip  YAML parse (PyYAML not installed); the structural checks above still ran"
fi

section "reviewed files"
has "DCS patch: sync on" "$REPO_ROOT/ha/patroni/dcs-sync.yml" "synchronous_mode: true"
has "DCS patch: not strict" "$REPO_ROOT/ha/patroni/dcs-sync.yml" "synchronous_mode_strict: false"
has "DCS patch: one sync standby" "$REPO_ROOT/ha/patroni/dcs-sync.yml" "synchronous_node_count: 1"
if grep -qE '^KC_IMAGE_REF=.*:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$' "$REPO_ROOT/ha/image.pin"; then ok "image.pin is version tag plus digest"; else bad "image.pin shape"; fi
for f in "$REPO_ROOT"/bin/*.sh; do
	case "$(basename "$f")" in harden-node.sh | check-*.sh | policy-eval.sh | apply-clients.sh | deploy.sh | rollback.sh | verify.sh) continue ;; esac
	if head -1 "$f" | grep -q '^#!/usr/bin/env bash$' && grep -q '^set -euo pipefail' "$f" || [ "$(basename "$f")" = lib-idpha.sh ]; then ok "$(basename "$f") fails closed (set -euo pipefail)"; else bad "$(basename "$f") lacks set -euo pipefail"; fi
done

section "no environment-specific content in the HA artefacts"
# Files this change set owns. IPv4 literals other than loopback / wildcard /
# RFC 5737 documentation ranges are topology; refuse them.
SCAN=$(ls "$REPO_ROOT"/bin/lib-idpha.sh "$REPO_ROOT"/bin/harden-ha.sh "$REPO_ROOT"/bin/ha-*.sh "$REPO_ROOT"/bin/host-check.sh "$REPO_ROOT"/bin/idpha-*.sh "$REPO_ROOT"/bin/patroni-sync.sh "$REPO_ROOT"/bin/verify-ha.sh 2>/dev/null)
SCAN="$SCAN
$(find "$REPO_ROOT/ha" "$REPO_ROOT/tests/ha" "$REPO_ROOT/docs/HA.md" -type f 2>/dev/null)"
leak=""
while IFS= read -r f; do
	[ -n "$f" ] || continue
	hits="$(grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$f" | grep -vE '(^|[^0-9.])(127\.0\.0\.1|0\.0\.0\.0|192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+)([^0-9]|$)' || true)"
	# a line may mix allowed and disallowed; re-check each literal
	while IFS= read -r lit; do
		[ -n "$lit" ] || continue
		case "$lit" in 127.0.0.1 | 0.0.0.0 | 192.0.2.* | 198.51.100.* | 203.0.113.*) ;; *) leak="$leak $f:$lit" ;; esac
	done < <(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$f" | sort -u)
	: "$hits"
done <<<"$SCAN"
v6="$(grep -noE '([0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F]{0,4}|::[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})+' $SCAN 2>/dev/null | grep -viE '2001:db8' || true)"
if [ -z "$v6" ]; then ok "no IPv6 literal outside the documentation range"; else bad "IPv6 literals found: $v6"; fi
if [ -z "$leak" ]; then ok "no IPv4 literal outside loopback and RFC 5737 ranges"; else bad "IPv4 literals found:$leak"; fi
topo=""
while IFS= read -r f; do
	[ -n "$f" ] || continue
	[ "$(basename "$f")" = t-static.sh ] && continue
	for pat in 'openbao' 'bao://' 'dotmac-''s3' 'minio' 'wasabi' 'conta''bo' '10\.10\.0\.' '/etc/dot''mac' '/opt/keycloak-''ha' 'idp-ha-[0-9]' 'vm''i[0-9]' '/etc/ssl/i''dp' '/var/www/li''nks'; do
		if grep -qiE -- "$pat" "$f"; then topo="$topo $(basename "$f"):$pat"; fi
	done
done <<<"$SCAN"
if [ -z "$topo" ]; then ok "no OpenBao path, backup destination, provider or host-layout name"; else bad "topology names found:$topo"; fi

finish "t-static"
