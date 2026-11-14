#!/usr/bin/env bash
# t-kcadm.sh — offline behaviour tests for bin/apply-clients.sh and bin/verify.sh
# against a STUB `docker` (no Keycloak, no container, no network). Proves script
# logic only: APPLY_ONLY scoping, the update refusal, the dry-run diff, that the
# admin password is never in a constructed argv, that .secret never reaches a
# temp file or output, and that the kcadm login cache is removed on exit. It does
# NOT prove real kcadm behaviour (e.g. update -f semantics) or real container paths.
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PW="pw-canary-4f9a1c"
SEC="secret-canary-7b2e5d"
TMPD="$T/tmp"
mkdir -p "$TMPD"
export TMPDIR="$TMPD"

# Stub docker. Records argv (one line per call). Serves canned kcadm reads that
# INCLUDE a `secret` field, so any leak is detectable. At every call it also
# greps TMPDIR for the secret canary: a temp file holding it is a leak.
KSTUB="$T/kstub"
mkdir -p "$KSTUB"
cat >"$KSTUB/docker" <<STUBEOF
#!/usr/bin/env bash
echo "docker \$*" >>"$T/argv.log"
if grep -rqF "$SEC" "$TMPD" 2>/dev/null; then echo leak >>"$T/leak.log"; fi
case "\$*" in
*"kcadm.sh get clients/"*) cat "$T/live-client.json" ;;
*"kcadm.sh get clients"*) cat "$T/live-list.json" ;;
*"kcadm.sh get realms/"*) echo '{"realm":"dotmac"}' ;;
*" ps "*) echo '{"State":"running"}' ;;
*"kcadm.sh create"*|*"kcadm.sh update"*) echo "\$*" | sed 's/.*kcadm.sh //' >>"$T/writes.log" ;;
esac
cat >/dev/null 2>&1 </dev/null
exit 0
STUBEOF
chmod +x "$KSTUB/docker"

# Manifest: academy (absent live), workspace (present live), field (present live).
MAN="$T/manifest.json"
jq '.clients |= map(select(.class != "keycloak-builtin"))' "$REPO_ROOT/realm/expected-clients.json" >"$MAN"

setup() { # setup <live-list-json> <live-client-json>
	printf '%s' "$1" >"$T/live-list.json"
	printf '%s' "$2" >"$T/live-client.json"
	: >"$T/argv.log"
	: >"$T/writes.log"
	: >"$T/leak.log"
}
run_apply() { # run_apply <outfile> [args...]; env passes through
	local out="$1"
	shift
	PATH="$KSTUB:$PATH" MANIFEST="$MAN" KC_ADMIN_PASSWORD="$PW" CONFIG_ENV_FILE=/nonexistent SECRET_ENV_FILE=/nonexistent \
		bash "$REPO_ROOT/bin/apply-clients.sh" "$@" >"$out" 2>&1
}
LIVE_LIST='[{"id":"u-ws","clientId":"dotmac-workspace","secret":"'$SEC'"},{"id":"u-fld","clientId":"io.dotmac.field"}]'
LIVE_WS="$(jq --arg s "$SEC" '. + {secret:$s}' "$REPO_ROOT/realm/clients/dotmac-workspace.json")"

section "APPLY_ONLY scopes writes"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=dotmac-academy run_apply "$T/o1"
rc=$?
expect "APPLY_ONLY=academy exits 0" 0 "$rc"
if [ "$(wc -l <"$T/writes.log" | tr -d ' ')" = 1 ] && grep -q '^create clients' "$T/writes.log"; then ok "exactly one write, a create"; else bad "writes: $(cat "$T/writes.log")"; fi
hasnt "no update issued for unlisted clients" "$T/writes.log" "update"
hasnt "no read of unlisted client" "$T/argv.log" "clients/u-ws"
setup "$LIVE_LIST" "$LIVE_WS"
run_apply "$T/o1b" --only dotmac-academy
expect "--only works like APPLY_ONLY" 0 $?
has "--only creates academy" "$T/writes.log" "create clients"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=no-such-client run_apply "$T/o2"
expect "unknown APPLY_ONLY name refuses" 2 $?
if [ ! -s "$T/argv.log" ]; then ok "unknown name refused before any container call"; else bad "docker called before refusal"; fi
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=account run_apply "$T/o2b"
expect "builtin client name refuses" 2 $?
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=dotmac-workspace APPLY_ALLOW_UPDATE=true run_apply "$T/o3"
expect "APPLY_ONLY + ALLOW_UPDATE updates" 0 $?
if [ "$(wc -l <"$T/writes.log" | tr -d ' ')" = 1 ] && grep -q '^update clients/u-ws' "$T/writes.log"; then ok "only the named client updated"; else bad "writes: $(cat "$T/writes.log")"; fi

section "default refuses updates"
setup "$LIVE_LIST" "$LIVE_WS"
run_apply "$T/o4"
expect "default run with existing clients refuses" 3 $?
if [ ! -s "$T/writes.log" ]; then ok "refusal happened before any write (including creates)"; else bad "wrote before refusing: $(cat "$T/writes.log")"; fi
has "refusal names the knob" "$T/o4" "APPLY_ALLOW_UPDATE=true"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=dotmac-workspace run_apply "$T/o4b"
expect "APPLY_ONLY alone does not permit an update" 3 $?

section "dry-run diff"
setup "$LIVE_LIST" "$(jq --arg s "$SEC" '. + {secret:$s, redirectUris:["https://app.example.invalid/cb"], fullScopeAllowed:true}' "$REPO_ROOT/realm/clients/dotmac-workspace.json")"
APPLY_DRY_RUN=true APPLY_ONLY=dotmac-workspace run_apply "$T/o5"
expect "dry run exits 0" 0 $?
has "diff lists differing key" "$T/o5" "redirectUris: declared="
has "diff shows live value" "$T/o5" "https://app.example.invalid/cb"
has "diff lists fullScopeAllowed" "$T/o5" "fullScopeAllowed: declared=false live=true"
hasnt "dry-run output hides secret value" "$T/o5" "$SEC"
hasnt "dry-run output has no secret key" "$T/o5" "secret"
if [ ! -s "$T/writes.log" ]; then ok "dry run wrote nothing"; else bad "dry run wrote"; fi
if [ ! -s "$T/leak.log" ]; then ok "no temp file ever held the secret (apply)"; else bad "secret reached a temp file (apply)"; fi
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_DRY_RUN=true APPLY_ONLY=dotmac-workspace run_apply "$T/o6"
has "identical live reports no change" "$T/o6" "no change"
hasnt "no-change output hides secret" "$T/o6" "$SEC"

section "password never in argv; login cache removed"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=dotmac-academy run_apply "$T/o7"
hasnt "apply argv has no password value" "$T/argv.log" "$PW"
hasnt "apply output has no password value" "$T/o7" "$PW"
has "apply passes -e KCADM_PASSWORD by name" "$T/argv.log" "-e KCADM_PASSWORD "
hasnt "no KCADM_PASSWORD=value form" "$T/argv.log" "KCADM_PASSWORD="
has "apply removes kcadm.config on exit" "$T/argv.log" "kcadm.config"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=no-such-client run_apply "$T/o7b"
hasnt "no cleanup exec when never logged in" "$T/argv.log" "kcadm.config"
if [ -z "$(ls -A "$TMPD")" ]; then ok "apply left no temp files"; else bad "apply left temp files"; fi

setup "$LIVE_LIST" "$LIVE_WS"
PATH="$KSTUB:$PATH" MANIFEST="$MAN" KC_ADMIN_PASSWORD="$PW" CONFIG_ENV_FILE=/nonexistent SECRET_ENV_FILE=/nonexistent \
	VERIFY_DISCOVERY=false VERIFY_ROLLOUT=false bash "$REPO_ROOT/bin/verify.sh" >"$T/v1" 2>&1
hasnt "verify argv has no password value" "$T/argv.log" "$PW"
hasnt "verify output has no password value" "$T/v1" "$PW"
has "verify passes -e KCADM_PASSWORD by name" "$T/argv.log" "-e KCADM_PASSWORD "
hasnt "verify has no KCADM_PASSWORD=value form" "$T/argv.log" "KCADM_PASSWORD="
has "verify removes kcadm.config on exit" "$T/argv.log" "kcadm.config"
hasnt "verify output hides client secret" "$T/v1" "$SEC"
if [ ! -s "$T/leak.log" ]; then ok "no temp file ever held the secret (verify)"; else bad "secret reached a temp file (verify)"; fi
if [ -z "$(ls -A "$TMPD")" ]; then ok "verify left no temp files"; else bad "verify left temp files"; fi
if grep -q 'kcadm.sh get clients' "$T/argv.log"; then ok "verify exercised the client reads"; else bad "verify never read clients"; fi

echo
echo "t-kcadm: $pass passed, $failn failed"
[ "$failn" = 0 ]
