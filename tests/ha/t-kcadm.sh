#!/usr/bin/env bash
# t-kcadm.sh — offline behaviour tests for bin/apply-clients.sh and bin/verify.sh
# against a STUB `docker` (no Keycloak, no container, no network). Proves script
# logic only: APPLY_ONLY scoping, the update refusal, the dry-run diff, that the
# admin password is never in a constructed argv, that masked export reads are
# projected without credential material or unrelated export values, and that the kcadm login cache is removed on exit. It does
# NOT prove real kcadm behaviour (e.g. update -f semantics) or real container paths.
set -uo pipefail
# shellcheck source=tests/ha/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PW="pw-canary-4f9a1c"
SEC="secret-canary-7b2e5d"
ROT="rotated-canary-3c8d90"
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
if grep -rqF -e "$SEC" -e "$ROT" -e '**********' -e v-live-only -e discard-this-component -e discard-this-user "$TMPD" 2>/dev/null; then echo leak >>"$T/leak.log"; fi
case "\$*" in
*"config credentials"*) if [ -n "\${CANCEL_SIGNAL:-}" ]; then kill -s "\$CANCEL_SIGNAL" "\$PPID"; exit 0; fi ;;
esac
case "\$*" in
*"kcadm.sh get clients"*|*"kcadm.sh get realms/"*) echo forbidden >>"$T/forbidden-get.log"; exit 91 ;;
*"kcadm.sh create partial-export "*)
  [ -z "\${FAIL_EXPORT:-}" ] || { echo "$SEC" >&2; exit 27; }
  if [ -n "\${INVALID_EXPORT:-}" ]; then printf '%s' '{invalid'; else cat "$T/masked-export.json"; fi
  ;;
*" mktemp "*) printf '%s\n' "\${KCADM_DIR:-/tmp/kcadm.TESTDIR}"; : >"$T/cache.present" ;;
*" rm -rf "*)
  if [ "\${!#}" != /tmp/kcadm.TESTDIR ]; then echo unexpected >"$T/unrelated-delete.log"; exit 24; fi
  if [ -n "\${CANCEL_CLEANUP:-}" ]; then kill -s "\$CANCEL_CLEANUP" "\$PPID"; fi
  [ -z "\${FAIL_CLEANUP:-}" ] || exit 23
  [ -n "\${CACHE_REMAINS:-}" ] || rm -f "$T/cache.present"
  ;;
*'test -e "'* )
  if [ -n "\${SUCCESS_OUTPUT:-}" ] && grep -Eq 'desired state applied|verify.sh: PASSED' "\$SUCCESS_OUTPUT"; then echo premature >"$T/premature.log"; fi
  [ -z "\${QUERY_ERROR:-}" ] || exit "\$QUERY_ERROR"
  [ ! -e "$T/cache.present" ] || exit 42
  ;;
*" ps "*) echo '{"State":"running"}' ;;
*"kcadm.sh create"*|*"kcadm.sh update"*) echo "\$*" | sed 's/.*kcadm.sh //' >>"$T/writes.log"; if [ -n "\${FAIL_WRITE:-}" ]; then exit "\$FAIL_WRITE"; fi ;;
esac
cat >/dev/null 2>&1 </dev/null
exit 0
STUBEOF
chmod +x "$KSTUB/docker"
cat >"$KSTUB/rm" <<'STUBEOF'
#!/usr/bin/env bash
if [ -n "${FAIL_LOCAL_CLEANUP:-}" ] && [[ "${*: -1}" == "$TMPDIR/"* ]]; then exit 31; fi
exec /bin/rm "$@"
STUBEOF
chmod +x "$KSTUB/rm"


# Manifest: academy (absent live), workspace (present live), field (present live).
MAN="$T/manifest.json"
jq '.clients |= map(select(.class != "keycloak-builtin"))' "$REPO_ROOT/realm/expected-clients.json" >"$MAN"

setup() { # setup <live-list-json> <live-client-json>
	printf '%s' "$1" >"$T/live-list.json"
	printf '%s' "$2" >"$T/live-client.json"
	: >"$T/argv.log"
	: >"$T/writes.log"
	: >"$T/leak.log"
	: >"$T/premature.log"
	: >"$T/unrelated-delete.log"
	: >"$T/forbidden-get.log"
	# Model server-side masking BEFORE the stub returns any HTTP-equivalent data.
	# Unrelated export data must be discarded by the projection.
	jq -n --slurpfile clients "$T/live-list.json" --slurpfile live "$T/live-client.json" '
	  {realm:"dotmac", enabled:true, sslRequired:"all", bruteForceProtected:true,
	   components:{unrelated:"discard-this-component"}, users:[{unrelated:"discard-this-user"}],
	   clients:[$clients[0][] | . as $c |
	     (if $c.id == "u-ws" then $live[0] + {id:$c.id,clientId:$c.clientId} else $c end)
	     | .secret = "**********"
	     | if .attributes then .attributes["client.secret.rotated"] = "**********" else . end]}' >"$T/masked-export.json"
	rm -f "$T/cache.present"
}
run_apply() { # run_apply <outfile> [args...]; env passes through
	local out="$1"
	shift
	PATH="$KSTUB:$PATH" MANIFEST="$MAN" KC_ADMIN_PASSWORD="$PW" CONFIG_ENV_FILE=/nonexistent SECRET_ENV_FILE=/nonexistent \
		bash "$REPO_ROOT/bin/apply-clients.sh" "$@" >"$out" 2>&1
}
run_verify() { # Minimal valid builtin inventory isolates cleanup from shape policy.
	PATH="$KSTUB:$PATH" MANIFEST="$T/cleanup-manifest.json" REALM_DESIRED="$T/cleanup-realm.json" \
		KC_ADMIN_PASSWORD="$PW" CONFIG_ENV_FILE=/nonexistent SECRET_ENV_FILE=/nonexistent \
		VERIFY_DISCOVERY=false VERIFY_ROLLOUT=false bash "$REPO_ROOT/bin/verify.sh" >"$1" 2>&1
}
printf '%s' '{"clients":[{"clientId":"account","class":"keycloak-builtin"}]}' >"$T/cleanup-manifest.json"
printf '%s' '{}' >"$T/cleanup-realm.json"

LIVE_LIST='[{"id":"u-ws","clientId":"dotmac-workspace","secret":"'$SEC'","attributes":{"client.secret.rotated":"'$ROT'"}},{"id":"u-fld","clientId":"io.dotmac.field"}]'
LIVE_WS="$(jq --arg s "$SEC" --arg r "$ROT" '. + {secret:$s} | .attributes += {"client.secret.rotated":$r, "live.only.attr":"v-live-only"}' "$REPO_ROOT/realm/clients/dotmac-workspace.json")"

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
setup "$LIVE_LIST" "$(jq --arg s "$SEC" --arg r "$ROT" '. + {secret:$s, redirectUris:["https://app.example.invalid/cb"], fullScopeAllowed:true} | .attributes += {"client.secret.rotated":$r, "live.only.attr":"v-live-only"}' "$REPO_ROOT/realm/clients/dotmac-workspace.json")"
APPLY_DRY_RUN=true APPLY_ONLY=dotmac-workspace run_apply "$T/o5"
expect "dry run exits 0" 0 $?
has "diff lists differing key" "$T/o5" "redirectUris: declared="
has "diff shows live value" "$T/o5" "https://app.example.invalid/cb"
has "diff lists fullScopeAllowed" "$T/o5" "fullScopeAllowed: declared=false live=true"
hasnt "dry-run output hides secret value" "$T/o5" "$SEC"
hasnt "dry-run output hides client.secret.rotated value" "$T/o5" "$ROT"
hasnt "dry-run output never prints the rotated attribute name" "$T/o5" "client.secret.rotated"
has "live-only attribute listed by name" "$T/o5" "live.only.attr"
hasnt "live-only attribute value not printed" "$T/o5" "v-live-only"
hasnt "dry-run output has no secret key" "$T/o5" "secret"
if [ ! -s "$T/writes.log" ]; then ok "dry run wrote nothing"; else bad "dry run wrote"; fi
if [ ! -s "$T/leak.log" ]; then ok "no temp file ever held the secret (apply)"; else bad "secret reached a temp file (apply)"; fi
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_DRY_RUN=true APPLY_ONLY=dotmac-workspace run_apply "$T/o6"
has "identical live (extra live attrs, secret, rotated) reports no change" "$T/o6" "no change"
hasnt "no-change output hides secret" "$T/o6" "$SEC"
hasnt "no-change output hides rotated secret" "$T/o6" "$ROT"
# arrays compared sorted; empty-string attribute equals absent live
setup "$LIVE_LIST" "$(jq '.redirectUris |= reverse | .attributes |= del(.["post.logout.redirect.uris"])' "$REPO_ROOT/realm/clients/dotmac-workspace.json")"
APPLY_DRY_RUN=true APPLY_ONLY=dotmac-workspace run_apply "$T/o6b"
has "reordered arrays and empty-vs-absent attribute are no change" "$T/o6b" "no change"

section "password never in argv; private login cache removed"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=dotmac-academy run_apply "$T/o7"
hasnt "apply argv has no password value" "$T/argv.log" "$PW"
hasnt "apply output has no password value" "$T/o7" "$PW"
hasnt "apply argv has no --password" "$T/argv.log" "--password"
if grep 'config credentials' "$T/argv.log" | grep -q 'sh -c'; then bad "config credentials goes through an sh -c wrapper"; else ok "config credentials has no sh -c wrapper"; fi
has "apply passes -e KC_CLI_PASSWORD by name" "$T/argv.log" "-e KC_CLI_PASSWORD "
hasnt "no NAME=value env form" "$T/argv.log" "KC_CLI_PASSWORD="
hasnt "KCADM_PASSWORD no longer used" "$T/argv.log" "KCADM_PASSWORD"
has "apply removes exactly its private dir on exit" "$T/argv.log" "rm -rf /tmp/kcadm.TESTDIR"
hasnt "apply never touches a shared cache path" "$T/argv.log" ".keycloak"
nocfg="$(grep 'kcadm.sh' "$T/argv.log" | grep -vc -- '--config /tmp/kcadm.TESTDIR/kcadm.config')"
if [ "$nocfg" = 0 ] && grep -q 'config credentials' "$T/argv.log"; then ok "every kcadm call (incl. config credentials) uses the private --config"; else bad "kcadm calls without private --config: $nocfg"; fi
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=no-such-client run_apply "$T/o7b"
hasnt "no cleanup exec when nothing was created" "$T/argv.log" "rm -rf"
if [ -z "$(ls -A "$TMPD")" ]; then ok "apply left no temp files"; else bad "apply left temp files"; fi

section "scope rules"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ALLOW_UPDATE=true run_apply "$T/o8"
expect "ALLOW_UPDATE without APPLY_ONLY refuses" 2 $?
if [ ! -s "$T/argv.log" ]; then ok "refused before any container call"; else bad "docker called"; fi
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_ONLY=dotmac-workspace run_apply "$T/o9" --only dotmac-academy
expect "--only replacing env runs" 0 $?
if [ "$(wc -l <"$T/writes.log" | tr -d ' ')" = 1 ] && grep -q '^create clients' "$T/writes.log"; then ok "--only REPLACED the environment APPLY_ONLY (only academy written)"; else bad "writes: $(cat "$T/writes.log")"; fi
has "resolved scope printed" "$T/o9" "scope: dotmac-academy"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_DRY_RUN=true run_apply "$T/o9b" --only dotmac-academy --only io.dotmac.field
expect "repeated --only accumulates" 0 $?
has "scope lists both" "$T/o9b" "scope: dotmac-academy,io.dotmac.field"
setup "$LIVE_LIST" "$LIVE_WS"
APPLY_DRY_RUN=true run_apply "$T/o9c"
has "unscoped run prints the full resolved list" "$T/o9c" "scope: all applicable clients"

section "staged files removed when a write fails"
setup "$LIVE_LIST" "$LIVE_WS"
FAIL_WRITE=1 APPLY_ONLY=dotmac-academy run_apply "$T/o10"
if [ "$?" != 0 ]; then ok "failed create exits nonzero"; else bad "failed create exited 0"; fi
has "private dir (with staged file) removed after failure" "$T/argv.log" "rm -rf /tmp/kcadm.TESTDIR"
has "staged file lives inside the private dir" "$T/argv.log" "/tmp/kcadm.TESTDIR/desired-dotmac-academy.json"

setup "$LIVE_LIST" "$LIVE_WS"
PATH="$KSTUB:$PATH" MANIFEST="$MAN" KC_ADMIN_PASSWORD="$PW" CONFIG_ENV_FILE=/nonexistent SECRET_ENV_FILE=/nonexistent \
	VERIFY_DISCOVERY=false VERIFY_ROLLOUT=false bash "$REPO_ROOT/bin/verify.sh" >"$T/v1" 2>&1
hasnt "verify argv has no password value" "$T/argv.log" "$PW"
hasnt "verify argv has no --password" "$T/argv.log" "--password"
hasnt "verify output has no password value" "$T/v1" "$PW"
has "verify passes -e KC_CLI_PASSWORD by name" "$T/argv.log" "-e KC_CLI_PASSWORD "
hasnt "verify has no NAME=value env form" "$T/argv.log" "KC_CLI_PASSWORD="
has "verify removes exactly its private dir on exit" "$T/argv.log" "rm -rf /tmp/kcadm.TESTDIR"
nocfg="$(grep 'kcadm.sh' "$T/argv.log" | grep -vc -- '--config /tmp/kcadm.TESTDIR/kcadm.config')"
if [ "$nocfg" = 0 ]; then ok "every verify kcadm call uses the private --config"; else bad "verify kcadm calls without --config: $nocfg"; fi
hasnt "verify output hides rotated secret" "$T/v1" "$ROT"
hasnt "verify output hides client secret" "$T/v1" "$SEC"
if [ ! -s "$T/leak.log" ]; then ok "no temp file ever held the secret (verify)"; else bad "secret reached a temp file (verify)"; fi
if [ -z "$(ls -A "$TMPD")" ]; then ok "verify left no temp files"; else bad "verify left temp files"; fi
has "verify uses masked export" "$T/argv.log" 'create partial-export'
if [ ! -s "$T/forbidden-get.log" ]; then ok "verify made no ordinary client or realm GET"; else bad "verify made an unsafe GET"; fi

section "cleanup is a success barrier"
for script in apply verify; do
	cleanup_run() {
		if [ "$script" = apply ]; then
			APPLY_ONLY=dotmac-academy run_apply "$T/cleanup-out"
		else
			run_verify "$T/cleanup-out"
		fi
	}
	cleanup_setup() {
		if [ "$script" = apply ]; then setup "$LIVE_LIST" "$LIVE_WS";
		else setup '[{"id":"builtin","clientId":"account"}]' '{}'; fi
	}
	cleanup_setup
	SUCCESS_OUTPUT="$T/cleanup-out" cleanup_run
	expect "$script succeeds after confirmed absence" 0 $?
	if [ ! -s "$T/premature.log" ]; then ok "$script success follows absence query"; else bad "$script reported success before cleanup"; fi
	if [ ! -s "$T/unrelated-delete.log" ]; then ok "$script removes no unrelated directory"; else bad "$script removed an unrelated directory"; fi
	expect "$script reuses exactly one snapshot" 1 "$(grep -c 'create partial-export' "$T/argv.log")"
	has "$script requests server-masked clients" "$T/argv.log" 'create partial-export'
	has "$script exports clients" "$T/argv.log" 'exportClients=true'
	has "$script omits groups and roles" "$T/argv.log" 'exportGroupsAndRoles=false'
	if [ ! -s "$T/forbidden-get.log" ]; then ok "$script made no ordinary client or realm GET"; else bad "$script made an unsafe GET"; fi
	has "$script queries only its own directory" "$T/argv.log" 'sh /tmp/kcadm.TESTDIR'
	for export_failure in FAIL_EXPORT INVALID_EXPORT; do
		cleanup_setup
		export "$export_failure=1"
		cleanup_run
		rc=$?
		unset "$export_failure"
		expect "$script $export_failure fails closed" 1 "$rc"
		hasnt "$script export failure hides raw diagnostics" "$T/cleanup-out" "$SEC"
		hasnt "$script export failure cannot pass" "$T/cleanup-out" 'verify.sh: PASSED'
		hasnt "$script export failure cannot claim applied" "$T/cleanup-out" 'desired state applied'
		if [ ! -s "$T/writes.log" ]; then ok "$script export failure causes no write"; else bad "$script wrote after export failure"; fi
		has "$script export failure still removes cache" "$T/argv.log" 'rm -rf /tmp/kcadm.TESTDIR'
	done
	for failure in FAIL_CLEANUP CACHE_REMAINS; do
		cleanup_setup
		export "$failure=1"
		cleanup_run
		rc=$?
		unset "$failure"
		expect "$script $failure fails closed" 1 "$rc"
		has "$script cleanup failure is explicit" "$T/cleanup-out" 'cleanup unconfirmed'
		hasnt "$script cleanup failure cannot pass" "$T/cleanup-out" 'verify.sh: PASSED'
		hasnt "$script cleanup failure cannot claim applied" "$T/cleanup-out" 'desired state applied'
		if [ -z "$(ls -A "$TMPD")" ]; then ok "$script remote failure still removes local work"; else bad "$script left local work"; fi
	done
	for query_rc in 1 2 125; do
		cleanup_setup
		QUERY_ERROR="$query_rc" cleanup_run
		expect "$script query status $query_rc is not absence" 1 $?
		hasnt "$script query error cannot pass" "$T/cleanup-out" 'verify.sh: PASSED'
		hasnt "$script query error cannot claim applied" "$T/cleanup-out" 'desired state applied'
	done
	for invalid in /tmp/kcadm. /tmp/kcadm.X/../other /tmp/kcadm.X/child $'/tmp/kcadm.X\nother' $'/tmp/kcadm.X\n'; do
		cleanup_setup
		KCADM_DIR="$invalid" cleanup_run
		expect "$script invalid directory refuses" 1 $?
		hasnt "$script invalid directory never reaches login" "$T/argv.log" 'config credentials'
		hasnt "$script invalid directory is never removed" "$T/argv.log" 'rm -rf'
		if [ ! -s "$T/unrelated-delete.log" ]; then ok "$script invalid path leaves unrelated directories alone"; else bad "$script attempted unrelated deletion"; fi
	done
	cleanup_setup
	FAIL_LOCAL_CLEANUP=1 cleanup_run
	expect "$script local cleanup failure fails closed" 1 $?
	has "$script local failure still attempts cache removal" "$T/argv.log" 'rm -rf /tmp/kcadm.TESTDIR'
	has "$script local failure still confirms cache absence" "$T/argv.log" 'sh /tmp/kcadm.TESTDIR'
	rm -rf "$TMPD"/*
	cleanup_setup
	CANCEL_CLEANUP=TERM cleanup_run
	expect "$script cancellation during cleanup fails closed" 143 $?
	has "$script cancellation during cleanup still confirms absence" "$T/argv.log" 'sh /tmp/kcadm.TESTDIR'
	hasnt "$script cancellation during cleanup cannot pass" "$T/cleanup-out" 'verify.sh: PASSED'
	hasnt "$script cancellation during cleanup cannot claim applied" "$T/cleanup-out" 'desired state applied'
	for signal in TERM HUP INT; do
		cleanup_setup
		CANCEL_SIGNAL="$signal" cleanup_run
		rc=$?
		case "$signal" in TERM) expected=143 ;; HUP) expected=129 ;; INT) expected=130 ;; esac
		expect "$script $signal cancellation status" "$expected" "$rc"
		has "$script cancellation removes owned cache" "$T/argv.log" 'rm -rf /tmp/kcadm.TESTDIR'
		has "$script cancellation confirms absence" "$T/argv.log" 'sh /tmp/kcadm.TESTDIR'
		hasnt "$script cancellation cannot pass" "$T/cleanup-out" 'verify.sh: PASSED'
		hasnt "$script cancellation cannot claim applied" "$T/cleanup-out" 'desired state applied'
	done
done
setup '[{"id":"unexpected","clientId":"unexpected"}]' '{}'
FAIL_CLEANUP=1 run_verify "$T/verify-failure-cleanup"
expect "verify assertion failure survives cleanup failure" 1 $?
hasnt "verify assertion and cleanup failure cannot pass" "$T/verify-failure-cleanup" 'verify.sh: PASSED'
setup "$LIVE_LIST" "$LIVE_WS"
FAIL_WRITE=17 FAIL_CLEANUP=1 APPLY_ONLY=dotmac-academy run_apply "$T/failed-write-cleanup"
expect "write failure status survives cleanup failure" 17 $?
expect "failed write is never retried" 1 "$(wc -l <"$T/writes.log" | tr -d ' ')"
has "write and cleanup failure both reported" "$T/failed-write-cleanup" 'cleanup unconfirmed'
setup "$LIVE_LIST" "$LIVE_WS"
FAIL_CLEANUP=1 run_apply "$T/refusal-cleanup"
expect "existing refusal status survives cleanup failure" 3 $?

echo
echo "t-kcadm: $pass passed, $failn failed"
[ "$failn" = 0 ]
