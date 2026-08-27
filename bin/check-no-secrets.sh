#!/usr/bin/env bash
# check-no-secrets.sh — the owner's hard rule, made mechanical.
#
#   "Never write a secret value into any file. Reference an OpenBao path only."
#
# Since this repository is public, the paths themselves are supplied as required
# configuration (BAO_KEYCLOAK_PATH and friends) and are not recorded here either
# — a path is estate topology. This scanner grades the VALUE rule; the path rule
# is docs/SECRETS.md and AGENTS.md § 1.
#
# This repository describes an identity provider. The two documents that would
# most naturally be committed here — a full Keycloak realm export and the
# runtime `.env` — are precisely the two that carry signing keys, client
# secrets and the database password. So the rule needs a guard, not a habit.
#
# The check is REFERENTIAL, not entropic: a secret-named key must be assigned
# a REFERENCE (an OpenBao path, an unexpanded ${VAR}, empty, or null), never a
# literal. That is checkable, whereas "does this string look secret" is not.
#
# It carries its own sensitivity proof: --self-test writes deliberately-unsafe
# files to a TEMPORARY directory and asserts each is caught. Nothing
# secret-shaped is ever committed to prove the scanner works.
#
# Knobs: REPO_ROOT (derived), SCAN_ROOT (default: REPO_ROOT).

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCAN_ROOT="${SCAN_ROOT:-$REPO_ROOT}"

# A value that is a REFERENCE rather than a secret. `?` and `-` are here for
# the shell/compose forms ${VAR:?message} and ${VAR:-default}, where the match
# begins at the variable NAME inside the expansion.
ALLOWED_VALUE='(\$\{|\$[A-Z_]|bao://|secret/|<[A-Z_-]+>|PLACEHOLDER|REDACTED|null|\?|-|""|'"''"'|,|\}|$)'

SECRET_KEY='(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)'

scan() {
	local root="$1" hits=0
	# NOTE: every grep here puts its flags BEFORE the path. BSD grep (macOS) does
	# not permute arguments the way GNU grep does, so a trailing
	# `--exclude-dir=.git` is read as another PATH and the exclusion silently
	# does nothing — which is how the first run of this scanner "found" a secret
	# in a git hook sample.
	local -a EXCL=(--exclude-dir=.git --exclude-dir=node_modules)

	# 1. PEM private key blocks. There is no benign reason for one here.
	local pem
	pem="$(grep -rIlE "${EXCL[@]}" -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$root" 2>/dev/null || true)"
	if [ -n "$pem" ]; then
		echo "SECRET  a PEM private key block is present in:"
		printf '%s\n' "$pem" | sed 's/^/          /'
		hits=1
	fi

	# 2. A secret-named key assigned a LITERAL value.
	#    `=` is excluded from the first value character on purpose: without it,
	#    a comparison such as jq's `.secret == null` reads as an assignment of
	#    the literal `=`. A scanner with false positives is a scanner someone
	#    eventually switches off, so precision here is a security property.
	local matches
	matches="$(grep -rInEi "${EXCL[@]}" -- "${SECRET_KEY}[\"']?[[:space:]]*[:=][[:space:]]*[\"']?[^[:space:]\"',}=]" "$root" 2>/dev/null |
		grep -viE -- "${SECRET_KEY}[\"']?[[:space:]]*[:=][[:space:]]*[\"']?${ALLOWED_VALUE}" || true)"
	if [ -n "$matches" ]; then
		echo "SECRET  a secret-named key is assigned a literal value (use an OpenBao path):"
		printf '%s\n' "$matches" | sed 's/^/          /'
		hits=1
	fi

	# 3. An AWS-shaped access key id.
	local aws
	aws="$(grep -rInE "${EXCL[@]}" -- '\b(AKIA|ASIA)[0-9A-Z]{16}\b' "$root" 2>/dev/null || true)"
	if [ -n "$aws" ]; then
		echo "SECRET  an AWS access key id is present:"
		printf '%s\n' "$aws" | sed 's/^/          /'
		hits=1
	fi

	# 4. A committed runtime env file. .env.example is the CONTRACT; .env is the
	#    MATERIAL. .gitignore is the first line of defence, this is the second.
	local envs
	envs="$(find "$root" -name .git -prune -o -type f \
		\( -name '.env' -o -name '*.env' -o -name '.env.*' \) \
		! -name '.env.example' -print 2>/dev/null || true)"
	if [ -n "$envs" ]; then
		echo "SECRET  a runtime env file is present in the tree:"
		printf '%s\n' "$envs" | sed 's/^/          /'
		hits=1
	fi

	# 5. Key material from a full Keycloak realm export.
	local exports
	exports="$(grep -rIlE "${EXCL[@]}" -- '"(privateKey|certificate|secret)"[[:space:]]*:[[:space:]]*"MI' "$root" 2>/dev/null || true)"
	if [ -n "$exports" ]; then
		echo "SECRET  what looks like key material from a realm export is present in:"
		printf '%s\n' "$exports" | sed 's/^/          /'
		hits=1
	fi

	return "$hits"
}

if [ "${1:-}" = "--self-test" ]; then
	# The scanner's own sensitivity proof. A scanner that has never rejected
	# anything is indistinguishable from a scanner that matches nothing.
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	failures=0
	mk() {
		mkdir -p "$tmp/$1"
		printf '%s\n' "$3" >"$tmp/$1/$2"
	}

	# Every unsafe case is ASSEMBLED AT RUNTIME — the key as well as the value.
	# A literal here would make the scanner flag its own source, and a guard
	# that cannot be run over its own repository is not a guard. Nothing
	# secret-shaped is ever committed to prove the scanner works.
	mk case1 compose.yml "      KEYCLOAK_ADMIN_$(printf PASSWORD): $(printf hunter)2-not-real"
	mk case2 client.json "  \"$(printf secret)\": \"$(printf abcdef)0123456789\""
	mk case3 key.pem "$(printf '%s%s' '-----BEGIN ' 'RSA PRIVATE KEY-----')"
	mk case4 aws.sh "AWS_ACCESS_$(printf KEY)_ID=AKIA$(printf IOSFODNN7EXAMPLE)"
	mkdir -p "$tmp/case5" && printf 'KC_DB_%s=%s\n' PASSWORD literal >"$tmp/case5/.env"

	for c in case1 case2 case3 case4 case5; do
		if scan "$tmp/$c" >/dev/null 2>&1; then
			echo "NOT-PROVEN  $c was NOT caught by the secret scanner"
			failures=$((failures + 1))
		else
			echo "caught      $c"
		fi
	done

	# And it must not scream at a correctly-referenced secret, or nobody will
	# be able to keep it switched on.
	mk case6 ok.yml '      KEYCLOAK_ADMIN_PASSWORD: ${KC_ADMIN_PASSWORD}'
	# case7 is LOAD-BEARING: it is the proof that the check is REFERENTIAL rather
	# than entropic — a secret-named key pointing at an OpenBao LOCATION is a
	# reference, not a value, and must pass. The literal below is a placeholder
	# on purpose; this repository is public and records no real OpenBao path
	# anywhere (docs/SECRETS.md). Changing the literal is fine; deleting the case
	# removes the proof.
	mk case7 ok.md '  admin_password: secret/EXAMPLE-PATH/component (field: admin_password)'
	for c in case6 case7; do
		if scan "$tmp/$c" >/dev/null 2>&1; then
			echo "clean       $c"
		else
			echo "NOT-PROVEN  $c is a correct OpenBao reference but the scanner rejected it"
			scan "$tmp/$c" | sed 's/^/            /'
			failures=$((failures + 1))
		fi
	done

	if [ "$failures" -ne 0 ]; then
		echo "secret-scanner self-test FAILED ($failures)"
		exit 1
	fi
	echo "secret-scanner self-test complete"
	exit 0
fi

if scan "$SCAN_ROOT"; then
	echo "no committed secret value found under $SCAN_ROOT"
	exit 0
fi
echo "check-no-secrets: refusing. Replace every value above with an OpenBao path; see docs/SECRETS.md."
exit 1
