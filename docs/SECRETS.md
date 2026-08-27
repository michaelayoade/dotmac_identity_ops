# Secrets

**The rule is absolute: no secret value is ever written into any file in this
repository.** Not in a comment, not in an example, not "temporarily", not in a
test fixture.

**And, since this repository is public, no OpenBao *path* either.** A path is
not a value, but it is topology: published, it tells any reader exactly where
the estate keeps its credentials. So each location is a **required
configuration input with no default**. This repository names the *variable*;
the operator supplies the *value*, and it is recorded only in the operator's
private runbook, outside every repository.

This repository describes an identity provider, so the two documents that would
most naturally be committed here are exactly the two that must never be: a full
Keycloak realm export (signing keys, client secrets, credential material) and
the runtime `.env` (database password, admin password). The rule needs a guard,
not a habit — see "Enforcement" below.

## Where the material lives

Three OpenBao locations exist. Each is named here by its **configuration
variable**; none of the three locations is written down anywhere in this
repository, and none has a default. The operator's private runbook maps
variable → location.

| What | Required config variable | Field(s) | Read by |
|---|---|---|---|
| Keycloak database + admin material | `BAO_KEYCLOAK_PATH` | `db_user`, `db_name`, `db_password`, `admin_user`, `admin_password`, `issuer`, `realm` | `bin/deploy.sh`, at deploy time only |
| Workspace relying-party client secret | `BAO_WORKSPACE_OIDC_PATH` | `value` (plus `client_id`, `realm`, `issuer`, `redirect_uri`) | **nothing in this repository**. Named so nobody goes looking for it here |
| IdP host access | `BAO_IDP_HOST_PATH` | — | host access only; no script here uses it |

`BAO_KEYCLOAK_PATH` is the only one any script consumes. `bin/deploy.sh` checks
it with `${BAO_KEYCLOAK_PATH:?...}` **after** loading the operator's `./.env`,
so it may be set in either place, and it fails closed with a message pointing at
the private runbook rather than falling back to a guess. A default here would be
the same mistake as a value: it would put the location back into a public
repository.

## How material reaches the runtime

Read once, held, delivered — never dereferenced on a request path (ADR-0009).

1. `bin/deploy.sh` reads the named fields at deploy time from the location
   `BAO_KEYCLOAK_PATH` names.
2. It renders them into `$SECRET_ENV_FILE` (default `./.env.secrets`) under
   `umask 077` — a **different file** from the operator's `./.env`, which holds
   non-secret knobs and must survive the deploy.
3. Compose receives both with `--env-file`. The rendered file is removed by an
   `EXIT` trap, whether the deploy succeeded or not.
4. **Names are logged; values never are.** The deploy prints which knobs it
   rendered, not what they contain.

`.env` and `.env.*` are gitignored, and `bin/check-no-secrets.sh` fails a tree
that contains one regardless (`.env.example` excepted — it is the contract, and
carries no values) — the ignore rule is the first line of defence, not the only one.

The Keycloak container receives **no** OpenBao address and **no** OpenBao token.
A compromise of the runtime therefore cannot be turned into a secrets-store
read. Do not add one for convenience.

`KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD` are deliberately
absent from `compose/docker-compose.yml`. They are bootstrap-only by design, and
an admin password left in a container environment is one `docker inspect` away
from anyone with socket access. They were removed from the live host once the
admin account was confirmed persisted. Do not reintroduce them.

## The admin password and `kcadm`

`bin/verify.sh` and `bin/apply-clients.sh` need `KC_ADMIN_PASSWORD` in the
environment. They pass it into the container through `docker compose exec -e`,
so it never appears in the **host's** process table, in any log, or in any file.

**Stated honestly:** `kcadm.sh` accepts the password only as a command-line
argument, so for the duration of the `config credentials` call it is visible in
the *container's own* process table. There is no `--password-stdin`. This is a
residual, it is named rather than hidden, and it is bounded to a process that
already holds the credential.

Both scripts refuse to run under `set -x`: a traced run would put the credential
into the trace output, which is the one place nobody thinks to check.

## Enforcement

`bin/check-no-secrets.sh` runs in CI, and is **referential rather than
entropic**: a secret-named key must be assigned a reference — an OpenBao path,
an unexpanded `${VAR}`, empty, or null — never a literal. "Does this string look
secret" is not checkable; "is this a reference" is.

It rejects: PEM private key blocks, secret-named keys assigned literals,
AWS-shaped access key ids, any `.env`-style file in the tree, and what looks
like key material from a realm export.

It carries its own sensitivity proof (`--self-test`), which writes
deliberately-unsafe files to a **temporary directory** and asserts each is
caught — and asserts that a correctly-referenced secret is *not* flagged
(`case7`, a placeholder OpenBao location), since a scanner nobody can keep
switched on is not a control. That passing case is as load-bearing as the
failing ones: it is what proves the check distinguishes a reference from a
value. Nothing secret-shaped is ever committed to prove the scanner works.

The scanner grades **values**. The no-path rule above is not mechanical: it is
review discipline plus the required-config shape, and `git grep secret/` over a
pull request is the practical check.

## If a secret is ever committed

Rotate first, scrub second. A value that reached a git object is compromised
even after a force-push, because it may already have been fetched. The order is:

1. rotate the credential in OpenBao and in Keycloak
2. redeploy
3. then, and only then, deal with the history
