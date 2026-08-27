# Files that must be reconciled against the live IdP host

**Status: OPEN.** Every file listed here was authored from specification —
ADR-0069, `docs/inventories/mobile-application-sources.md` (findings R1 and R4),
and the recorded operational state of the IdP host. **None of it has been
compared against the live host.**

That distinction is the whole point of this document. This repository currently
describes what the realm *must* look like. It does **not** yet prove what the
realm *does* look like, and it must not be read as if it did.

Each section below names the host artefact by **filename**, not by its path on
the host. This repository is public; the host's directory layout is estate
topology and lives in the operator's private runbook, which is also where the
landing-zone location is recorded.

## Why this list exists at all

The operational guard for the `dotmac` realm lives in one directory on one
host. The realm *database* is backed up hourly, encrypted, and
has a passed restore drill. The *verifier* is not backed up by any of that: a
host replacement would restore every user, credential and signing key while
losing the thing that checks them. That is the gap this repository closes, and
it is not closed until the files below have been reconciled.

## The pre-push checklist items this blocks

Two items of the owner's mandatory pre-push checklist depend on an export that
had not arrived when this repository was authored, and are recorded here as
**PENDING** rather than assumed:

| # | Checklist item | Status |
|---|---|---|
| 4 | Compare desired state against the live non-secret client projection | **PENDING** — no export available |
| 6 | Confirm this repository reproduces the live verifier's successful result | **PENDING** — no export available |

Items 1, 2, 3, 5 and 7 were completed; see `docs/PRE-PUSH-CHECKLIST.md`.

## Landing zone

The owner is exporting the files personally. **No agent working in this
repository may SSH, scp, rsync or curl the IdP host**, for any reason, including
to check whether the export has landed.

The landing zone is a directory on the owner's own workstation, outside every
repository. Its location is in the operator's private runbook; naming it here
would put a path an agent must never write to into a public repository.

As of the last check it contained only the owner's own `README.md` and
`export-from-idp.sh`, and none of the allowlisted export files.

## What must be reconciled, file by file

### 1. `compose/docker-compose.yml` ← the host's `docker-compose.yml`

Must be the **raw, uninterpolated** file. Never `docker compose config`, which
interpolates the environment and would write the database password into the
export.

Specifically unknown and currently authored rather than observed:

- the exact Keycloak image **tag and digest** now running (`26.0.7` is the
  committed default and is a guess at the patch level; the digest knob
  `KEYCLOAK_IMAGE_DIGEST` is deliberately **empty**, and `bin/deploy.sh` refuses
  to deploy with it empty while `REQUIRE_IMAGE_DIGEST=true`)
- the exact Postgres image tag and digest
- the real volume name, network name and container names
- whether `KC_PROXY_HEADERS`, `KC_HTTP_ENABLED` and the health settings match
- confirmation that `KC_BOOTSTRAP_ADMIN_*` are still absent from the live
  environment
- confirmation that both published ports are still loopback-bound

### 2. `bin/verify.sh` ← the host's `verify.sh`

The host verifier is recorded as checking **14 realm/client invariants** from
the complete client object. The version here asserts the realm fields declared
in `realm/dotmac-realm.json`, the client inventory, and the per-class shape
policies. **The two lists have not been diffed.** Any invariant the host checks
and this one does not is a regression introduced by adopting this repository,
which is the opposite of the wave's purpose.

Reconciliation must produce an explicit mapping: host assertion → the policy
line here that owns it, or a new one.

Known host details already carried over: every `docker compose exec -T` gets
`< /dev/null` so stdin has exactly one owner; the full client object is fetched
rather than `--fields attributes`, which can render `{}` and turn a missing pin
into a silent pass.

### 3. `policy/verify-mobile-client.jq` ← the host's `verify-mobile-client.jq`

**A jq policy of this name already exists on the host.** The one here was
written independently from ADR-0069 § 4 and must be diffed against it, not
assumed to supersede it. If the host policy asserts something this one does
not, this one is incomplete.

### 4. `tests/run-policy-tests.sh` ← the host's `test-verify-mobile-client.sh`

**A sensitivity harness already exists on the host** and is recorded as
rejecting: password grant, implicit flow, plain PKCE, confidential-client mode,
wildcard/unexpected redirect, and web-origin fixtures — with hardened active and
disabled fixtures passing.

The harness here covers all of those and adds: an absent PKCE pin, service
accounts, full scope, premature enablement, a redirect staged on a disabled
client, an unverified custom scheme, a symmetric ID-token algorithm, the device
grant, and a redirect outside the declared set. Reconcile in **both** directions
— any host case missing here is a coverage loss.

### 5. `realm/clients/io.dotmac.field.json` ← the host's `clients/io.dotmac.field.json`

The desired state committed here is deliberately **narrow**: it declares exactly
the fields the policy asserts and nothing else. The live client will carry more
(`defaultClientScopes`, `optionalClientScopes`, `frontchannelLogout`,
`attributes` this repository does not name, protocol mappers).

Reconciliation decides, field by field, which of those this repository should
own and which stay Keycloak defaults. Anything not adopted is an **unmonitored
region** and must be named as one in `docs/POLICY.md`, not left implied.

### 6. `realm/clients/dotmac-workspace.json` — SAFE FIELDS ONLY

Represented minimally and on purpose. The workspace client is **confidential**,
and its full representation carries the client secret. Only non-secret shape
fields belong here; the secret itself stays in OpenBao at the location
`BAO_WORKSPACE_OIDC_PATH` names (field `value`), and is neither read nor written
by anything in this repository. See `docs/SECRETS.md`.

Needing confirmation: the exact `clientId`, whether the redirect URI is still
exactly `https://workspace.dotmac.io/login/callback`, and whether `enabled` is
still `true`.

### 7. `realm/dotmac-realm.json` — realm-level settings

`sslRequired: all` and `bruteForceProtected: true` are recorded operational
facts but have not been re-read. Everything else about the realm is currently
an unmonitored region.

**A full realm export must never be committed.** It carries the realm's signing
keys and every client secret. Reconcile field by field into the partial
document instead.

### 8. `realm/expected-clients.json` — the builtin client list

The six Keycloak builtins (`account`, `account-console`, `admin-cli`, `broker`,
`realm-management`, `security-admin-console`) are the standard set for
Keycloak 26 and were **not** read from the realm. If the live realm's set
differs, the inventory policy will report `inventory-unknown` or
`inventory-missing` on the first live run — which is the guard working, but it
must be reconciled before it can be trusted as a signal.

### 9. Not yet present in this repository at all

These are on the export allowlist and have no counterpart here yet. Each is a
gap in the recovery story, not merely a missing file:

| Host artefact | Why it matters |
|---|---|
| backup script (sanitized) | `docs/RECOVERY.md` describes the regime from the recorded operational facts, not from the script that implements it |
| systemd `.service` + `.timer` units | the hourly backup cadence and the freshness alarm depend on them; nothing here declares them |
| nginx configuration (sanitized) | TLS termination, the loopback proxy, and the fact that the admin console is **not** exposed externally (404 from outside). Two version-specific traps apply: nginx 1.24 does not accept a standalone `http2` directive, and `certonly --webroot` does not create `options-ssl-nginx.conf` |
| restore / deployment procedures | must be diffed against `bin/deploy.sh`, `bin/rollback.sh` and `docs/RECOVERY.md` |

## Refusal list

If any of these appears in the landing zone, **stop and report it. Do not
commit it, and do not read further into it than needed to identify it:**

the host's runtime `.env`, database dumps, kcadm credential caches, client
secrets, TLS private keys, object-store credentials, generated Compose output,
and any log or export containing user or credential data.

## Definition of done

This document is deleted — not emptied — when every section above has been
reconciled, `provenance` on every entry in `realm/expected-clients.json` reads
`reconciled-from-host` with a date, and `bin/verify.sh` has run green against
the live realm at a recorded commit.
