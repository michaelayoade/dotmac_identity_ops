# AGENTS.md — hard rules for `dotmac_identity_ops`

Canonical. `README.md` indexes; this file governs. If the two disagree, this
file wins and the drift gets fixed.

## 1. No secret value in any file. Ever. And no OpenBao path either.

Not in a comment, not in an example, not "temporarily", not in a fixture.
Enforced by `bin/check-no-secrets.sh`, which runs in CI and carries its own
sensitivity proof (`--self-test`) — including a PASSING case, which is what
proves the check distinguishes a reference from a value. Deleting that case
removes the proof.

**This repository is public, so the OpenBao *paths* are out too.** A path is not
a value, but published it says exactly where the estate keeps its credentials.
Every location is a **required configuration input with no default**
(`BAO_KEYCLOAK_PATH`, `BAO_WORKSPACE_OIDC_PATH`, `BAO_IDP_HOST_PATH`); a
default would be the same mistake as a literal. Documentation says *that* a
location is required and that the operator's private runbook records it —
never what it is. `bin/deploy.sh` fails closed with `${BAO_KEYCLOAK_PATH:?...}`,
checked after `./.env` is loaded so either place works.

The same applies to estate topology generally: host directory layouts, backup
destinations, which host holds which key, and workstation paths do not belong
in a public repository. Architectural *reasoning* about them does, and is worth
keeping — see `docs/RECOVERY.md`.

A **full Keycloak realm export must never be committed** — it carries the
realm's signing keys and every client secret. Reconcile field by field into the
partial documents in `realm/` instead. Likewise `docker compose config`, which
interpolates the environment: only the raw compose file is ever exported or
committed.

If a secret ever lands: rotate first, scrub second. See `docs/SECRETS.md`.

## 2. `io.dotmac.field` stays disabled

The committed desired state says `"enabled": false` with zero redirect URIs, and
`policy/verify-mobile-client.jq`'s `rollout-enabled` and `rollout-redirect`
assertions are what make that a guard rather than an intention.

Enabling it is **Wave 10**, gated on (a) an exact verified App Link and
Universal Link — ADR-0069 § 7 and finding R1, both still open — and (b) the
`dotmac_sub` ID-token exchange endpoint (§ 3). Neither exists. A change that
flips `enabled` without both is wrong even if CI is green, and the
`fixture-tamper-canary` job exists to make the flip loud.

## 3. One owner per decision

- `policy/verify-realm-clients.jq` owns **which clients may exist**. It asserts
  nothing about shape.
- `policy/verify-mobile-client.jq` owns **what a native client is**.
- `policy/verify-web-client.jq` owns **what a confidential client is**.
- `bin/policy-eval.sh` is the **only** dispatcher from a policy name to a jq
  program. The offline gate and the live verifier both go through it.

Do not add a fourth place that grades a client. Do not let `bin/verify.sh` grow
its own copy of a rule — a verifier with its own rules means CI proves a policy
production does not run. Do not merge the mobile and web policies: they have
**opposite** requirements on `publicClient`, and a single file would have to
branch on class, which is how a mobile client eventually gets graded on the web
rules.

## 4. A guard must be proven to bite

Every policy assertion that matters has a fixture that is safe in every respect
except one deliberate defect, and that fixture must be **rejected for its
declared reason**. A rejection for a different reason proves nothing about the
property under test.

`tests/required-cases.tsv` is a **two-directional** ratchet: a fixture on disk
without a line fails CI, and a line without a fixture fails CI. Deleting an
inconvenient sensitivity fixture is a build failure, not a quiet loss of
coverage.

A new assertion ships with its fixture in the same change. An assertion with no
fixture is an untested claim.

## 5. An unmonitored region is named, never implied

The desired state's footprint is deliberately identical to the policy's
footprint: this repository declares exactly what it asserts. Anything it does
not assert — Keycloak builtin client shape, undeclared client fields, realm
settings beyond the three declared, database state — is an **unmonitored
region** and is listed as one in `docs/POLICY.md`.

An exemption states an enforceable premise, or the region is unmonitored rather
than exempt. Do not write a guard name that does not exist; do not imply a field
is correct merely because it is committed.

## 6. Tests run on CI, never here

No test suite, no Keycloak container, no database, no daemon on a workstation.
`jq` program compiles and `shellcheck` are static checks and are **not** test
evidence; do not report them as such. Git-hosted CI is the acceptance owner.

`bin/verify.sh` runs on the IdP host, from `bin/deploy.sh`, and nowhere else.

## 7. No host access from an agent

No SSH, scp, rsync or curl against `idp.dotmac.io` or any Dotmac host, for any
reason — including checking whether an export has landed. Host state arrives
through the owner's export into the landing zone and is reconciled file by file.

If a file on the refusal list appears in the landing zone — `.env`, a database
dump, a kcadm credential cache, a client secret, a TLS private key, an S3
credential, generated compose output, or any log carrying user or credential
data — **stop and report it**. Do not commit it.

## 8. The commit is the unit of deployment

`bin/deploy.sh` takes a full 40-character sha, refuses a dirty tree, refuses an
abbreviated sha, and refuses an unpinned image while `REQUIRE_IMAGE_DIGEST=true`.
A branch name is a moving label; "we deployed main" is not an answer to "which
policy was in force at 03:00".

A deployment is finished when `bin/verify.sh` has graded the **live** realm, not
when the containers come up.

## 9. Configuration rollback and data rollback are different operations

`bin/rollback.sh` returns the **operational files** to the last verified commit
and deliberately does **not** touch the realm database. Restoring a backup over
a live realm discards every credential change, disable and MFA enrolment since
that backup — a human decision, never a fallback a failed deployment takes on
its own. See `docs/RECOVERY.md`.

## 10. Everything by config

Every environment-specific value is an overridable knob with a documented
default: `.env.example`, `${VAR:-default}` in compose, `${VAR:?message}` where
there is no safe default, `"${VAR:-default}"` in shell. Never hardcode a host, a
port, an image tag or a path.

A value that must not be *published* has no safe default by definition, so it
takes the `${VAR:?message}` form and the message names where the operator finds
it. That is the shape every OpenBao location uses (§ 1).

## 11. The realm issuer is permanent

`https://idp.dotmac.io/realms/dotmac` is written into every
`external_identity_bindings.issuer` row in every relying party. Changing it
orphans every binding rather than renaming them. `bin/verify.sh` asserts it.

## 12. Commit messages carry no attribution trailer

No `Co-Authored-By`, no AI or model attribution, in any commit message. Absolute.

## 13. Branch, never `main`

Work on a branch. Do not commit to `main`, do not merge — the owner merges, and
only on green CI.
