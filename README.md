# dotmac_identity_ops

**The Git-backed owner of the Dotmac Keycloak control plane.**

The `dotmac` realm at `https://idp.dotmac.io/realms/dotmac` is the fleet's only
authentication authority (ADR-0069 § 1). Its realm *database* has been backed up
hourly, encrypted and restore-drilled for some time. Its *operational guard* —
the compose configuration, the desired client state, the policy and the verifier
— lived only in one directory on the IdP host, owned by no repository. A host replacement
would have restored every user, credential and signing key while losing the
thing that checks them, and nothing would have said so.

This repository closes that gap.

## Status

**Bootstrap.** Everything here was authored from specification and has **not**
been reconciled against the live host. Read `docs/HOST-IMPORT-TODO.md` before
treating any file as a description of what is running. No production deployment
runs from this repository during bootstrap.

`io.dotmac.field` is committed **disabled**, with no redirect URI. Enabling it is
Wave 10, gated on a verified App Link and Universal Link (ADR-0069 § 7, finding
R1) and on the `dotmac_sub` ID-token exchange endpoint (§ 3).

## Layout

```
realm/                     desired state — declarative and reviewable
  expected-clients.json      WHICH clients may exist, and their class
  clients/*.json             what each managed client must look like
  dotmac-realm.json          the realm fields this repository owns (PARTIAL)
policy/*.jq                the policy, as executable jq
bin/
  policy-eval.sh             the ONE dispatcher both halves go through
  check-policy.sh            OFFLINE gate — what CI runs
  verify.sh                  LIVE verifier — runs on the IdP host
  apply-clients.sh           push desired state into the realm
  deploy.sh                  deploy an EXACT commit, then verify
  rollback.sh                return to the last verified commit
  check-no-secrets.sh        the no-secret-values rule, made mechanical
tests/
  fixtures/                  deliberately-unsafe realms and clients
  required-cases.tsv         the fixture ratchet (two-directional)
  run-policy-tests.sh        the sensitivity proof
compose/docker-compose.yml image pin and runtime configuration
ha/                        IdP HA node templates and reviewed files (see ha/README.md)
docs/                      POLICY, SECRETS, RECOVERY, HOST-IMPORT-TODO
```

## The one idea

A policy check that passes over an empty or always-safe input passes for the
wrong reason. So the repository is built around its *sensitivity* proof rather
than around its policy:

- **`tests/fixtures/*/fail/`** holds realms and clients that are safe in every
  respect except one deliberate defect — a password grant, `plain` PKCE, a
  wildcard redirect, a confidential mobile client, a pre-rollout client quietly
  enabled, and eleven more.
- Each must be **rejected**, and rejected **for its declared reason**. A
  wildcard fixture that failed because someone typo'd its client id would prove
  nothing about wildcards.
- **`tests/required-cases.tsv`** is a two-directional ratchet: adding a fixture
  without declaring it fails CI, and so does deleting a declared one.
- The **`fixture-tamper-canary`** CI job mutates the desired state in the
  runner's workspace and asserts the gate goes red. A guard that has never
  failed in CI is a guard nobody has confirmed can fail in CI.

**A green run means unsafe fixtures were rejected — not that unsafe
configuration was accepted.**

## Two halves, one policy

`bin/check-policy.sh` runs offline in CI over committed JSON: jq and a shell, no
Keycloak, no database, no container, no network. `bin/verify.sh` runs on the IdP
host against the real realm. Both go through `bin/policy-eval.sh` into the same
`policy/*.jq` files — if the verifier kept its own copy of the rules, CI would
be proving a policy production does not run.

Full assertion list, and the stated unmonitored regions: `docs/POLICY.md`.

## Secrets

**No secret value appears in any file here, ever**, and — because this
repository is public — **no OpenBao path either**. A path is not a value, but it
is topology. Each location is a required configuration input with no default
(`BAO_KEYCLOAK_PATH` and friends); `bin/deploy.sh` fails closed when one is
unset rather than guessing. `bin/check-no-secrets.sh` enforces the value rule in
CI and carries its own sensitivity proof, including the passing case that proves
it distinguishes a reference from a value. See `docs/SECRETS.md`.

## Everything by config

Every environment-specific value is an overridable knob with a documented
default; see `.env.example`. Values with no safe default use compose's
`${VAR:?}` so an unset database password stops the deployment rather than
starting a server with a guess. The image **digest** is the real pin —
`bin/deploy.sh` refuses to deploy with `KEYCLOAK_IMAGE_DIGEST` empty while
`REQUIRE_IMAGE_DIGEST=true`, because a tag is a moving label.

## Deploying

```sh
./bin/deploy.sh <40-character commit sha>
```

The commit is the unit of deployment — not the working tree, not a branch name.
"We deployed main" is not an answer to "which policy was in force at 03:00". The
deploy refuses a dirty tree, refuses an unset `BAO_KEYCLOAK_PATH`, runs the
offline gate, reads credentials from OpenBao, checks image digests, applies the
desired state, and is finished only
when `bin/verify.sh` has graded the **live** realm. A failed verification rolls
back the operational files and never touches the database.

## Rules

See `AGENTS.md`. The short list: no secret value — and no OpenBao path — in any
file; `io.dotmac.field` stays disabled; the desired state's footprint equals the policy's footprint;
every unmonitored region is named rather than implied; tests run on CI, never on
a workstation.

## References

- `dotmac_starter_mt/docs/adr/0069-mobile-authentication-federates-to-the-existing-identity-provider.md`
- `dotmac_starter_mt/docs/inventories/mobile-application-sources.md` — findings
  R1 (no verified deep link) and R4 (the realm advertises `plain` PKCE and the
  `implicit` and `password` grants; the mitigation is per-client)
