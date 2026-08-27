# What CI enforces, and what it deliberately does not

Two documents matter for reading this repository: this one, which says what is
guarded, and `docs/HOST-IMPORT-TODO.md`, which says what has not yet been
compared with reality.

## The shape of the guard

```
realm/expected-clients.json ──┐
realm/clients/*.json ─────────┤
realm/dotmac-realm.json ──────┘  the desired state (declarative, reviewable)

policy/verify-realm-clients.jq   which clients may exist    (inventory)
policy/verify-mobile-client.jq   what a native client is    (shape)
policy/verify-web-client.jq      what a confidential client is (shape)

bin/policy-eval.sh               the ONE dispatcher both halves go through
   ├── bin/check-policy.sh       OFFLINE  — CI, over committed JSON
   └── bin/verify.sh             LIVE     — the IdP host, over the real realm
```

The dispatcher exists so the two halves cannot drift. If the live verifier
carried its own copy of the rules, CI would be proving a policy production does
not run.

## The assertions

Each row names the failure code the policy emits. A sensitivity fixture must be
rejected with that exact code — a rejection for a different reason proves
nothing about the property under test.

### Inventory — `policy/verify-realm-clients.jq`

| Code | Assertion |
|---|---|
| `inventory-unknown` | a client exists in the realm that `realm/expected-clients.json` does not declare. An undeclared client is an unreviewed authorization surface, and no shape policy runs over a client the repository does not know exists |
| `inventory-missing` | a declared client is absent from the realm. Not a safe state: the desired state and the realm have diverged and nothing is asserting the pins any more |
| `inventory-duplicate` | one client id is registered more than once. An authorization request may then be served by whichever object the lookup returns, and only one of them was reviewed |
| `inventory-empty` | the realm reported no clients at all — an unreachable admin API, a wrong realm name, or a jq path that silently produced nothing. Treated as a failure by construction |
| `manifest` | the manifest itself is unusable: empty, missing a `clientId`, or declaring one twice |
| `manifest-class` | a managed client declares a class no shape policy owns |
| `manifest-builtin` | a client carrying a Dotmac identity is declared a Keycloak builtin, which would make it shape-exempt |

### Native mobile client — `policy/verify-mobile-client.jq`

| Code | Assertion | Ground |
|---|---|---|
| `public` | `publicClient == true` | ADR-0069 § 4. A secret in a downloadable artifact is readable by anyone who downloads it |
| `public-secret` | no `secret` field present | same |
| `bearer-only` | `bearerOnly == false` | |
| `flow-standard` | Authorization Code enabled | ADR-0069 § 2 |
| `flow-implicit` | implicit **disabled** | § 4. Implicit returns tokens in a redirect the OS may log |
| `flow-direct-grant` | password grant **disabled** | § 4. It reintroduces the credential-entry surface federation exists to remove |
| `flow-service-account` | service accounts **disabled** | |
| `flow-authz-services` | authorization services **disabled** | |
| `flow-device` | device authorization grant **disabled** | Authorization Code must be the *only* interactive flow, and Keycloak has more grant toggles than the four obvious ones |
| `flow-ciba` | CIBA grant **disabled** | same |
| `pkce` | `pkce.code.challenge.method == "S256"`, exactly | § 4 and finding R4. The **realm** advertises `["plain","S256"]`; a client-side preference is not a control, the server must refuse `plain` for this client. An **absent** pin fails as loudly as an explicit `plain` |
| `id-token-alg` | `id.token.signed.response.alg == "RS256"` | Keycloak advertises HS-family algorithms; the pin stops negotiation drift from emitting one |
| `access-token-alg` | access-token algorithm, when set, is asymmetric | |
| `full-scope` | `fullScopeAllowed == false` | § 5. IdP roles never grant product permissions |
| `web-origins` | `webOrigins == []` | a native client has no browser origin |
| `redirect-wildcard` | no redirect URI contains `*` | § 2 |
| `post-logout-wildcard` | `post.logout.redirect.uris` contains no `*` | |
| `redirect-unverified-scheme` | every redirect is `https` (App Link / Universal Link) or loopback | § 7 and finding R1. Any application on the device may claim a custom scheme and receive the authorization code |
| `redirect-set` | the registered set **equals** the declared set | exactness alone is not enough; an extra exact redirect nobody reviewed is still unreviewed |
| `rollout-enabled` | `enabled` matches the desired state | § 7. `io.dotmac.field` is disabled pre-rollout; enabling it is Wave 10 |
| `rollout-redirect` | a disabled client registers **no** redirect; an enabled one registers at least one | a staged redirect on a pre-rollout client is one `enabled=true` from a live ceremony |

### Confidential web client — `policy/verify-web-client.jq`

`confidential` (must **not** be public), `flow-standard`, `flow-implicit`,
`flow-direct-grant`, `flow-service-account`, `pkce`, `id-token-alg`,
`redirect-wildcard`, `redirect-scheme` (absolute https), `redirect-set`,
`rollout-enabled`.

This is a separate file from the mobile policy on purpose. The two classes have
**opposite** requirements on `publicClient`, and one file asserting both would
have to branch on class — which is how a mobile client eventually gets graded
on the web rules.

### Live-only assertions — `bin/verify.sh`

Not reachable offline, so CI cannot run them:

- both containers running
- the realm's declared fields (`sslRequired`, `bruteForceProtected`, `enabled`)
- discovery serves the **permanent** issuer. Changing the issuer orphans every
  `external_identity_bindings.issuer` row in every relying party rather than
  renaming them
- JWKS advertises an RS256 key
- a client declared disabled actually answers **HTTP 400** at the authorization
  endpoint. Configuration is a claim; the endpoint's answer is the evidence

## What a green CI run means

**Unsafe fixtures were rejected, each for its declared reason.** It does not
mean unsafe configuration was accepted into the desired state.

A policy check that passes over an empty or always-safe input passes for the
wrong reason, so the harness fails when:

- a `fail/` fixture is **accepted**
- a `fail/` fixture is rejected for a **different** reason than declared
- a `pass/` fixture is rejected (a policy that rejects everything is not a
  working guard either)
- the fixture set on disk and `tests/required-cases.tsv` disagree, in **either**
  direction — deleting an inconvenient fixture is a CI failure, not a quiet
  loss of coverage
- any of the four rejections this wave was commissioned to prove
  (`flow-direct-grant`, `pkce`, `redirect-wildcard`, `public`) has no fixture
- fewer than 16 rejections or zero acceptances were proven

The `fixture-tamper-canary` job goes further: it mutates the desired state **in
the runner's workspace** and asserts the gate goes red for the right reason. A
guard that has never failed in CI is a guard nobody has confirmed can fail in
CI.

## Unmonitored regions — stated, not exempted

An exemption states an enforceable premise, or the region is unmonitored rather
than exempt. These are unmonitored, and naming them is the point:

1. **Keycloak builtin clients** (`account`, `account-console`, `admin-cli`,
   `broker`, `realm-management`, `security-admin-console`) are checked for
   presence only. Their shape is Keycloak's, not ours — `admin-cli` ships with
   direct access grants enabled *by product design*, and asserting our mobile
   shape over it would be asserting a property we do not own. The boundary is
   enforced from the other side: `manifest-builtin` fails if a client carrying a
   Dotmac identity is declared a builtin.

2. **Client fields this repository does not declare** — `defaultClientScopes`,
   `optionalClientScopes`, protocol mappers, and every attribute not named in
   the policy. The desired state's footprint is deliberately identical to the
   policy's footprint, so nothing is implied to be correct merely by being
   committed. Narrowing this region is item 5 of `docs/HOST-IMPORT-TODO.md`.

3. **Realm settings beyond the three declared fields.** Same reasoning.

4. **Users, credentials, MFA enrolments, sessions and signing keys.** These are
   database state, not configuration. They are covered by the backup regime
   (`docs/RECOVERY.md`), never by this repository.

5. **Everything on the live host that has not been reconciled yet.** The whole
   of `docs/HOST-IMPORT-TODO.md`. Until that document is deleted, this
   repository describes what the realm *must* look like and not what it *does*.
