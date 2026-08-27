# Recovery

Two things can be lost independently, and conflating them is how a recovery goes
wrong. **The realm database** holds users, credentials, MFA enrolments, sessions
and signing keys. **The operational files** hold the compose configuration, the
desired state, the policy and the verifier. Different owners, different media,
different failure modes, different restore procedures.

Until this repository existed, only the first was protected. A host replacement
would have restored every user, credential and signing key while losing the
thing that checks them — the realm would come back and its guard would not, and
nothing would have said so.

|  | Realm database | Operational files |
|---|---|---|
| Owner | Postgres on the IdP host | this repository |
| Protection | hourly `pg_dump`, encrypted at rest, off-host, WORM-retained | git |
| Restore proven by | weekly automated semantic restore; quarterly whole-host exercise | `bin/check-policy.sh` on every push |
| RPO / RTO | 1 hour / 4 hours | minutes, from any clone |
| Restoring is | **destructive** — discards every change since the backup | safe and repeatable |

## Restoring the operational files

From any clone, with no host access:

```sh
git clone <this repository> && cd dotmac_identity_ops
git checkout <the commit deploy-log.tsv records as `verified`>
./bin/check-policy.sh          # offline; proves the policy before it is applied
```

Then, on the IdP host, with the environment knobs set (`.env.example`):

```sh
./bin/deploy.sh <that same 40-character commit>
```

`bin/deploy.sh` refuses a dirty tree, refuses an abbreviated sha, refuses an
unpinned image while `REQUIRE_IMAGE_DIGEST=true`, applies the desired state, and
then runs `bin/verify.sh` against the **live** realm. A deployment is not
finished when the containers come up; it is finished when the live realm has
been graded against the committed policy.

## Restoring the realm database

**This is destructive and it is a human decision.** Restoring a backup over a
live realm silently discards every credential change, account disable, MFA
enrolment and signing-key transition made since that backup was taken. Nothing
in this repository does it automatically, and `bin/rollback.sh` deliberately
refuses to: a failed *configuration* deployment must never take a *data*
recovery path on its own.

### Where the topology is written down — deliberately not here

This repository is public. **Where the decryption key lives, which identity may
read the backups, and where the objects are stored are all recorded in the
operator's private runbook and nowhere in this tree.** So are the restore steps
themselves. That is not modesty about the design; it is that a backup regime's
*location* is the part an attacker can use, and a public repository is a poor
place to keep it. The backup script, its systemd units and the restore
procedure are still unreconciled host artefacts — `docs/HOST-IMPORT-TODO.md`
item 9.

What is worth stating publicly is how the regime is *judged*, because that is
reasoning rather than topology and it is the part that is easy to get wrong:

- **Freshness means the newest *validated* backup, not the newest object.** An
  object landing in a bucket proves an upload happened, not that anything can be
  restored from it. The validator decrypts, restores into a throwaway container,
  and asserts the realm, client, redirect URI and RS256 invariants before it
  advances the `last-valid` timestamp — and it walks **backwards** through
  versions when a candidate fails, so one bad upload does not page anybody and a
  run of them does.
- **The weekly drill recovers a working IdP, not a database.** It starts a real
  Keycloak against the restored dump, on a private network, with the permanent
  `KC_HOSTNAME`, and asserts that discovery serves the permanent issuer with an
  RS256 key in JWKS. `pg_restore` exiting is not evidence that anyone can log
  in. First run: 38 seconds.

Checking the **issuer** matters more than it looks, and it is why the drill
asserts discovery rather than row counts. A restore that produced a different
issuer would orphan every `external_identity_bindings` row in every relying
party rather than renaming them — the bindings would not move, they would stop
matching. The issuer is permanent.

### Order of operations for a whole-host recovery

1. **Rebuild the host and restore the database first**, per the operator's
   private runbook. A verifier has nothing to verify against an empty realm.
2. **Deploy the operational files from a recorded commit** (above).
3. **Run `bin/verify.sh`.** This is the step that did not exist before this
   repository: it proves the restored realm still satisfies the policy, rather
   than merely that Postgres started.
4. Expect the client inventory to be the first thing that disagrees, and treat
   that as the guard working. Reconcile per `docs/HOST-IMPORT-TODO.md`.
5. One real login, then declare the RTO met. `pg_restore` exiting is not
   recovery.

## What is still single-homed

The IdP is **one host with a 4-hour RTO**. An outage prevents new login
ceremonies; already-issued product sessions continue until their own expiry and
revocation rules refuse them. That asymmetry is exactly what ADR-0069 § 6 relies
on to make the staged rollout safe — a bounded field workforce can hold existing
sessions through an outage, a subscriber base cannot — and it is why customer
self-care is gated on Keycloak HA rather than on a date.
