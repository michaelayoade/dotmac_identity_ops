# Pre-push checklist — bootstrap push

Recorded for the first push of this repository, 2026-08-27. Two items are
**PENDING** and were not faked, assumed, or quietly skipped.

| # | Item | Result |
|---|---|---|
| 1 | Secret scanner over every file | **PASS** |
| 2 | Explicit search for passwords, tokens, private keys, credentials, substituted env values | **PASS** |
| 3 | Only OpenBao paths appear, never a value | **PASS** |
| 4 | Compare desired state against the live non-secret client projection | **PENDING** |
| 5 | Confirm the malicious fixtures are rejected | **PASS (static)** — see the note |
| 6 | Confirm this repository reproduces the live verifier's successful result | **PENDING** |
| 7 | Manual file-by-file review of the staged diff | **PASS** |

## 1 — secret scanner

No `gitleaks`, `trufflehog`, `detect-secrets` or `ggshield` is installed on this
workstation, and installing one was not attempted. The tool used was this
repository's own `bin/check-no-secrets.sh`, which is referential rather than
entropic: a secret-named key must be assigned an OpenBao path, an unexpanded
`${VAR}`, empty, or null — never a literal.

Two false positives were found and **fixed**, because a scanner with false
positives is a scanner someone eventually switches off:

- it scanned `.git` and flagged a stock git hook sample. BSD `grep` does not
  permute arguments the way GNU `grep` does, so a trailing `--exclude-dir=.git`
  was being read as another *path* and excluded nothing. Flags now precede the
  path.
- it read jq's `.secret == null` as an assignment of the literal `=`. `=` is now
  excluded from the first value character.

Two real gaps were also found and fixed while confirming the above:

- the rule was **case-sensitive**, so an uppercase `KEYCLOAK_ADMIN_PASSWORD`
  assigned a literal — the single most likely way this rule gets broken — would
  not have been caught. (This sentence is deliberately phrased to avoid writing
  the pattern out: the scanner correctly flagged the first draft of it, which is
  a small live demonstration that the guard bites.)
- the scanner's own self-test fixtures were written as literals in its source,
  so it flagged itself. Keys and values in the self-test are now assembled at
  runtime; the file contains no line it would match.

## 2 — independent sweep

A separate grep pass over every file, with **no allowlist applied**, for: PEM
blocks, any `password|passwd|pwd|secret|token|api_key|access_key|private_key|
credential` assigned a non-reference value (case-insensitive), AWS-shaped access
key ids, base64-ish runs of 40+ characters, and the presence of `.env`, `*.dump`,
`*.sql`, `*.pem`, `*.key`, `*.p12`, `*.jks`, `kcadm.config`, `*.age`.

Every hit was one of: a `${VAR}` reference, an OpenBao path, a scanner's own
search pattern, or the literal string `PLACEHOLDER-NOT-A-SECRET` in the
confidential-client sensitivity fixture. No secret value is present.

## 3 — OpenBao references only

At the time of the bootstrap push, three OpenBao **paths** were referenced and
no values. When the repository was opened to the public those paths were
removed too — a path is not a value, but it is topology — and replaced with
required configuration variables carrying no defaults:

- `BAO_KEYCLOAK_PATH` — consumed by `bin/deploy.sh`, which refuses to run while
  it is unset
- `BAO_WORKSPACE_OIDC_PATH` — named so nobody looks for the workspace client
  secret here; **read by nothing in this repository**
- `BAO_IDP_HOST_PATH` — host access; used by no script here

The operator's private runbook maps each variable to its location. See
`docs/SECRETS.md`.

## 4 — compare against the live client projection: **PENDING**

No export has arrived. The owner's landing zone contained only the owner's own
`README.md` and `export-from-idp.sh`, and none of the allowlisted files. No SSH,
scp, rsync or curl was attempted against any host.

Everything in `realm/` is therefore authored from ADR-0069 and the recorded
operational facts, and is **not** a verified description of the live realm. Every
manifest entry carries `"provenance": "authored-from-spec"` and
`"reconciled_from_host_at": null`. `docs/HOST-IMPORT-TODO.md` names each file and
what specifically must be compared.

## 5 — malicious fixtures are rejected: PASS, statically

**Confirmed without executing the harness.** The owner's standing rule is that
tests run only on Git-hosted CI, and the instruction restated it as unchanged;
naming a gate is not a grant to run it here. So:

- all 23 declared rejection codes were confirmed to exist as codes the owning
  policy can actually emit — a fixture cannot be rejected for a reason no policy
  emits
- every `fail/` fixture was diffed against its hardened baseline and differs by
  exactly **one** logical field, so each proves the property it is named for
- the ratchet (`tests/required-cases.tsv`) and the fixture tree were confirmed
  to list the same 27 files

**Execution is CI's job**, and the pushed run is the evidence. If a fixture is
not in fact rejected, the `sensitivity` job goes red — which is the correct
place for that to be discovered, and is information rather than damage.

## 6 — reproduce the live verifier's result: **PENDING**

Blocked on the same missing export as item 4, and additionally on running
`bin/verify.sh`, which needs a real Keycloak. No container, database or daemon
was started on this workstation.

The IdP host's own verifier is recorded as checking **14** realm/client
invariants. The two assertion lists have **not** been diffed. Any invariant the
host checks and this repository does not would be a regression introduced by
adopting this repository — the opposite of the point. That diff is item 2 of
`docs/HOST-IMPORT-TODO.md`.

## 7 — manual review

Every file read before staging. No generated output was committed unreviewed;
the fixtures were produced with `jq` from the hardened baselines and then read
individually.

## Bottom line

**The push proceeded with items 4 and 6 outstanding**, on the basis that items
1, 2, 3, 5 and 7 pass, that no production deployment runs from this repository
during bootstrap, and that a repository nobody can push is the same host-only
durability problem this wave exists to fix.

---

## Post-push: CI has NOT executed

**Recorded 2026-08-27, immediately after the first push.**

The `keycloak-policy` workflow was scheduled and all three jobs were created —
so the workflow file parses and the job graph resolves — but **every job was
refused a runner** before starting, for an account-level reason unrelated to
this repository. GitHub Actions minutes are billed on **private** repositories;
the other Dotmac repositories run CI at no cost because they are **public**,
and this one was created private on instruction.

**Consequence, stated plainly: the sensitivity proof in this repository had
never been executed anywhere.** Item 5 of the checklist above was a *static*
confirmation, and the acceptance owner had accepted nothing. Until a run went
green, nothing here was proven — only reviewed.

## Resolution: the repository was opened

Making it public was a **security** decision, not a billing one, and it was
taken deliberately rather than as a side effect. The repository named the
realm's client ids, its redirect targets, the IdP hostname, the OpenBao paths
and the host's operational layout. None of that is a secret *value*; some of it
is reconnaissance and some of it is not, and the two were separated rather than
lumped together:

**Stayed.** The IdP hostname — already public DNS serving a public OIDC
discovery document. The client ids — a public native client transmits its id in
a browser URL by design. The realm desired state, the policy and the whole
fixture set — publishing a provably hardened posture is the point of this
repository, and gutting the fixtures would have destroyed the sensitivity proof
that makes a green run mean anything.

**Left.** The OpenBao paths, replaced by required configuration variables with
no defaults (§ 3 above). The recovery and backup topology in
`docs/RECOVERY.md` — which host holds the backup decryption key and the
read-only restore identity, and how the object-store credentials are split —
replaced by a pointer to the operator's private runbook; the document keeps its architectural reasoning,
which discloses nothing exploitable. The host-side operational directory path
and the owner's workstation landing-zone path, generalized.

No production deployment ran from this repository during bootstrap, so the
period with blocked CI was a delay rather than an exposure.
