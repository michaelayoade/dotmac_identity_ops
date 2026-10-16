# IdP HA node hardening

How the three-node Keycloak/Patroni layout is reproduced from Git. The decisions
(D-H1 … D-H14) and the rollout sequence live in the operator's private plan;
this page records the *mechanism* and the properties each script enforces.

Nothing here carries an address, a host layout, a secret-file location, a bucket
or any backup topology (AGENTS.md § 1). Every environment-specific value arrives
in ONE typed params document, composed and entered at ship time (a governed
operation's parameters), never hand-authored as files on a host.

## The params contract

- `ha/params.schema.json` is strict (`additionalProperties: false`, typed formats,
  enums, no defaults for topology). `ha/params.example.json` holds documentation
  ranges only. One document, one section per operation (`harden-ha`, `ha-install`,
  `patroni-sync`, `ha-backup`, `collector`, `host-check`, `verify-ha`,
  `rolling-maint`) plus a shared `node` block.
- Every script takes `--params <file|->` (or `IDPHA_PARAMS`) and validates the
  document BEFORE doing anything; a missing or invalid value, an unknown
  parameter, or an unsupported schema keyword is a refusal. The validator
  (`bin/idpha-params.py`, standard library only) fails closed on keywords and
  formats it does not know. The values are exported to the script as quoted
  shell assignments produced by the validator; the document is never sourced.
- **Secrets are never parameters.** Credentials appear only as REFERENCES
  (`*_file`: a root-600 file on the host) or are carried over on the host (the
  database credential line). The schema has no property that can hold a secret
  value, and a test enforces it.
- **Allowlists are single hosts.** `gate_allow`, `gate_extra_allow`,
  `metrics_allow` accept `/32` (IPv4) or `/128` (IPv6) only; ranges, `0.0.0.0/0`
  and the unspecified address are refused by the schema and again in the shell.
- **Gate default.** The closed gate admits the monitoring sources and loopback
  only; the operator reaches a node through an SSH tunnel to loopback. A source
  such as an office NAT is admitted only when named in `gate_extra_allow`.

### Plan, digest, apply

- `--plan` prints the effect summary as JSON on stdout (human text goes to
  stderr): per node, the ordered effects (file writes with path, mode, new and
  previous content hash; removals; commands), the hash of the tool bundle
  (script, library, validator, schema, every template) and of the params. The
  `digest` is the sha256 of that canonical document. It contains paths, modes and
  hashes, never content.
- `--apply --expect-digest <digest>` re-plans on the host and refuses if the
  digest differs (params, tool, or any pre-state hash changed since the preview).
  `--apply` without a digest is refused. The approved digest and run stamp are
  recorded in the run's backup directory.
- The params must describe the host: the node's overlay address has to be on
  the WireGuard interface, and the ufw peers have to equal `wg show endpoints`.
- Timer-run jobs (backup, collector) and read-only checks (`host-check`,
  `verify-ha`) cannot carry a per-run approval and do not take a digest. The
  weekly maintenance unit sets `IDPHA_ALLOW_UNBOUND_APPLY=1`: enabling that timer
  is the operator's standing approval for that one class of action.
- Not implemented yet: plan expiry and a host-wide lock around apply. A Starter
  governed operation should add both when it wraps these scripts.

## Properties and the code that enforces them

| Property | Where |
|---|---|
| Host firewall deny-by-default; ssh/http/https public, WireGuard transport only from the two peers, everything else on the overlay | `bin/harden-ha.sh ufw` (dead-man timer first; confirmed only after a fresh login) |
| Nothing that binds the overlay starts before it exists (the etcd boot race, repeated by keepalived) | `bin/harden-ha.sh dropins` |
| An unattended upgrade never restarts the Patroni leader, haproxy, nginx, keepalived or etcd; upgrades are staggered per node | `bin/harden-ha.sh upgrade-policy`, `bin/idpha-rolling-maint.sh` |
| Keycloak: loopback only, hostname strict, digest-pinned image, bounded logs | `ha/compose.yml.tmpl`, `ha/image.pin`, `bin/ha-install.sh compose` |
| nginx: closed by default, `/admin` 404, header parity with the single host, ACME challenge answered for any node via the peers (one hop) | `ha/nginx/*`, `bin/ha-install.sh nginx` |
| One writable authority: the IdP vhost serves only an allowlist until the cutover step swaps the gate | `bin/ha-install.sh gate closed\|open` (open needs an explicit confirmation) |
| Replication: one synchronous standby, never strict | `ha/patroni/dcs-sync.yml`, `bin/patroni-sync.sh` (refuses a degraded cluster; reads back) |
| Hourly encrypted logical backup, leader only, ciphertext validated before upload; `age` from apt, the S3 client only from a sha256 pin | `bin/ha-backup.sh`, `ha/systemd/keycloak-ha-backup.*`, `ha/tools.pin`, `ha-install.sh backup-tools` |
| Patroni, etcd-server, haproxy and keepalived are excluded from unattended upgrades and upgraded per node, after a switchover, by the weekly maintenance (timer installed disabled; an alert fires when a security update waits more than 8 days) | `bin/harden-ha.sh upgrade-policy`, `bin/idpha-rolling-maint.sh`, `ha/systemd/idpha-maint.*`, `IdpHaClusterPackageUpdateOverdue` |
| The old enabled vhosts for the same names are disabled in the same run and restored on rollback | `legacy_vhost_files`, `ha-install.sh nginx` |
| Node metrics pulled over HTTPS from the monitoring host only (source allowlist + bearer) | `bin/idpha-collect.sh`, `ha/nginx/*`, `ha/prometheus/*` |
| Drift is detectable | `bin/host-check.sh` (read-only JSON), `bin/verify-ha.sh` (the shared verifier on the HA layout) |

## Conventions every script follows

- **Dry-run by default.** `APPLY=1` or `--apply` changes things.
- **Backups and rollback.** Every file replaced is copied to a per-run backup
  directory; `ha-install.sh rollback <stamp>` restores it. A failed `nginx -t`
  restores the run automatically and does not reload.
- **Refusal on drift.** A different pre-existing drop-in, a degraded Patroni
  cluster, an existing active firewall, an unresolved template token, a malformed
  address: each stops the run.
- **No secret in output.** The database credential line is carried over verbatim
  from the node's existing compose file and never printed; the metrics bearer and
  the verifier credentials are read from root-600 files.
- **One node at a time.** Replica first, leader last. The applier does not
  coordinate nodes.

## Approved widening (Michael, 2026-10-16)

Excluding the four cluster packages from unattended upgrades trades patch latency
for not failing over the leader on a package upgrade (their maintainer scripts
restart the service whatever `needrestart` says). It is on by default
(`exclude_cluster_packages`, `upgrade_cluster_packages`), paired with the
weekly maintenance and the overdue-update alert.

## Residuals

- The verifier's long-lived client secret no longer appears on a command line in
  client mode (`verify.sh` requests a short-lived token over stdin and hands only
  the token to `kcadm`). The password mode used on the retiring single host still
  passes `--password` to `kcadm` inside the container; that predates this work.
- The S3 client (`mc`) has no verifiable public download any more (the vendor's
  site answers 410). `ha/tools.pin` is empty on purpose and `backup-tools` refuses
  until an artefact the operator has verified is pinned.
- etcd test fixtures are shaped from the 3.4 documentation, not captured from a node.

## What is not covered

The tests (`make ha-test`) use stubbed system commands. They do not prove that
nginx accepts the rendered configuration, that `ufw`, Patroni or systemd behave
as the stubs assume, or anything about a live node. Each packet's read-back
(`bin/host-check.sh`, `bin/verify-ha.sh`, `nginx -t`, `patronictl`) is the live
check.

Unconfirmed on the target: the Keycloak metric for the Infinispan view size
(`kc_cluster_size_metric`; likely `vendor_cache_manager_keycloak_cluster_size`,
confirm at H5.0). In 26.0.8 the management interface follows `KC_HTTP_HOST`, so
`host-check.sh` FAILS a wildcard 9000 while Keycloak runs. The dump flags must
equal the single host's (`--no-owner --clean --if-exists`); `pgdump_format_args`
has no default on purpose.
