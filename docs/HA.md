# IdP HA node hardening

How the three-node Keycloak/Patroni layout is reproduced from Git. The decisions
(D-H1 … D-H14) and the rollout sequence live in the operator's private plan;
this page records the *mechanism* and the properties each script enforces.

Nothing here carries an address, a host layout, a secret-file location, a bucket
or any backup topology (AGENTS.md § 1). Each is a required private value — see
`ha/idpha.env.example` for the names.

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
| Hourly encrypted logical backup, leader only, ciphertext validated before upload | `bin/ha-backup.sh`, `ha/systemd/keycloak-ha-backup.*` |
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

## What is not covered

The tests (`make ha-test`) use stubbed system commands. They do not prove that
nginx accepts the rendered configuration, that `ufw`, Patroni or systemd behave
as the stubs assume, or anything about a live node. Each packet's read-back
(`bin/host-check.sh`, `bin/verify-ha.sh`, `nginx -t`, `patronictl`) is the live
check.

Unconfirmed on the target and flagged in code: the Keycloak metric that carries
the Infinispan view size (`KC_CLUSTER_SIZE_METRIC`), whether the management
interface follows `KC_HTTP_HOST` in 26.0.8 (`host-check.sh` treats a wildcard
9000 as contained-by-ufw, not clean), and the exact dump flags of the
single-host backup (`PGDUMP_FORMAT_ARGS` has no default on purpose).
