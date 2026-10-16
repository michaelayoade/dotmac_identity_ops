# ha/ — IdP HA node artefacts

Templates and reviewed files for the three-node Keycloak/Patroni layout. Nothing
here is applied by CI; the scripts in `bin/` render and install them **on a node,
as root, dry-run by default** (`APPLY=1` or `--apply`). No environment-specific
value is committed: they arrive in one typed params document (`params.schema.json`;
`params.example.json` shows the shape with documentation ranges). Each script takes
`--params`, validates first, prints `--plan` JSON with a digest, and `--apply` must
carry `--expect-digest`.

| Path | What | Installed by |
|---|---|---|
| `image.pin` | the digest-pinned Keycloak image (reviewed change to alter) | `bin/ha-install.sh compose` |
| `compose.yml.tmpl` | loopback-only Keycloak, hostname strict, json-file logging | `bin/ha-install.sh compose` |
| `nginx/*` | closed-by-default vhosts, `/admin` 404, header parity, ACME peer fallback, gate, metrics endpoint | `bin/ha-install.sh nginx\|gate\|metrics-token` |
| `patroni/dcs-sync.yml` | the reviewed DCS patch (sync mode, not strict, one sync standby) | `bin/patroni-sync.sh` |
| `systemd/*` | hourly leader-only backup, 30 s metrics collector, weekly maintenance (all timers installed disabled) | `bin/ha-install.sh units` |
| `tools.pin` | sha256 pin of the S3 client (empty until a verified artefact is chosen) | `bin/ha-install.sh backup-tools` |
| `params.schema.json`, `params.example.json` | the typed params contract | every script |
| `prometheus/*` | scrape job template + alert rules | the monitoring host's operator |

Scripts: `harden-ha.sh` (ufw behind a dead-man timer, boot-ordering and restart
drop-ins, needrestart list-only, staggered apt timer), `ha-install.sh`,
`patroni-sync.sh`, `ha-backup.sh`, `idpha-collect.sh`, `idpha-rolling-maint.sh`,
`host-check.sh`, `verify-ha.sh` (the shared `verify.sh` mapped onto the HA layout).

Offline tests: `make ha-test` (`tests/ha/run-ha-tests.sh`). They use stubbed
system commands and a temporary root; they prove behaviour of the scripts, **not**
of any host.

Placeholders use RFC 5737 documentation ranges only.
