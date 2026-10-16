Fixtures are REAL command output captured read-only from the running nodes (etcd 3.4.30
`endpoint {health,status} --cluster -w json`, Patroni 3.2.2 `/cluster` and `patronictl list -f tsv`,
needrestart 3.6 `-b -r l`, `wg show wg0 endpoints`), then MASKED for this public repository:
addresses -> RFC 5737 ranges, node names -> node-N, cluster name -> example-cluster, etcd member and
cluster ids -> made-up numbers (the leader/member id relationship is preserved), WireGuard public keys ->
KEYA/KEYB. Shapes, field names and value types are untouched. The stubs in lib.sh reject `-w tsv`
exactly as etcd 3.4.30 does.
