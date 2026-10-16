etcd fixtures: the JSON shape that `etcdctl endpoint {health,status} --cluster -w json` prints on
etcd 3.4.x, written from the 3.4 documentation with documentation-range addresses and made-up ids.
They are NOT captured from a live node (this build touches no host). The stubs in lib.sh REJECT
`-w tsv` exactly as 3.4.30 does ("unsupported output format"), which is the defect the first
version of the collector had. Replace with a recorded capture when one exists.
