# Cluster overlay network

The three HA nodes reach each other over a **WireGuard mesh on `10.10.0.0/24`**,
carried by their public IPs — not over the provider's private network.

## Why not the provider private network

Two reasons, one measured and one structural.

**Measured.** Round-trip between two nodes, 20 packets each:

| path | avg | jitter (mdev) | max |
|---|---|---|---|
| provider private segment | 0.489 ms | 0.442 | 2.361 |
| public IP, no encryption | 0.419 ms | 0.181 | 1.138 |
| WireGuard overlay | ~0.87 ms | 0.10–0.21 | ≤1.49 |

Encryption costs about 0.4 ms of average latency and *improves* jitter and
worst case against the private segment. For etcd that is the right trade:
leader elections are triggered by outliers, not by the mean.

**Structural.** The private segment is unencrypted. Patroni streaming
replication and etcd peer traffic would cross it in clear. WireGuard also
authenticates peers by key rather than trusting whatever is on the segment, and
does not depend on provider provisioning — which, at the time of writing, was
failing to present a private vNIC to three of six member instances despite
identical configuration to those that worked.

## Addressing

`10.10.0.0/24` is deliberately NOT `10.0.0.0/22`, so the overlay cannot collide
with provider-assigned private addresses if that provisioning is ever repaired.

| node | overlay |
|---|---|
| idp-ha-1 | 10.10.0.1 |
| idp-ha-2 | 10.10.0.2 |
| idp-ha-3 | 10.10.0.3 |

## Rules

- Bind etcd (client + peer), the Patroni REST API, PostgreSQL and the Keycloak
  cache transport to the overlay address only. **An exposed Patroni REST API
  accepts an unauthenticated failover request** — a public bind is a one-call
  cluster takeover.
- Private keys are generated on the node with `umask 077` and never leave it.
  Only public keys are exchanged.
- `wg-quick@wg0` is enabled, so the mesh returns after a reboot. Verify with
  `wg show wg0 latest-handshakes` — a peer with handshake 0 is not connected,
  and an interface being "up" does not mean the mesh is formed.
