# Ferry design notes

Background and motivation: https://bblaker.com/projects/ferry/

## Planes

```
 discovery (static file | EndpointSlices) ──snapshot──▶ controlplane.Reconciler
                                                          │  maglev.Build per service
                                                          ▼
                                              dataplane.Dataplane (interface)
                                              ├── Memory  (tests, macOS dev)
                                              └── XDP     (cilium/ebpf → bpf/ferry.c maps)
```

## BPF maps

| map              | type                | key → value                         |
|------------------|---------------------|-------------------------------------|
| `services`       | HASH                | (vip, port, proto) → service id     |
| `maglev_tables`  | ARRAY_OF_MAPS       | service id → inner ARRAY[16381] of backend id |
| `backends`       | ARRAY               | backend id → (ip, port, active)     |
| `conntrack`      | LRU_HASH            | 5-tuple → (backend id, last seen)   |
| `stats`, `backend_packets` | PERCPU_ARRAY | counters for Prometheus          |

## Atomic table swaps

The post called this the least-certain part. Ferry uses `ARRAY_OF_MAPS`
from the start rather than as a fallback:

1. Create a fresh inner array, fill it with one batch update.
2. One `bpf_map_update_elem` on `maglev_tables[service id]` swaps the pointer.
3. Packets already holding the old inner map finish with it (RCU), and the
   kernel frees it once the last reference is gone.

So readers see the old table or the new one, never a partially written one.
This costs one extra map lookup per new flow; tracked flows skip it.

## Connection continuity

- Maglev moves about 1/N of the slots when a backend changes. With 10
  backends, removing one moved 72 slots besides the removed backend's own
  1638 (see `TestRemovalDisruption`).
- Flows in `conntrack` keep their backend across swaps, even when their slot
  moved.
- Removed backends are marked `active=0` instead of deleted. Conntrack hits
  on them reselect through the current table.
- Backend IDs go round-robin and are reused only after the allocator wraps,
  so a stale conntrack entry can't land on an unrelated backend that took
  over its ID.

Reconciler ordering: activate backends → swap tables → delete services →
retire backends.

## Next decision: forwarding mode

`ferry_ingress` currently picks and counts a backend, then returns `XDP_PASS`
(shadow mode). Before writing the rewrite, choose a mode:

- **Full NAT (recommended for pi-tower).** DNAT to the backend and SNAT to
  the node, then `bpf_fib_lookup` + `bpf_redirect`. Backends need no changes,
  which matters because they are pods. Return traffic comes back through
  Ferry and needs a reverse-NAT entry plus an XDP/TC hook on the return path.
- **DSR with IPIP (Katran style).** Faster for responses, but every backend
  must decapsulate and own the VIP. That is awkward for pods.

## Not built yet

- Kubernetes EndpointSlice source (`internal/discovery`)
- Active and passive health checks that feed discovery
- gRPC/protobuf control API, Prometheus exporter for `stats`
- L7 / `crypto/tls` termination path
- IPv6, conntrack expiry on TCP FIN/RST, weighted Maglev
