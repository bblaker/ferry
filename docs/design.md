# Ferry design notes

Background and motivation: https://bblaker.com/projects/ferry/

## Planes

```
 discovery (static file | EndpointSlices) ──snapshot──▶ controlplane.Reconciler
   ▲ re-read on SIGHUP                                    │  maglev.Build per service
   │                                                      ▼
 cmd/ferry daemon ── /metrics, /healthz ◀──Stats── dataplane.Dataplane (interface)
                                              ├── Memory  (tests, macOS dev)
                                              └── XDP     (cilium/ebpf → bpf/ferry.c maps,
                                                           pinned under /sys/fs/bpf/ferry)
```

## BPF maps

| map              | type                | key → value                         |
|------------------|---------------------|-------------------------------------|
| `services`       | HASH                | (vip, port, proto) → service id     |
| `maglev_tables`  | ARRAY_OF_MAPS       | service id → inner ARRAY[16381] of backend id |
| `backends`       | ARRAY               | backend id → (ip, port, active)     |
| `conntrack`      | LRU_HASH            | client 5-tuple → (backend id, SNAT port) |
| `nat`            | LRU_HASH            | (backend ip, port, SNAT port, proto) → (client, VIP, TCP state, last seen) |
| `stats`, `backend_packets` | PERCPU_ARRAY | counters for Prometheus          |

The SNAT address, SNAT port range and shadow flag are `volatile const`
globals, set when the program is loaded.

## Forwarding: one-armed full NAT

Chosen over DSR because the backends are pods: full NAT needs nothing from
them. The cost is that backends see Ferry's address, not the client's.

```
client C:c ──▶ VIP:v      XDP: pick backend B:b, allocate SNAT port s
                          rewrite to  S:s ──▶ B:b, XDP_TX to next hop
backend B:b ──▶ S:s       XDP: nat[B:b, s] → (C:c, VIP:v)
                          rewrite to  VIP:v ──▶ C:c, XDP_TX to next hop
```

- **One interface.** Packets leave by the interface they arrived on
  (`XDP_TX`), and replies must come back to it, since that's where the
  program sees them. `bpf_fib_lookup` gives the next hop and its MAC. A route
  out of another interface is dropped and counted (`wrong_interface`).
- **Next hops must be resolved.** `bpf_fib_lookup` reads the neighbor table
  but can't trigger ARP, so a miss drops the packet (`no_neighbor`; the
  sender retransmits). The daemon keeps every backend's next hop resolved by
  sending it an empty UDP datagram every 30 s and after each reload. Clients
  usually ARP for the VIP first, which resolves them.
- **Routing before state.** The program routes before allocating a SNAT
  port, so an unroutable backend costs no NAT entry.
- **Checksums** are updated incrementally (RFC 1624) for the addresses,
  ports and TTL. A UDP checksum of 0 (none) stays 0. TTL is decremented, and
  packets that would reach 0 are dropped.

### SNAT ports and flow lifetime

A reply can only be matched on (backend, SNAT port), so ports only need to
be unique per backend address: the default 40000-59999 gives each backend
20000 concurrent flows. A new flow tries up to 32 random ports. A port is
free if it has no `nat` entry or its entry has expired (delete, then insert
with `BPF_NOEXIST`, so two CPUs racing for one port can't both win).

`nat` decides whether a flow is alive. Each entry records when it last saw
a packet in either direction and a state, which sets its idle timeout:

| state | entered on | TCP | UDP |
|---|---|---|---|
| new | first packet; client SYN on a reused 5-tuple | 60 s | 30 s |
| established | any backend packet | 900 s | 60 s |
| closing | FIN either way | 60 s | |
| closed | RST either way | 10 s | |

A `conntrack` hit is only used if its `nat` entry is alive and still
belongs to that client flow; otherwise the packet starts a new flow.
Expired entries are reclaimed lazily, when a new flow lands on their port,
or by LRU eviction.

### Shadow mode

With `-shadow`, the program selects and counts exactly as above but passes
every packet to the kernel unmodified and keeps no NAT state. Use it to
watch Ferry's decisions before letting it forward.

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
- Flows in `conntrack` keep their backend and SNAT port across swaps, even
  when their slot moved.
- Removed backends are marked `active=0` instead of deleted. Conntrack hits
  on them release their SNAT port and reselect through the current table;
  the new backend answers the mid-stream packet with a RST, so the client
  fails fast.
- Backend IDs go round-robin and are reused only after the allocator wraps,
  so a stale conntrack entry can't land on an unrelated backend that took
  over its ID. Flow expiry bounds how stale an entry can get.

Reconciler ordering: activate backends → delete departed services → swap
tables → retire backends. Deleting before swapping frees service IDs and
`services` map entries, so a full table can still change. Retiring last is
what keeps conntrack safe. `Memory` rejects updates that break this order,
so every reconciler test checks it (see [testing.md](testing.md)).

### When an update fails

Before changing anything, `Apply` checks the snapshot fits: no duplicate
VIPs, at most 256 services, and at most 1024 backend IDs counting the old
backends that stay active until the swap is done. A snapshot that fails
this is rejected (`ErrInvalid`) and the running tables stay whole.

Any later error comes from a map update (`ENOMEM`, say). The data plane is
then partly updated, but because of the ordering above it still routes
every flow correctly. The daemon keeps the snapshot as the desired state and
re-applies it with exponential backoff (1 s, doubling up to 1 min) until it
converges, or a newer config replaces it. A rejected reload doesn't
interrupt the retry. `ferry_config_last_reload_successful` reports whether
the latest config was accepted; `ferry_dataplane_converged` reports whether
the data plane holds it.

### Across restarts

The maps and the XDP attachment (a `bpf_link`) are pinned under
`/sys/fs/bpf/ferry/<iface>/`. When ferry stops, the program keeps forwarding
with the last tables. When it starts again it:

1. opens the pinned maps instead of creating new ones;
2. swaps its freshly loaded program into the pinned link (`BPF_LINK_UPDATE`,
   atomic per packet);
3. reads the `backends` and `services` maps back and adopts their IDs
   (`Reconciler.Restore`), so `conntrack` entries keep naming the same
   backends;
4. applies the config as usual. Tables are rebuilt, but Maglev is
   deterministic, so no slot moves.

Established connections survive restarts and upgrades. `ferry detach` is
the only way to remove the program. If a new build changes a map's layout,
loading fails with "incompatible build", and the operator chooses to
`ferry detach`, which drops tracked flows.

## Not built yet

See [todo.md](todo.md).
