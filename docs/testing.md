# Testing

Four layers. Each catches something the layer below can't.

| layer | command | needs | covers |
|---|---|---|---|
| unit | `make check` | Go | Maglev properties, config parsing, metrics, reload behaviour |
| reconciler, randomized | (part of `make check`) | Go | update ordering under random snapshots and injected failures |
| BPF, in-kernel | `make test-bpf` | Docker (macOS) or root (Linux: `make test-bpf-native`) | the real `bpf/ferry.c` against crafted packets, via `BPF_PROG_TEST_RUN`: selection, NAT, checksums, routing, flow state, pinning |
| end-to-end | `make e2e` | Docker (macOS) or root (Linux: `make e2e-native`) | the `ferry` binary forwarding real TCP/UDP connections; reload, restart, detach |

CI runs all four on every push and PR.

## Unit and randomized tests

`make check` runs everywhere, macOS included.

The key piece is `dataplane.Memory`. It is stricter than the kernel: it
rejects a table that references an inactive backend, and rejects deactivating
a backend that an installed table still references. Those are the two ways
the reconciler could misroute traffic, so any test that drives the
reconciler through `Memory` checks the ordering contract for free.

`TestApplyRandomized` (internal/controlplane) builds on that. It runs 100
seeded sequences of 30 random snapshots. Each snapshot is applied once with
5% of data plane calls failing, then again cleanly, and the result is checked
for convergence: every service serves exactly its desired backends, and no
backend is leaked or left active. A failure prints the seed and step.

## BPF tests

These load the compiled program (without attaching it) and run hand-built
Ethernet frames through it. Frames are built with valid checksums.

`internal/dataplane/xdp_linux_test.go` covers backend selection, in shadow
mode. Most of its tests are **differential**: they program identical tables
into `XDP` and `Memory`, and require the kernel to pick the backend that
`Memory` (via `Flow.Hash`, the Go mirror of `flow_hash`) predicts. That
checks the hash, the Maglev table layout and the map encodings in one go.

They also cover:

- conntrack keeps a flow's backend across a table swap, and rehashes it when
  the backend is retired;
- non-service traffic passes untouched: ARP, IPv6, ICMP, other ports and
  protocols, fragments, truncated and malformed headers;
- IP options are skipped correctly;
- the stats counters, including `NoTable`/`NoBackend`, and resetting a
  backend's counter when its ID is reused;
- `TestConstantsMatchBPF`: the map sizes in the ELF match the Go constants.
  This one needs no privileges, so it also runs in `make check` on Linux.

`internal/dataplane/nat_linux_test.go` covers forwarding. Because the
program routes with `bpf_fib_lookup`, it builds a small topology first: a
veth with static neighbors for a client, three backends and a gateway, a
dummy interface, and a blackhole route. Frames are injected as if received
on the veth. Every output frame's IP and L4 checksums are **recomputed from
scratch** and compared, which checks the incremental updates. The tests
cover:

- the forward rewrite (addresses, ports, TTL, MACs from the FIB) and that
  SNAT ports are unique per backend;
- the reverse rewrite to on-link clients and to clients behind a gateway;
- tracked flows keeping backend and port across table swaps;
- TCP state transitions, expiry, and reclaiming expired ports;
- SNAT exhaustion with a two-port pool;
- releasing a retired backend's port when its flow reselects;
- drops without leaked state for no neighbor, another interface, no route,
  and TTL 1; a zero UDP checksum staying zero; stray packets passing;
- pinned maps surviving a reload, and switching from shadow to forwarding
  on them.

Without root they skip; `make test-bpf*` sets `FERRY_REQUIRE_BPF=1` so a
skip fails instead. `BenchmarkIngressShadow` and `BenchmarkIngressForward`
report in-kernel time per tracked packet (on an M-series Mac under Docker,
about 46 ns in shadow mode and 92 ns forwarding). Use them to spot
regressions, not as line-rate figures.

## End-to-end

`test/e2e/e2e.sh` runs the real binary as a full-NAT load balancer. One
network namespace holds the client and four backend servers on a single
L2 segment, joined to the host by a veth pair. Ferry is attached to the host
end, which carries the SNAT address and the VIP, so the client ARPs for the
VIP like a LAN client would. `test/e2e/e2etool` provides the servers (TCP
and UDP, replying with their own address and the client address they saw)
and the clients. The suite runs in `xdp-generic`, then `xdp-native`:

1. attach: program visible in `ip link`, services and backends programmed;
2. ping to the host still works (non-VIP traffic is untouched);
3. 60 TCP connections and 60 UDP exchanges through the VIPs: every backend
   answers, every backend saw the SNAT address, no drops of any kind;
4. a TCP connection is opened and held, then:
   - a SIGHUP reload adds a fourth backend, and new connections use it;
   - ferry stops: the pinned program stays attached and new connections
     still work with no daemon running;
   - ferry starts again: it replaces the program in place and restores
     state, and **the held connection still reaches the same backend**;
5. a SIGHUP with a broken config is rejected; forwarding continues;
6. `ferry detach` removes the program and the pinned state.

Two veth details the script handles, neither of which applies to real NICs:
packets sent on a veth carry only a partial checksum (finished by "offload"
that native XDP bypasses), so it turns TX checksum offload off in the client
namespace; and a veth only accepts native `XDP_TX` frames if its peer has XDP
enabled, so it attaches a pass-everything program there
(`e2etool xdp-pass`).

Set `FERRY_E2E_MODES=xdp-generic` to run one mode only.

## Checking the tests can fail

When changing the harness, break the code on purpose and confirm a test
notices. These were checked when the harness was written:

| mutation | caught by |
|---|---|
| `Flow.Hash` drifts from `flow_hash` | `TestHashGolden` (all platforms), `TestSelectionMatchesMemory` |
| reconciler retires backends before swapping tables | `TestApplyRandomized` (contract violation) |
| reconciler deletes old services after adding new ones | `TestFullServiceTableCanChange` |
| e2e metric parsing broken | e2e fails on the first per-backend check |
| TTL change left out of the IP checksum | `TestForwardRewritesToBackend`, `TestReplyRewritesToClient` |
| port change left out of the L4 checksum | same |
| flows never expire | `TestExpiredFlowStartsOver`, `TestSNATExhaustion` |
| no egress-interface check | `TestUnroutableBackendsDropWithoutState` |
| reconciler ignores restored state | `TestRestoreKeepsIDs` |

## Adding tests

- A new packet-path behaviour belongs in `xdp_linux_test.go` (selection) or
  `nat_linux_test.go` (forwarding). Build the frame with `frame()` or
  `withFlags()`, compare against `Memory` where the behaviour is about
  backend choice, and decode output with `decode()`, which checks checksums.
- A new ordering rule belongs in `Memory`, as a rejected update, so every
  reconciler test enforces it.
- Keep e2e for things only the real binary and kernel stack show: real
  connections, signals, flags, attach, restart and detach, the metrics
  endpoint.
