# Testing

Four layers. Each catches something the layer below can't.

| layer | command | needs | covers |
|---|---|---|---|
| unit | `make check` | Go | Maglev properties, config parsing, metrics, reload behaviour |
| reconciler, randomized | (part of `make check`) | Go | update ordering under random snapshots and injected failures |
| BPF, in-kernel | `make test-bpf` | Docker (macOS) or root (Linux: `make test-bpf-native`) | the real `bpf/ferry.c` against crafted packets, via `BPF_PROG_TEST_RUN` |
| end-to-end | `make e2e` | Docker (macOS) or root (Linux: `make e2e-native`) | the `ferry` binary on a veth pair: attach, steer, reload, detach |

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

`internal/dataplane/xdp_linux_test.go` loads the compiled program (without
attaching it) and runs hand-built Ethernet frames through it. Most tests are
**differential**: they program identical tables into `XDP` and `Memory`, and
require the kernel to pick the backend that `Memory` (via `Flow.Hash`, the Go
mirror of `flow_hash`) predicts. That checks the hash, the Maglev table
layout and the map encodings in one go.

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

Without root they skip; `make test-bpf*` sets `FERRY_REQUIRE_BPF=1` so a
skip fails instead. `BenchmarkIngress` reports in-kernel time per tracked
packet (about 45 ns on an M-series Mac under Docker). Use it to spot
regressions, not as a line-rate figure.

## End-to-end

`test/e2e/e2e.sh` builds the binary, creates a client network namespace
joined to the host by a veth pair, starts `ferry attach` on the host end, and
asserts on `/metrics`. It runs the whole suite in `xdp-generic` and then
`xdp-native` (veth supports both):

1. attach: program visible in `ip link`, services and backends programmed;
2. ping to the host still works and isn't counted (shadow mode is transparent);
3. 100 UDP and 40 TCP flows to the VIPs: every backend gets traffic, and
   per-backend counts add up to service hits;
4. SIGHUP after a config edit: old backends retired, new flows go to the new
   backend;
5. SIGHUP with a broken config: rejected, tables unchanged, still steering;
6. SIGTERM: process exits 0 and the XDP program is gone from the interface.

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

## Adding tests

- A new packet-path behaviour belongs in `xdp_linux_test.go`. Build the frame
  with `frame()`, and compare against `Memory` where the behaviour is about
  backend choice.
- A new ordering rule belongs in `Memory`, as a rejected update, so every
  reconciler test enforces it.
- Keep e2e for things only the real binary shows: signals, flags, attach and
  detach, the metrics endpoint.
