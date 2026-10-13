# Remaining work

Ordered by what blocks what. "Shadow mode" means the current state:
selection, conntrack and counters work end to end, but every packet is
passed to the kernel unchanged.

## Before forwarding real traffic

1. **Choose the forwarding mode and implement it.** This is the open
   decision in [design.md](design.md#next-decision-forwarding-mode). Full NAT
   is the recommendation for pi-tower. It needs DNAT + SNAT, checksum
   updates, `bpf_fib_lookup` + `bpf_redirect`, and a reverse-NAT map with an
   XDP/TC hook on the return path. Extend the e2e test with a backend
   namespace that actually answers, and assert on end-to-end connections
   rather than counters.
2. **Pin maps and the link under `/sys/fs/bpf`.** A restart today recreates
   every map, so conntrack is lost and tracked flows are rehashed. That is
   harmless in shadow mode but breaks connections once forwarding is on.
   Pinning also makes zero-downtime binary upgrades possible. The systemd unit
   will need `ReadWritePaths=/sys/fs/bpf/ferry`.
3. **Conntrack expiry.** `last_seen_ns` is written but never read, so
   entries only leave through LRU eviction. Add idle timeouts (in the program
   or a userspace sweeper) and drop entries on TCP FIN/RST. This also bounds
   a latent hazard: backend IDs are reused once the allocator wraps (1024
   allocations), and an old enough entry could then land on an unrelated
   backend.
4. **Retry partial reload failures.** If a map update fails partway through
   `Apply`, the data plane stays partly updated until the next SIGHUP. Retry
   with backoff, and expose "converged" separately from "last reload OK".
5. **Validate on the real Pi.** Confirm native XDP on the target NIC/driver,
   run the hardened `deploy/ferry.service` on Raspberry Pi OS (it has only
   passed `systemd-analyze verify` and a capability test in Docker so far),
   and measure throughput with real traffic (pktgen or TRex).

## Features

6. Kubernetes EndpointSlice discovery source (`internal/discovery`).
7. Active and passive health checks feeding discovery.
8. gRPC/protobuf control API (today: config file + SIGHUP).
9. Per-service counters. Today there are only global and per-backend ones.
10. IPv6, VLAN-tagged frames, weighted Maglev.
11. L7 / `crypto/tls` termination path.
12. Optional: watch the config file and reload on change, instead of
    relying on `systemctl reload`.

## Design questions surfaced by review

13. **Backends shared across services.** A backend is identified by
    `ip:port` globally. If one is removed from service A but still used by
    service B, it stays active, so A's tracked flows keep going to it. Decide
    whether conntrack hits should also check the backend is still in the
    flow's service.
14. **Backend capacity headroom.** New backends are activated before old
    ones are retired, so one reload must fit old and new backends together
    in 1024 IDs. Replacing a near-full set needs two steps. Document this or
    stage it automatically.

## Engineering hygiene

15. Run the new CI steps (`test-bpf-native`, `e2e-native`) on GitHub. They
    pass locally in Docker (Linux 6.10, arm64) but haven't run on GitHub's
    runners yet. Consider an `ubuntu-24.04-arm` job so CI matches the Pi's
    architecture.
16. Add `staticcheck` or `golangci-lint` to `make check`.
17. Fuzz the packet parser: random frames through `BPF_PROG_TEST_RUN`,
    asserting `XDP_PASS` and no unexpected counter movement.
18. Release process: tagged versions (`ferry version` already reports a
    module version or VCS revision), checksummed release artifacts, and a
    changelog.
19. A Grafana dashboard and a Prometheus rules file to go with the starter
    alerts in [deploy.md](deploy.md#metrics).
20. Teach `Memory` to simulate conntrack, so controlplane tests can assert
    connection continuity without root.
