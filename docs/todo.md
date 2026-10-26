# Remaining work

Ordered by what blocks what. Ferry forwards with one-armed full NAT, keeps
flows across reloads and restarts, and is tested end to end in Docker. It
has not run on the real edge host yet.

## Before relying on it in production

1. **Validate on the real Pi.** Confirm native XDP on the target NIC and
   driver, run `deploy/ferry.service` on Raspberry Pi OS (so far it has only
   passed `systemd-analyze verify` and a capability test in Docker), roll
   out in shadow mode, then forward. Measure throughput and latency with real
   traffic (iperf3 for a first look, pktgen or TRex for packet rates).
2. **Retry partial reload failures.** If a map update fails partway through
   `Apply`, the data plane stays partly updated until the next SIGHUP. Retry
   with backoff, and expose "converged" separately from "last reload OK".
3. **NAT table visibility.** Export how many flows are live (per backend,
   by state) and how full the SNAT pools are, so `snat_exhausted` can be
   alerted on before it happens. That needs a periodic map walk in
   userspace, which could also sweep expired entries instead of leaving them
   for lazy reclaim and LRU eviction.
4. **Map layout upgrades.** A build that changes a map's layout currently
   needs `ferry detach`, which drops every flow. Migrate pinned maps on
   startup instead (copy into new maps, then swap the program).

## Features

5. Kubernetes EndpointSlice discovery source (`internal/discovery`).
6. Active and passive health checks feeding discovery. Seeing both
   directions makes passive checks possible: RSTs and unanswered SYNs per
   backend.
7. Client addresses for backends. Full NAT hides them. The L7 /
   `crypto/tls` termination path can add `X-Forwarded-For`; for plain TCP,
   consider the PROXY protocol from that path too.
8. Fragmented packets to a VIP go to the kernel, so large UDP datagrams to a
   VIP are lost. Track fragments, or reassemble.
9. More than one interface (two-armed: clients on one NIC, backends on
    another) and backends on the edge host itself. Both need the program on
    every interface traffic can return on, and `bpf_redirect` where the
    egress driver supports it.
10. gRPC/protobuf control API (today: config file + SIGHUP).
11. Per-service counters. Today there are only global and per-backend ones.
12. IPv6, VLAN-tagged frames, weighted Maglev.
13. Optional: watch the config file and reload on change, instead of
    relying on `systemctl reload`.

## Design questions

14. **Backends shared across services.** A backend is identified by
    `ip:port` globally. If one is removed from service A but still used by
    service B, it stays active, so A's tracked flows keep going to it. Decide
    whether conntrack hits should also check the backend is still in the
    flow's service.
15. **Backend capacity headroom.** New backends are activated before old
    ones are retired, so one reload must fit old and new backends together
    in 1024 IDs. Replacing a near-full set needs two steps. Document this or
    stage it automatically.
16. **Two LRU maps per flow.** `conntrack` and `nat` evict independently. If
    either loses a live flow's entry under memory pressure, the flow breaks.
    Both hold 65536 entries; consider one map keyed both ways, or sizing
    them from the SNAT pool.
17. **A stopped daemon leaves forwarding on.** That is what makes restarts
    safe, but a crashed control plane goes unnoticed by the data plane.
    The `FerryDown` alert covers it today; consider a staleness metric
    exported from the data plane itself.

## Engineering hygiene

18. Add `staticcheck` or `golangci-lint` to `make check`.
19. Fuzz the packet parser: random frames through `BPF_PROG_TEST_RUN`,
    asserting no unexpected actions or counter movement.
20. Release process: tagged versions (`ferry version` already reports a
    module version or VCS revision), checksummed release artifacts, and a
    changelog.
21. A Grafana dashboard and a Prometheus rules file to go with the starter
    alerts in [deploy.md](deploy.md#metrics).
22. Teach `Memory` to simulate conntrack, so controlplane tests can assert
    connection continuity without root.
