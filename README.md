# Ferry

An L4/L7 edge router and load balancer for pi-tower. It has an XDP + Maglev
fast path and a Go control plane that swaps tables without breaking
in-flight connections. Background: https://bblaker.com/projects/ferry/

## Layout

| path | what |
|---|---|
| `bpf/ferry.c` | XDP program: service lookup, conntrack, Maglev selection |
| `internal/maglev` | Maglev table builder (pure Go, no deps) |
| `internal/dataplane` | `Dataplane` interface; `XDP` (Linux, cilium/ebpf) and `Memory` implementations |
| `internal/controlplane` | Reconciler: ID allocation, update ordering |
| `internal/discovery` | Desired-state sources (static JSON today) |
| `cmd/ferry` | The daemon |
| `docs/design.md` | Maps, swap mechanics, open decisions |

## Develop

```sh
make test       # works on macOS
make run-dev    # in-memory data plane with deploy/ferry.example.json
make generate   # compile bpf/ferry.c in Docker (needs Docker running)
make build-linux
sudo ./bin/ferry-linux-arm64 -iface eth0 -config ferry.json
```

Requires Go 1.27.
