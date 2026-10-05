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
make check      # fmt, tidy, vet, race tests (what CI runs; works on macOS)
make run-dev    # in-memory data plane with deploy/ferry.example.json
make generate   # compile bpf/ferry.c in Docker (needs Docker running)
make build-linux
sudo ./bin/ferry-linux-arm64 -iface eth0 -config ferry.json
```

Requires Go 1.27. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Go code is [Apache-2.0](LICENSE). The XDP program in `bpf/` is
[GPL-2.0](bpf/LICENSE.GPL-2.0), as the kernel requires for BPF programs that
use GPL-only helpers.
