# Ferry

An L4/L7 edge router and load balancer for pi-tower. It has an XDP + Maglev
fast path and a Go control plane that swaps tables without breaking
in-flight connections. Background: https://bblaker.com/projects/ferry/

**Status: shadow mode.** Ferry attaches to the NIC, picks a Maglev backend
for every packet to a VIP, tracks the connection, and exports counters, but
passes every packet to the kernel unchanged. Forwarding is next; see
[docs/todo.md](docs/todo.md).

## Layout

| path | what |
|---|---|
| `bpf/ferry.c` | XDP program: service lookup, conntrack, Maglev selection |
| `internal/maglev` | Maglev table builder (pure Go, no deps) |
| `internal/dataplane` | `Dataplane` interface; `XDP` (Linux, cilium/ebpf) and `Memory` implementations |
| `internal/controlplane` | Reconciler: ID allocation, update ordering |
| `internal/discovery` | Desired-state sources (static JSON today) |
| `cmd/ferry` | The daemon: SIGHUP reload, `/metrics`, `/healthz` |
| `test/e2e` | End-to-end test on a veth pair |
| `deploy/` | Example config and systemd unit |
| `docs/` | [design](docs/design.md), [deploy](docs/deploy.md), [testing](docs/testing.md), [todo](docs/todo.md) |

## Develop

```sh
make check      # fmt, tidy, vet, race tests (works on macOS)
make run-dev    # in-memory data plane with deploy/ferry.example.json
make generate   # compile bpf/ferry.c in Docker (needs Docker running)
make test-bpf   # run bpf/ferry.c in the kernel, in a privileged container
make e2e        # run the ferry binary on a veth pair, in a privileged container
make build-linux
```

On Linux, use `generate-native`, `test-bpf-native` and `e2e-native`
instead (the last two use sudo).

```sh
ferry check -config ferry.json
sudo ferry attach -iface enp3s0 -mode xdp-native -config ferry.json
kill -HUP <pid>                      # re-read the config
curl localhost:9469/metrics
```

Requires Go 1.27. See [CONTRIBUTING.md](CONTRIBUTING.md) for details and
[docs/deploy.md](docs/deploy.md) to install it on the edge host.

## License

Go code is [Apache-2.0](LICENSE). The XDP program in `bpf/` is
[GPL-2.0](bpf/LICENSE.GPL-2.0), as the kernel requires for BPF programs that
use GPL-only helpers.
