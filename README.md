# Ferry

An L4/L7 edge router and load balancer for pi-tower. It has an XDP + Maglev
fast path and a Go control plane that swaps tables without breaking
in-flight connections. Background: https://bblaker.com/projects/ferry/

**Status:** forwards TCP and UDP with one-armed full NAT. Connections
survive backend changes and daemon restarts. It is tested end to end in
Docker but hasn't run on the edge host yet; see [docs/todo.md](docs/todo.md).

## Layout

| path | what |
|---|---|
| `bpf/ferry.c` | XDP program: service lookup, conntrack, Maglev selection, full NAT |
| `internal/maglev` | Maglev table builder (pure Go, no deps) |
| `internal/dataplane` | `Dataplane` interface; `XDP` (Linux, cilium/ebpf) and `Memory` implementations |
| `internal/controlplane` | Reconciler: ID allocation, update ordering |
| `internal/discovery` | Desired-state sources (static JSON today) |
| `cmd/ferry` | The daemon: SIGHUP reload, `/metrics`, `/healthz`, `detach` |
| `test/e2e` | End-to-end test: real connections through ferry on a veth pair |
| `deploy/` | Example config, systemd unit, sysctl settings |
| `docs/` | [design](docs/design.md), [deploy](docs/deploy.md), [testing](docs/testing.md), [todo](docs/todo.md) |

## Develop

```sh
make check      # fmt, tidy, vet, race tests (works on macOS)
make run-dev    # in-memory data plane with deploy/ferry.example.json
make generate   # compile bpf/ferry.c in Docker (needs Docker running)
make test-bpf   # run bpf/ferry.c in the kernel, in a privileged container
make e2e        # real connections through the ferry binary, in a privileged container
make build-linux
```

On Linux, use `generate-native`, `test-bpf-native` and `e2e-native`
instead (the last two use sudo).

```sh
ferry check -config ferry.json
sudo ferry attach -iface enp3s0 -snat-ip 192.168.1.10 -config ferry.json
kill -HUP <pid>                      # re-read the config
curl localhost:9469/metrics
sudo ferry detach -iface enp3s0      # stopping ferry leaves the program forwarding
```

Requires Go 1.27. See [CONTRIBUTING.md](CONTRIBUTING.md) for details and
[docs/deploy.md](docs/deploy.md) to install it on the edge host.

## License

Go code is [Apache-2.0](LICENSE). The XDP program in `bpf/` is
[GPL-2.0](bpf/LICENSE.GPL-2.0), as the kernel requires for BPF programs that
use GPL-only helpers.
