# Contributing

Ferry is a personal project built in the open. Issues and small PRs are
welcome; for anything bigger, open an issue first so we can agree on the
approach.

## Setup

- Go 1.27 (the version in `go.mod`; `GOTOOLCHAIN=auto` fetches it).
- Docker for `make generate`, `make test-bpf` and `make e2e` on macOS. On
  Linux, the `-native` variants use your own clang, libbpf headers and
  kernel (and sudo for the tests).

```sh
make generate   # compile bpf/ferry.c
make check      # fmt, tidy, vet, race tests
make test-bpf   # bpf/ferry.c in the kernel via BPF_PROG_TEST_RUN
make e2e        # the ferry binary on a veth pair
```

CI runs all of these. [docs/testing.md](docs/testing.md) explains what each
layer covers and where new tests go.

## Expectations

- Keep `bpf/ferry.c` and the constants in `internal/dataplane` in sync;
  `TestConstantsMatchBPF` checks map sizes. If you change `flow_hash`, update
  `Flow.Hash` and its golden values to match.
- Changes to update ordering or the table swap need a test in
  `internal/controlplane`, since that is where connection continuity lives.
  Packet-path changes need a test in `internal/dataplane/xdp_linux_test.go`
  (selection) or `nat_linux_test.go` (forwarding).
- Changing a map's key or value layout breaks restarts onto pinned state
  ("incompatible build"); call it out in the commit message.
- Explain the *why* in commit messages. One logical change per commit.

## Licensing

Go code is Apache-2.0 (`LICENSE`). The BPF program in `bpf/` is GPL-2.0
(`bpf/LICENSE.GPL-2.0`) because the kernel requires a GPL-compatible
license for the helpers it uses. By contributing, you agree to license your
work under the license of the files you change.
