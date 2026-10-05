# Contributing

Ferry is a personal project built in the open. Issues and small PRs are
welcome; for anything bigger, open an issue first so we can agree on the
approach.

## Setup

- Go 1.27 (the version in `go.mod`; `GOTOOLCHAIN=auto` fetches it).
- Docker for `make generate` on macOS. On Linux, `make generate-native` uses
  your own clang and libbpf headers.

```sh
make generate   # compile bpf/ferry.c
make check      # what CI runs: fmt, tidy, vet, race tests
```

## Expectations

- Keep `bpf/ferry.c` and the constants in `internal/dataplane` in sync; the
  comment at the top of each says which.
- Changes to update ordering or the table swap need a test in
  `internal/controlplane`, since that is where connection continuity lives.
- Explain the *why* in commit messages. One logical change per commit.

## Licensing

Go code is Apache-2.0 (`LICENSE`). The BPF program in `bpf/` is GPL-2.0
(`bpf/LICENSE.GPL-2.0`) because the kernel requires a GPL-compatible
license for the helpers it uses. By contributing, you agree to license your
work under the license of the files you change.
