# On macOS, BPF code is compiled and tested inside a Linux container
# (`make generate`, `make test-bpf`, `make e2e`). On Linux and in CI, the
# `-native` variants use the host's clang and kernel.
BUILDER       := ferry-bpf-builder
BPF2GO_CFLAGS := -O2 -g -Wall -Werror -I/usr/include/$(shell uname -m)-linux-gnu
# The container sees this checkout but, in a git worktree, not the main .git
# directory, so VCS stamping would fail there.
IN_BUILDER    := docker run --rm -v $(CURDIR):/src -v ferry-gomod:/go/pkg/mod \
                 -v ferry-gocache:/root/.cache/go-build -e GOFLAGS=-buildvcs=false
SUDO          := $(if $(filter 0,$(shell id -u)),,sudo)
GOARCH        ?= arm64

.PHONY: check fmt test generate generate-native builder build-linux run-dev \
        test-bpf test-bpf-native e2e e2e-native

# Everything CI checks without root. On Linux, run `make generate-native` first.
check: fmt
	go mod tidy -diff
	go vet ./...
	go test -race ./...

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

test:
	go test ./...

builder:
	docker build -q -t $(BUILDER) bpf

# Regenerates internal/dataplane/ferry_bpfel.{go,o} from bpf/ferry.c.
generate: builder
	$(IN_BUILDER) $(BUILDER) make generate-native

generate-native:
	BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate ./internal/dataplane/

# Runs bpf/ferry.c in the kernel via BPF_PROG_TEST_RUN. Needs root, so the
# container is privileged; natively, the test binary runs under sudo.
test-bpf: builder
	$(IN_BUILDER) --privileged $(BUILDER) make generate-native test-bpf-native

test-bpf-native:
	FERRY_REQUIRE_BPF=1 go test -count=1 -v $(if $(SUDO),-exec "sudo env FERRY_REQUIRE_BPF=1") ./internal/dataplane/

# Runs the ferry binary on a veth pair (test/e2e/e2e.sh). Needs root.
e2e: builder
	$(IN_BUILDER) --privileged $(BUILDER) make generate-native e2e-native

e2e-native:
	go build -o bin/ferry-e2e ./cmd/ferry
	$(SUDO) env FERRY_BIN=bin/ferry-e2e test/e2e/e2e.sh

# Cross-compiles for the Raspberry Pi edge host (GOARCH=amd64 for x86).
# Requires generated BPF code.
build-linux:
	GOOS=linux GOARCH=$(GOARCH) go build -o bin/ferry-linux-$(GOARCH) ./cmd/ferry

run-dev:
	go run ./cmd/ferry attach -config deploy/ferry.example.json
