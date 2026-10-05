# On macOS, BPF code is compiled inside a Linux container (`make generate`).
# On Linux and in CI, `make generate-native` uses the host's clang.
BUILDER       := ferry-bpf-builder
BPF2GO_CFLAGS := -O2 -g -Wall -Werror -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: check fmt test generate generate-native builder build-linux run-dev

# Everything CI checks. On Linux, run `make generate-native` first.
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
	docker run --rm -v $(CURDIR):/src -v ferry-gomod:/go/pkg/mod $(BUILDER) make generate-native

generate-native:
	BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate ./internal/dataplane/

# Cross-compiles for the Raspberry Pi edge host. Requires generated BPF code.
build-linux:
	GOOS=linux GOARCH=arm64 go build -o bin/ferry-linux-arm64 ./cmd/ferry

run-dev:
	go run ./cmd/ferry attach -config deploy/ferry.example.json
