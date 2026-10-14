# Linux toolchain for a non-Linux host: compiles bpf/ferry.c (bpf2go) and,
# run with --privileged, executes the BPF and end-to-end tests.
FROM golang:1.27-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev make \
    iproute2 iputils-ping curl ethtool \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
