# Toolchain for compiling bpf/ferry.c and running bpf2go from a non-Linux host.
FROM golang:1.27-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
