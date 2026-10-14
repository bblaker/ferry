//go:build !linux

package main

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/bblaker/ferry/internal/dataplane"
)

func openDataplane(cfg dataplane.XDPConfig, log *slog.Logger) (dataplane.Dataplane, error) {
	if cfg.Iface != "" {
		return nil, errors.New("XDP requires Linux; omit -iface to use the in-memory data plane")
	}
	log.Warn("not on Linux; using in-memory data plane, no traffic will be steered")
	return dataplane.NewMemory(), nil
}

func detach(string, string) error {
	return errors.New("XDP requires Linux")
}

func ifaceAddrs(string) ([]netip.Addr, error) { return nil, nil }
