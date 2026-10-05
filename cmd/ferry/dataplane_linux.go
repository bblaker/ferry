//go:build linux

package main

import (
	"log/slog"

	"github.com/bblaker/ferry/internal/dataplane"
)

func openDataplane(iface string, mode dataplane.Mode, log *slog.Logger) (dataplane.Dataplane, error) {
	if iface == "" {
		log.Warn("no -iface given; using in-memory data plane, no traffic will be steered")
		return dataplane.NewMemory(), nil
	}
	return dataplane.LoadXDP(iface, mode, log)
}
