//go:build !linux

package main

import (
	"errors"
	"log/slog"

	"github.com/bblaker/ferry/internal/dataplane"
)

func openDataplane(iface string, _ dataplane.Mode, log *slog.Logger) (dataplane.Dataplane, error) {
	if iface != "" {
		return nil, errors.New("XDP requires Linux; omit -iface to use the in-memory data plane")
	}
	log.Warn("not on Linux; using in-memory data plane, no traffic will be steered")
	return dataplane.NewMemory(), nil
}
