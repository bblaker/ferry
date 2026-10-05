// Command ferry is the Ferry control plane. It loads the XDP data plane,
// reads the desired services, and keeps the BPF maps in sync with them.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bblaker/ferry/internal/controlplane"
	"github.com/bblaker/ferry/internal/discovery"
	"github.com/bblaker/ferry/internal/maglev"
)

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP to (empty: in-memory data plane, for development)")
	config := flag.String("config", "ferry.json", "static service definition")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*iface, *config, log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(iface, config string, log *slog.Logger) error {
	dp, err := openDataplane(iface, log)
	if err != nil {
		return err
	}
	defer dp.Close()

	services, err := discovery.LoadFile(config)
	if err != nil {
		return err
	}
	r := controlplane.NewReconciler(dp, maglev.DefaultSize, log)
	if err := r.Apply(services); err != nil {
		return err
	}
	log.Info("ferry running", "services", len(services), "iface", iface)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Info("shutting down")
	return nil
}
