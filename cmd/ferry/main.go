// Command ferry is the Ferry control plane. It loads the XDP data plane,
// reads the desired services, and keeps the BPF maps in sync with them.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bblaker/ferry/internal/controlplane"
	"github.com/bblaker/ferry/internal/dataplane"
	"github.com/bblaker/ferry/internal/discovery"
	"github.com/bblaker/ferry/internal/maglev"
)

const usage = `usage: ferry <command> [flags]

commands:
  attach   load and attach the XDP program, then keep its tables in sync

Run "ferry <command> -h" for a command's flags.
`

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "attach":
		err = attach(args, log)
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "ferry: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func attach(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("attach", flag.ExitOnError)
	iface := fs.String("iface", "", "network interface to attach XDP to (empty: in-memory data plane, for development)")
	mode := fs.String("mode", string(dataplane.ModeNative), "xdp-native or xdp-generic")
	config := fs.String("config", "ferry.json", "static service definition")
	fs.Parse(args)
	return run(*iface, dataplane.Mode(*mode), *config, log)
}

func run(iface string, mode dataplane.Mode, config string, log *slog.Logger) error {
	dp, err := openDataplane(iface, mode, log)
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
