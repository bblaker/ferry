// Command ferry is the Ferry control plane. It loads the XDP data plane,
// reads the desired services, and keeps the BPF maps in sync with them.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/bblaker/ferry/internal/controlplane"
	"github.com/bblaker/ferry/internal/dataplane"
	"github.com/bblaker/ferry/internal/discovery"
	"github.com/bblaker/ferry/internal/maglev"
)

const usage = `usage: ferry <command> [flags]

commands:
  attach   load and attach the XDP program, then keep its tables in sync
  check    validate a service config without touching the data plane
  version  print the build version

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
	case "check":
		err = check(args)
	case "version":
		fmt.Println(version())
		return
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
	modeFlag := fs.String("mode", string(dataplane.ModeNative), "xdp-native or xdp-generic")
	config := fs.String("config", "ferry.json", "static service definition; re-read on SIGHUP")
	metricsAddr := fs.String("metrics-addr", "127.0.0.1:9469", "serve /metrics and /healthz on this address (empty: disabled)")
	fs.Parse(args)
	mode, err := dataplane.ParseMode(*modeFlag)
	if err != nil {
		return err
	}
	return run(*iface, mode, *config, *metricsAddr, log)
}

func run(iface string, mode dataplane.Mode, config, metricsAddr string, log *slog.Logger) error {
	log.Info("starting", "version", version())
	// Read the config before attaching, so a bad file never touches the NIC.
	services, err := discovery.LoadFile(config)
	if err != nil {
		return err
	}
	dp, err := openDataplane(iface, mode, log)
	if err != nil {
		return err
	}
	defer dp.Close()

	d := newDaemon(dp, config, log)
	if err := d.apply(services); err != nil {
		return err
	}

	var srv *http.Server
	if metricsAddr != "" {
		ln, err := net.Listen("tcp", metricsAddr)
		if err != nil {
			return fmt.Errorf("metrics: %w", err)
		}
		srv = &http.Server{Handler: d.handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server stopped", "err", err)
			}
		}()
	}
	log.Info("ferry running", "services", len(services), "iface", iface, "metrics", metricsAddr)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case <-hup:
			d.reload()
		case <-ctx.Done():
			log.Info("shutting down")
			if srv != nil {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				srv.Shutdown(shutdownCtx)
			}
			return nil
		}
	}
}

// check validates a config the way attach would, including table capacity,
// by applying it to an in-memory data plane.
func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	config := fs.String("config", "ferry.json", "static service definition")
	fs.Parse(args)
	services, err := discovery.LoadFile(*config)
	if err != nil {
		return err
	}
	quiet := slog.New(slog.DiscardHandler)
	r := controlplane.NewReconciler(dataplane.NewMemory(), maglev.DefaultSize, quiet)
	if err := r.Apply(services); err != nil {
		return err
	}
	fmt.Printf("%s: ok (%d services, %d backends)\n", *config, r.Services(), len(r.Backends()))
	return nil
}

// version reports the module version for `go install`ed builds, otherwise
// the VCS revision stamped by `go build`.
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value[:min(12, len(s.Value))]
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return "devel"
	}
	return rev + dirty
}
