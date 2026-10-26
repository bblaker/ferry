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
	"net/netip"
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
  detach   remove a pinned program and its flow state from an interface
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
	case "detach":
		err = detachCmd(args)
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

const defaultPinDir = "/sys/fs/bpf/ferry"

func attach(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("attach", flag.ExitOnError)
	iface := fs.String("iface", "", "network interface to attach XDP to (empty: in-memory data plane, for development)")
	modeFlag := fs.String("mode", string(dataplane.ModeNative), "xdp-native or xdp-generic")
	config := fs.String("config", "ferry.json", "static service definition; re-read on SIGHUP")
	metricsAddr := fs.String("metrics-addr", "127.0.0.1:9469", "serve /metrics and /healthz on this address (empty: disabled)")
	shadow := fs.Bool("shadow", false, "select backends and count packets, but pass every packet to the kernel unmodified")
	snatIP := fs.String("snat-ip", "", "source address for packets to backends; an address of -iface (default: its only IPv4 address)")
	snatPorts := fs.String("snat-ports", dataplane.DefaultSNATPorts.String(), "source ports for packets to backends; must not be kernel ephemeral ports")
	pinDir := fs.String("pin-dir", defaultPinDir, "bpffs directory for state that survives restarts (empty: detach on exit)")
	fs.Parse(args)

	cfg := dataplane.XDPConfig{Iface: *iface, Shadow: *shadow, PinDir: *pinDir}
	var err error
	if cfg.Mode, err = dataplane.ParseMode(*modeFlag); err != nil {
		return err
	}
	if cfg.SNATPorts, err = dataplane.ParsePortRange(*snatPorts); err != nil {
		return fmt.Errorf("-snat-ports: %w", err)
	}
	if *snatIP != "" {
		if cfg.SNAT, err = netip.ParseAddr(*snatIP); err != nil {
			return fmt.Errorf("-snat-ip: %w", err)
		}
	}
	return run(cfg, *config, *metricsAddr, log)
}

func detachCmd(args []string) error {
	fs := flag.NewFlagSet("detach", flag.ExitOnError)
	iface := fs.String("iface", "", "interface to detach from")
	pinDir := fs.String("pin-dir", defaultPinDir, "bpffs directory ferry attach pinned to")
	fs.Parse(args)
	if *iface == "" {
		return errors.New("detach: -iface is required")
	}
	if err := detach(*pinDir, *iface); err != nil {
		return err
	}
	fmt.Printf("detached from %s; flow state dropped\n", *iface)
	return nil
}

func run(cfg dataplane.XDPConfig, config, metricsAddr string, log *slog.Logger) error {
	log.Info("starting", "version", version())
	// Read the config before attaching, so a bad file never touches the NIC.
	services, err := discovery.LoadFile(config)
	if err != nil {
		return err
	}
	dp, err := openDataplane(cfg, log)
	if err != nil {
		return err
	}
	defer dp.Close()

	d := newDaemon(dp, config, log)
	st, err := dp.State()
	if err != nil {
		return err
	}
	d.rec.Restore(st)
	// A config that can't fit is fatal. A failed update isn't: the retry
	// below finishes it, and meanwhile the data plane routes correctly with
	// whatever was programmed.
	if err := d.apply(services); errors.Is(err, controlplane.ErrInvalid) {
		return err
	} else if err != nil {
		log.Error("programming failed; data plane partially updated, retrying", "next", retryMin, "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.Iface != "" && !cfg.Shadow {
		go d.warmNeighbors(ctx, cfg.Iface, 30*time.Second)
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
	log.Info("ferry running", "services", len(services), "iface", cfg.Iface, "shadow", cfg.Shadow, "metrics", metricsAddr)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	var retry <-chan time.Time // nil while converged
	schedule := func() {
		retry = nil
		if delay, ok := d.retryDelay(); ok {
			retry = time.After(delay)
		}
	}
	schedule()
	for {
		select {
		case <-hup:
			d.reload()
			schedule()
		case <-retry:
			d.retry()
			schedule()
		case <-ctx.Done():
			if cfg.Iface != "" && cfg.PinDir != "" {
				log.Info("shutting down; the pinned program keeps forwarding with the current tables (ferry detach removes it)")
			} else {
				log.Info("shutting down")
			}
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
