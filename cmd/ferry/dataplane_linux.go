//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/bblaker/ferry/internal/dataplane"
)

func openDataplane(cfg dataplane.XDPConfig, log *slog.Logger) (dataplane.Dataplane, error) {
	if cfg.Iface == "" {
		log.Warn("no -iface given; using in-memory data plane, no traffic will be steered")
		return dataplane.NewMemory(), nil
	}
	if !cfg.Shadow {
		if err := preflight(&cfg); err != nil {
			return nil, err
		}
		log.Info("forwarding", "snat", cfg.SNAT, "snat_ports", cfg.SNATPorts)
	}
	return dataplane.LoadXDP(cfg, log)
}

// preflight checks the host settings full NAT depends on, and defaults the
// SNAT address to the interface's first IPv4 address.
func preflight(cfg *dataplane.XDPConfig) error {
	addrs, err := ifaceAddrs(cfg.Iface)
	if err != nil {
		return err
	}
	switch {
	case !cfg.SNAT.IsValid() && len(addrs) == 0:
		return fmt.Errorf("%s has no IPv4 address to use for SNAT", cfg.Iface)
	case !cfg.SNAT.IsValid() && len(addrs) > 1:
		// Often the VIPs live here too; don't guess which is the node's.
		return fmt.Errorf("%s has several IPv4 addresses %v; choose one with -snat-ip", cfg.Iface, addrs)
	case !cfg.SNAT.IsValid():
		cfg.SNAT = addrs[0]
	case !slices.Contains(addrs, cfg.SNAT):
		return fmt.Errorf("-snat-ip %s is not an address of %s; replies to it would not reach ferry", cfg.SNAT, cfg.Iface)
	}

	// bpf_fib_lookup refuses to route for an interface with forwarding off.
	fwd, err := sysctl("net/ipv4/conf/" + cfg.Iface + "/forwarding")
	if err != nil {
		return err
	}
	if fwd != "1" {
		return fmt.Errorf("IPv4 forwarding is off on %s; enable it with `sysctl net.ipv4.conf.%s.forwarding=1` (see docs/deploy.md)", cfg.Iface, cfg.Iface)
	}

	ephemeral, err := sysctl("net/ipv4/ip_local_port_range")
	if err != nil {
		return err
	}
	reserved, err := sysctl("net/ipv4/ip_local_reserved_ports")
	if err != nil {
		return err
	}
	return checkSNATPorts(cfg.SNATPorts, ephemeral, reserved)
}

func detach(pinDir, iface string) error {
	return dataplane.Detach(pinDir, iface)
}

func ifaceAddrs(name string) ([]netip.Addr, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	as, err := ifc.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

func sysctl(name string) (string, error) {
	b, err := os.ReadFile("/proc/sys/" + name)
	if err != nil {
		return "", fmt.Errorf("read sysctl: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}
