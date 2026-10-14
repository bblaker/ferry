package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bblaker/ferry/internal/dataplane"
)

// checkSNATPorts verifies the kernel won't hand out SNAT ports as ephemeral
// ports for the host's own connections. If it did, and the host connected
// to a backend from a port Ferry was also using toward that backend, the
// XDP program would take the replies. ephemeral and reserved are the
// contents of net.ipv4.ip_local_port_range and ip_local_reserved_ports.
func checkSNATPorts(snat dataplane.PortRange, ephemeral, reserved string) error {
	f := strings.Fields(ephemeral)
	if len(f) != 2 {
		return fmt.Errorf("ip_local_port_range %q: unexpected format", ephemeral)
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return fmt.Errorf("ip_local_port_range %q: unexpected format", ephemeral)
	}
	res, err := parsePortList(reserved)
	if err != nil {
		return fmt.Errorf("ip_local_reserved_ports: %w", err)
	}
	for p := int(snat.Min); p <= int(snat.Max); p++ {
		if p >= lo && p <= hi && !res.contains(p) {
			return fmt.Errorf("SNAT ports %s overlap the kernel's ephemeral ports (%d-%d); reserve them with "+
				"`sysctl net.ipv4.ip_local_reserved_ports=%s` (see docs/deploy.md) or choose -snat-ports outside that range",
				snat, lo, hi, snat)
		}
	}
	return nil
}

type portList []dataplane.PortRange

func (l portList) contains(p int) bool {
	for _, r := range l {
		if p >= int(r.Min) && p <= int(r.Max) {
			return true
		}
	}
	return false
}

// parsePortList parses the ip_local_reserved_ports format: "8080,40000-59999".
func parsePortList(s string) (portList, error) {
	var out portList
	for item := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		if item == "" {
			continue
		}
		if !strings.Contains(item, "-") {
			item += "-" + item
		}
		r, err := dataplane.ParsePortRange(item)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
