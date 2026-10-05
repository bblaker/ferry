// Package discovery produces the desired set of services and their healthy
// backends. Sources (a static file today, Kubernetes EndpointSlices next)
// emit whole snapshots; the control plane diffs them.
package discovery

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/bblaker/ferry/internal/dataplane"
)

// Service is one virtual service and the backends that should receive its
// traffic right now.
type Service struct {
	Name     string
	Key      dataplane.ServiceKey
	Backends []netip.AddrPort
}

// staticFile is the on-disk format for LoadFile.
type staticFile struct {
	Services []struct {
		Name     string   `json:"name"`
		VIP      string   `json:"vip"`   // "192.168.1.240:443"
		Proto    string   `json:"proto"` // "tcp" (default) or "udp"
		Backends []string `json:"backends"`
	} `json:"services"`
}

// LoadFile reads a static service definition, used for development and for
// running ferry without Kubernetes.
func LoadFile(path string) ([]Service, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f staticFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	out := make([]Service, 0, len(f.Services))
	for _, s := range f.Services {
		vip, err := netip.ParseAddrPort(s.VIP)
		if err != nil {
			return nil, fmt.Errorf("service %q: vip: %w", s.Name, err)
		}
		if !vip.Addr().Is4() {
			return nil, fmt.Errorf("service %q: only IPv4 VIPs are supported", s.Name)
		}
		var proto dataplane.Proto
		switch strings.ToLower(s.Proto) {
		case "", "tcp":
			proto = dataplane.TCP
		case "udp":
			proto = dataplane.UDP
		default:
			return nil, fmt.Errorf("service %q: unknown proto %q", s.Name, s.Proto)
		}
		svc := Service{
			Name: s.Name,
			Key:  dataplane.ServiceKey{VIP: vip.Addr(), Port: vip.Port(), Proto: proto},
		}
		for _, b := range s.Backends {
			ap, err := netip.ParseAddrPort(b)
			if err != nil {
				return nil, fmt.Errorf("service %q: backend: %w", s.Name, err)
			}
			if !ap.Addr().Is4() {
				return nil, fmt.Errorf("service %q: only IPv4 backends are supported", s.Name)
			}
			svc.Backends = append(svc.Backends, ap)
		}
		out = append(out, svc)
	}
	return out, nil
}
