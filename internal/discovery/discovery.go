// Package discovery produces the desired set of services and their healthy
// backends. Sources (a static file today, Kubernetes EndpointSlices next)
// emit whole snapshots; the control plane diffs them.
package discovery

import (
	"bytes"
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
	out, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// Parse decodes and validates the static file format. It is strict:
// unknown fields are errors, because a misspelled "backends" would otherwise
// read as a service with none, and Ferry removes those from the data plane.
func Parse(data []byte) ([]Service, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f staticFile
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("unexpected data after the top-level object")
	}

	out := make([]Service, 0, len(f.Services))
	names := map[string]bool{}
	keys := map[dataplane.ServiceKey]string{}
	for i, s := range f.Services {
		if s.Name == "" {
			return nil, fmt.Errorf("services[%d]: name is required", i)
		}
		if names[s.Name] {
			return nil, fmt.Errorf("service %q: duplicate name", s.Name)
		}
		names[s.Name] = true

		vip, err := parseAddrPort(s.VIP)
		if err != nil {
			return nil, fmt.Errorf("service %q: vip: %w", s.Name, err)
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
		if other, dup := keys[svc.Key]; dup {
			return nil, fmt.Errorf("service %q: %s is already used by %q", s.Name, svc.Key, other)
		}
		keys[svc.Key] = s.Name

		for _, b := range s.Backends {
			ap, err := parseAddrPort(b)
			if err != nil {
				return nil, fmt.Errorf("service %q: backend: %w", s.Name, err)
			}
			svc.Backends = append(svc.Backends, ap)
		}
		out = append(out, svc)
	}
	return out, nil
}

// parseAddrPort accepts what the XDP program can match on or forward to:
// a unicast IPv4 address and a nonzero port.
func parseAddrPort(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return ap, err
	}
	switch a := ap.Addr(); {
	case !a.Is4():
		return ap, fmt.Errorf("%s: only IPv4 is supported", s)
	case a.IsUnspecified(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return ap, fmt.Errorf("%s: not a unicast address", s)
	case ap.Port() == 0:
		return ap, fmt.Errorf("%s: port 0", s)
	}
	return ap, nil
}
