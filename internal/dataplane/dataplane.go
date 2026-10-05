// Package dataplane is the boundary between the Go control plane and the BPF
// maps the XDP program reads. The control plane decides *what* the tables
// should be; implementations of Dataplane decide *how* they get there.
package dataplane

import (
	"fmt"
	"net/netip"
)

// Limits shared with bpf/ferry.c. Keep in sync.
const (
	MaxServices = 256
	MaxBackends = 4096
)

type Proto uint8

const (
	TCP Proto = 6
	UDP Proto = 17
)

func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return fmt.Sprintf("proto(%d)", uint8(p))
}

// ServiceKey identifies a virtual service as packets see it.
type ServiceKey struct {
	VIP   netip.Addr // IPv4 only for now
	Port  uint16
	Proto Proto
}

func (k ServiceKey) String() string {
	return fmt.Sprintf("%s/%s", netip.AddrPortFrom(k.VIP, k.Port), k.Proto)
}

// Backend is a real server. Active=false keeps the slot reserved so that
// connection-tracking entries still pointing at it reselect a live backend
// instead of being forwarded into the void.
type Backend struct {
	Addr   netip.AddrPort
	Active bool
}

// Dataplane programs the forwarding tables.
//
// Ordering contract (the control plane relies on it):
//   - SetBackend for every backend referenced by a table happens before the
//     SetService that installs the table.
//   - SetService replaces a service's whole table in one atomic step;
//     readers see either the old table or the new one, never a mix.
type Dataplane interface {
	SetBackend(id uint32, b Backend) error
	// SetService installs slots (backend IDs, one per Maglev slot) for the
	// service and maps key to id.
	SetService(key ServiceKey, id uint32, slots []uint32) error
	DeleteService(key ServiceKey, id uint32) error
	Close() error
}
