// Package dataplane is the boundary between the Go control plane and the BPF
// maps the XDP program reads. The control plane decides *what* the tables
// should be; implementations of Dataplane decide *how* they get there.
package dataplane

import (
	"fmt"
	"net/netip"
)

// Limits shared with bpf/ferry.c. Keep in sync; TestConstantsMatchBPF checks.
const (
	MaxServices = 256
	MaxBackends = 1024
)

// Mode selects where the XDP program attaches.
type Mode string

const (
	ModeNative  Mode = "xdp-native"  // in the NIC driver; the fast path
	ModeGeneric Mode = "xdp-generic" // after skb allocation; works anywhere, for testing
)

// ParseMode validates a -mode flag value.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeNative, ModeGeneric:
		return m, nil
	}
	return "", fmt.Errorf("unknown xdp mode %q (want %s or %s)", s, ModeNative, ModeGeneric)
}

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

// Stats are the XDP program's counters, summed over CPUs. They are
// monotonic for the life of the loaded program.
type Stats struct {
	Packets            uint64 // every packet seen
	ServiceHits        uint64 // destined to a known VIP
	ConntrackHits      uint64 // reused a tracked, still-active backend
	ConntrackReselects uint64 // tracked backend was retired; picked again
	NoTable            uint64 // VIP known but no table installed
	NoBackend          uint64 // table slot pointed at an inactive backend

	// BackendPackets counts packets steered to each backend ID. IDs with no
	// packets are omitted. A counter restarts at zero when its ID is
	// reassigned to a different address.
	BackendPackets map[uint32]uint64
}

// Dataplane programs the forwarding tables.
//
// Ordering contract (the control plane relies on it):
//   - SetBackend for every backend referenced by a table happens before the
//     SetService that installs the table.
//   - SetService replaces a service's whole table in one atomic step;
//     readers see either the old table or the new one, never a mix.
//   - A backend is only deactivated once no installed table references it.
//
// Memory enforces the first and last points so tests catch violations.
type Dataplane interface {
	SetBackend(id uint32, b Backend) error
	// SetService installs slots (backend IDs, one per Maglev slot) for the
	// service and maps key to id.
	SetService(key ServiceKey, id uint32, slots []uint32) error
	DeleteService(key ServiceKey, id uint32) error
	Stats() (Stats, error)
	Close() error
}
