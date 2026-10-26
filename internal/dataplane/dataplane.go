// Package dataplane is the boundary between the Go control plane and the BPF
// maps the XDP program reads. The control plane decides *what* the tables
// should be; implementations of Dataplane decide *how* they get there.
package dataplane

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
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

// XDPConfig configures the XDP data plane (Linux only).
type XDPConfig struct {
	Iface string
	Mode  Mode
	// Shadow selects backends and counts packets, but passes every packet
	// to the kernel unmodified.
	Shadow bool
	// SNAT is the source address of packets sent to backends. It must be
	// an address of Iface, so that replies come back to it.
	SNAT      netip.Addr
	SNATPorts PortRange
	// PinDir, if set, is a bpffs directory to pin the maps and attachment
	// under (in a subdirectory per interface). Pinned, they outlive the
	// process: a restart replaces the program in place and keeps every
	// tracked flow.
	PinDir string
}

// PortRange is an inclusive range of ports, such as the SNAT pool.
type PortRange struct{ Min, Max uint16 }

// DefaultSNATPorts sits inside Linux's default ephemeral range
// (32768-60999), so it must be reserved with ip_local_reserved_ports; see
// docs/deploy.md. Ports are only unique per backend, so this allows 20000
// concurrent flows to each backend.
var DefaultSNATPorts = PortRange{40000, 59999}

// ParsePortRange parses "min-max".
func ParsePortRange(s string) (PortRange, error) {
	a, b, ok := strings.Cut(s, "-")
	lo, err1 := strconv.ParseUint(a, 10, 16)
	hi, err2 := strconv.ParseUint(b, 10, 16)
	if !ok || err1 != nil || err2 != nil || lo == 0 || lo > hi {
		return PortRange{}, fmt.Errorf("port range %q: want min-max with 0 < min <= max <= 65535", s)
	}
	return PortRange{uint16(lo), uint16(hi)}, nil
}

func (r PortRange) String() string { return fmt.Sprintf("%d-%d", r.Min, r.Max) }

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

	Forwarded uint64 // client packets NATed to a backend
	Replied   uint64 // backend packets NATed back to a client

	// ICMP errors about a NATed flow, translated and sent on.
	ICMPToClient  uint64 // from the backend side, to the flow's client
	ICMPToBackend uint64 // from the client side, to the flow's backend

	// Packets dropped while forwarding, by reason.
	SNATExhausted  uint64 // no free SNAT port toward the backend
	NoNeighbor     uint64 // next hop's MAC address not resolved
	FIBFailed      uint64 // no usable route
	WrongInterface uint64 // route leaves by another interface
	TTLExceeded    uint64

	// BackendPackets counts packets steered to each backend ID. IDs with no
	// packets are omitted. A counter restarts at zero when its ID is
	// reassigned to a different address.
	BackendPackets map[uint32]uint64
}

// State is what a data plane already has programmed. An XDP data plane with
// pinned maps outlives the process, and a restarted control plane adopts its
// IDs so tracked flows keep resolving to the same backends.
type State struct {
	Backends map[uint32]Backend // including retired (inactive) ones
	Services map[ServiceKey]uint32
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
	State() (State, error)
	Close() error
}
