//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -target bpfel ferry ../../bpf/ferry.c

// Indexes into the `stats` map; enum stat in bpf/ferry.c.
const (
	statPackets = iota
	statServiceHit
	statCTHit
	statCTReselect
	statNoTable
	statNoBackend
	statForwarded
	statReplied
	statSNATExhausted
	statNoNeigh
	statFIBFail
	statWrongIface
	statTTLExceeded
	statICMPClient
	statICMPBackend
	statMax

	// statSlots is the stats map's size, STAT_SLOTS: room for more counters.
	statSlots = 32
)

// XDP programs the maps of a loaded ferry XDP program. Map keys and values
// use the bpf2go-generated types, so their layout follows bpf/ferry.c.
type XDP struct {
	objs      ferryObjects
	innerSpec *ebpf.MapSpec
	link      link.Link // nil until attached
}

// LoadXDP loads bpf/ferry.c and attaches it to cfg.Iface. With cfg.PinDir
// set, it reuses maps and an attachment left by a previous run, replacing
// only the program.
func LoadXDP(cfg XDPConfig, log *slog.Logger) (*XDP, error) {
	var flags link.XDPAttachFlags
	switch cfg.Mode {
	case ModeNative:
		// Explicit, so a driver without native XDP fails loudly instead of
		// silently falling back to the much slower generic path.
		flags = link.XDPDriverMode
	case ModeGeneric:
		flags = link.XDPGenericMode
	default:
		return nil, fmt.Errorf("unknown xdp mode %q", cfg.Mode)
	}
	ifc, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return nil, err
	}
	var pinPath string
	if cfg.PinDir != "" {
		pinPath = filepath.Join(cfg.PinDir, cfg.Iface)
	}
	start := time.Now()
	x, err := loadXDP(loadOptions{shadow: cfg.Shadow, snat: cfg.SNAT, ports: cfg.SNATPorts, pinPath: pinPath})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// %+v prints the whole verifier log, not just its last line.
			log.Error("verifier rejected ferry_ingress", "log", fmt.Sprintf("%+v", ve))
		}
		return nil, err
	}
	logProgram(log, x.objs.FerryIngress, time.Since(start))

	if err := x.attach(ifc, flags, pinPath, log); err != nil {
		x.objs.Close()
		return nil, err
	}
	return x, nil
}

// attach attaches the program to ifc, or swaps it into a pinned attachment
// from a previous run. The swap is atomic: every packet sees the old
// program or the new one.
func (x *XDP) attach(ifc *net.Interface, flags link.XDPAttachFlags, pinPath string, log *slog.Logger) error {
	var linkPath string
	if pinPath != "" {
		linkPath = filepath.Join(pinPath, "link")
		l, err := link.LoadPinnedLink(linkPath, nil)
		switch {
		case err == nil:
			if info, err := l.Info(); err == nil && info.XDP() != nil && info.XDP().Ifindex != uint32(ifc.Index) {
				l.Close()
				return fmt.Errorf("%s is attached to interface index %d, not %s; run `ferry detach`", linkPath, info.XDP().Ifindex, ifc.Name)
			}
			if err := l.Update(x.objs.FerryIngress); err != nil {
				l.Close()
				return fmt.Errorf("replace program in %s: %w", linkPath, err)
			}
			x.link = l
			log.Info("replaced program in place", "iface", ifc.Name, "pin", linkPath)
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("load pinned attachment: %w", err)
		}
	}

	// The link is owned by this process unless pinned: if ferry exits, the
	// kernel detaches the program and traffic goes straight to the stack.
	l, err := link.AttachXDP(link.XDPOptions{Program: x.objs.FerryIngress, Interface: ifc.Index, Flags: flags})
	if err != nil {
		return fmt.Errorf("attach xdp to %s: %w", ifc.Name, err)
	}
	if linkPath != "" {
		if err := l.Pin(linkPath); err != nil {
			l.Close()
			return fmt.Errorf("pin attachment: %w", err)
		}
	}
	x.link = l
	log.Info("attached", "iface", ifc.Name, "pin", linkPath)
	return nil
}

type loadOptions struct {
	shadow  bool
	snat    netip.Addr
	ports   PortRange
	pinPath string // "" to not pin
}

// loadXDP creates (or opens pinned) maps and loads the program without
// attaching it. Tests drive the loaded program with BPF_PROG_TEST_RUN.
func loadXDP(o loadOptions) (*XDP, error) {
	// Only matters on kernels before 5.11, which charge BPF memory to
	// RLIMIT_MEMLOCK instead of the memory cgroup.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock rlimit: %w", err)
	}
	spec, err := loadFerry()
	if err != nil {
		return nil, err
	}
	outer, ok := spec.Maps["maglev_tables"]
	if !ok || outer.InnerMap == nil {
		return nil, errors.New("maglev_tables: missing inner map spec")
	}

	vars := map[string]any{"shadow": uint8(0), "snat_ip": uint32(0), "snat_port_min": uint16(0), "snat_port_max": uint16(0)}
	if o.shadow {
		vars["shadow"] = uint8(1)
	} else {
		if !o.snat.Is4() {
			return nil, fmt.Errorf("SNAT address %v: need an IPv4 address", o.snat)
		}
		if o.ports.Min == 0 || o.ports.Min > o.ports.Max {
			return nil, fmt.Errorf("SNAT ports %s: empty range", o.ports)
		}
		vars["snat_ip"] = be32(o.snat.As4())
		vars["snat_port_min"] = o.ports.Min
		vars["snat_port_max"] = o.ports.Max
	}
	for name, v := range vars {
		if err := spec.Variables[name].Set(v); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}

	opts := &ebpf.CollectionOptions{}
	if o.pinPath != "" {
		if err := os.MkdirAll(o.pinPath, 0o700); err != nil {
			return nil, err
		}
		for name, m := range spec.Maps {
			if !strings.HasPrefix(name, ".") { // not .rodata: constants are per load
				m.Pinning = ebpf.PinByName
			}
		}
		opts.Maps.PinPath = o.pinPath
	}
	x := &XDP{innerSpec: outer.InnerMap.Copy()}
	if err := spec.LoadAndAssign(&x.objs, opts); err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			return nil, fmt.Errorf("pinned maps in %s are from an incompatible build; `ferry detach` resets them, dropping tracked flows: %w", o.pinPath, err)
		}
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	return x, nil
}

// logProgram reports what the kernel accepted. The load time includes map
// creation as well as verification.
func logProgram(log *slog.Logger, prog *ebpf.Program, load time.Duration) {
	attrs := []any{"prog", "ferry_ingress", "load", load.Round(time.Millisecond)}
	if info, err := prog.Info(); err == nil {
		if id, ok := info.ID(); ok {
			attrs = append(attrs, "id", id)
		}
		if n, ok := info.VerifiedInstructions(); ok {
			attrs = append(attrs, "insns", n)
		}
	}
	log.Info("loaded", attrs...)
}

// Detach removes a pinned attachment and its maps from pinDir: the program
// stops seeing packets and all flow state is dropped.
func Detach(pinDir, iface string) error {
	dir := filepath.Join(pinDir, iface)
	l, err := link.LoadPinnedLink(filepath.Join(dir, "link"), nil)
	switch {
	case err == nil:
		// Detach explicitly: dropping the last reference also detaches,
		// but the kernel does that later, from a workqueue.
		if err := errors.Join(l.Detach(), l.Unpin(), l.Close()); err != nil {
			return err
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	return os.RemoveAll(dir)
}

func (x *XDP) SetBackend(id uint32, b Backend) error {
	if !b.Addr.Addr().Is4() {
		return fmt.Errorf("backend %s: only IPv4 is supported", b.Addr)
	}
	v := ferryBackend{
		Ip:   be32(b.Addr.Addr().As4()),
		Port: be16(b.Addr.Port()),
	}
	if b.Active {
		v.Active = 1
	}
	// A packet counter belongs to an (id, address) pair. When the allocator
	// hands this ID to a different backend, start its counter from zero.
	var old ferryBackend
	if err := x.objs.Backends.Lookup(id, &old); err != nil {
		return fmt.Errorf("backend %d: %w", id, err)
	}
	if old.Ip != v.Ip || old.Port != v.Port {
		if err := x.objs.BackendPackets.Put(id, make([]uint64, ebpf.MustPossibleCPU())); err != nil {
			return fmt.Errorf("backend %d: reset counter: %w", id, err)
		}
	}
	return x.objs.Backends.Put(id, v)
}

// SetService builds a new inner table and swaps it into the outer map with a
// single update. The outer map holds its own reference to the inner map, so
// our file descriptor is closed as soon as the swap is done.
func (x *XDP) SetService(key ServiceKey, id uint32, slots []uint32) error {
	if !key.VIP.Is4() {
		return fmt.Errorf("service %s: only IPv4 is supported", key)
	}
	if len(slots) != int(x.innerSpec.MaxEntries) {
		return fmt.Errorf("table has %d slots, bpf program expects %d", len(slots), x.innerSpec.MaxEntries)
	}
	inner, err := ebpf.NewMap(x.innerSpec)
	if err != nil {
		return fmt.Errorf("create inner table: %w", err)
	}
	defer inner.Close()

	keys := make([]uint32, len(slots))
	for i := range keys {
		keys[i] = uint32(i)
	}
	if _, err := inner.BatchUpdate(keys, slots, nil); err != nil {
		return fmt.Errorf("fill inner table: %w", err)
	}
	// Table first, then the service entry, so a VIP never resolves to an
	// empty slot.
	if err := x.objs.MaglevTables.Put(id, inner); err != nil {
		return fmt.Errorf("swap table: %w", err)
	}
	return x.objs.Services.Put(toServiceKey(key), id)
}

func (x *XDP) DeleteService(key ServiceKey, id uint32) error {
	// Service entry first, so no new lookups reach the table being removed.
	if err := x.objs.Services.Delete(toServiceKey(key)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if err := x.objs.MaglevTables.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// Stats sums the per-CPU counters.
func (x *XDP) Stats() (Stats, error) {
	var c [statMax]uint64
	var perCPU []uint64
	for i := range c {
		if err := x.objs.Stats.Lookup(uint32(i), &perCPU); err != nil {
			return Stats{}, fmt.Errorf("read stat %d: %w", i, err)
		}
		c[i] = sum(perCPU)
	}
	s := Stats{
		Packets:            c[statPackets],
		ServiceHits:        c[statServiceHit],
		ConntrackHits:      c[statCTHit],
		ConntrackReselects: c[statCTReselect],
		NoTable:            c[statNoTable],
		NoBackend:          c[statNoBackend],
		Forwarded:          c[statForwarded],
		Replied:            c[statReplied],
		SNATExhausted:      c[statSNATExhausted],
		NoNeighbor:         c[statNoNeigh],
		FIBFailed:          c[statFIBFail],
		WrongInterface:     c[statWrongIface],
		TTLExceeded:        c[statTTLExceeded],
		ICMPToClient:       c[statICMPClient],
		ICMPToBackend:      c[statICMPBackend],
		BackendPackets:     map[uint32]uint64{},
	}
	var id uint32
	it := x.objs.BackendPackets.Iterate()
	for it.Next(&id, &perCPU) {
		if n := sum(perCPU); n > 0 {
			s.BackendPackets[id] = n
		}
	}
	if err := it.Err(); err != nil {
		return Stats{}, fmt.Errorf("read backend counters: %w", err)
	}
	return s, nil
}

// State reads back the backends and services in the maps, which are only
// non-empty when they were pinned by a previous run.
func (x *XDP) State() (State, error) {
	st := State{Backends: map[uint32]Backend{}, Services: map[ServiceKey]uint32{}}
	var id uint32
	var b ferryBackend
	it := x.objs.Backends.Iterate()
	for it.Next(&id, &b) {
		if b.Ip == 0 {
			continue // never used
		}
		st.Backends[id] = Backend{Addr: netip.AddrPortFrom(addrFromBE32(b.Ip), be16(b.Port)), Active: b.Active != 0}
	}
	if err := it.Err(); err != nil {
		return State{}, fmt.Errorf("read backends: %w", err)
	}
	var k ferryServiceKey
	it = x.objs.Services.Iterate()
	for it.Next(&k, &id) {
		st.Services[ServiceKey{VIP: addrFromBE32(k.Vip), Port: be16(k.Port), Proto: Proto(k.Proto)}] = id
	}
	if err := it.Err(); err != nil {
		return State{}, fmt.Errorf("read services: %w", err)
	}
	return st, nil
}

// Close releases this process's handles. A pinned attachment and maps stay
// in the kernel and keep forwarding; use Detach to remove them.
func (x *XDP) Close() error {
	var err error
	if x.link != nil {
		err = x.link.Close()
	}
	return errors.Join(err, x.objs.Close())
}

func toServiceKey(k ServiceKey) ferryServiceKey {
	return ferryServiceKey{Vip: be32(k.VIP.As4()), Port: be16(k.Port), Proto: uint8(k.Proto)}
}

func sum(vs []uint64) uint64 {
	var n uint64
	for _, v := range vs {
		n += v
	}
	return n
}
