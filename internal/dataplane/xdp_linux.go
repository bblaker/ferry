//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	statMax
)

// XDP programs the maps of a loaded ferry XDP program. Map keys and values
// use the bpf2go-generated types, so their layout follows bpf/ferry.c.
type XDP struct {
	objs      ferryObjects
	innerSpec *ebpf.MapSpec
	link      link.Link // nil until attached
}

// LoadXDP loads bpf/ferry.c and attaches it to the named interface.
func LoadXDP(iface string, mode Mode, log *slog.Logger) (*XDP, error) {
	var flags link.XDPAttachFlags
	switch mode {
	case ModeNative:
		// Explicit, so a driver without native XDP fails loudly instead of
		// silently falling back to the much slower generic path.
		flags = link.XDPDriverMode
	case ModeGeneric:
		flags = link.XDPGenericMode
	default:
		return nil, fmt.Errorf("unknown xdp mode %q", mode)
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	x, err := loadXDP()
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// %+v prints the whole verifier log, not just its last line.
			log.Error("verifier rejected ferry_ingress", "log", fmt.Sprintf("%+v", ve))
		}
		return nil, err
	}
	logProgram(log, x.objs.FerryIngress, time.Since(start))

	// The link is owned by this process: if ferry exits for any reason, the
	// kernel detaches the program and traffic goes straight to the stack.
	x.link, err = link.AttachXDP(link.XDPOptions{Program: x.objs.FerryIngress, Interface: ifc.Index, Flags: flags})
	if err != nil {
		x.objs.Close()
		return nil, fmt.Errorf("attach xdp to %s (%s): %w", iface, mode, err)
	}
	log.Info("attached", "iface", iface, "mode", mode)
	return x, nil
}

// loadXDP creates the maps and loads the program without attaching it.
// Tests drive the loaded program with BPF_PROG_TEST_RUN.
func loadXDP() (*XDP, error) {
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
	x := &XDP{innerSpec: outer.InnerMap.Copy()}
	if err := spec.LoadAndAssign(&x.objs, nil); err != nil {
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
