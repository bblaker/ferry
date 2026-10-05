//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go tool bpf2go -tags linux -target bpfel ferry ../../bpf/ferry.c

// Mirrors of the C structs in bpf/ferry.c. Fields marked be are stored in
// network byte order, so they are built with NativeEndian from big-endian
// bytes.
type serviceKey struct {
	VIP   uint32 // be
	Port  uint16 // be
	Proto uint8
	_     uint8
}

type backendValue struct {
	IP     uint32 // be
	Port   uint16 // be
	Active uint8
	_      uint8
}

// XDP programs the maps of a loaded and attached ferry XDP program.
type XDP struct {
	objs      ferryObjects
	innerSpec *ebpf.MapSpec
	link      link.Link
}

// LoadXDP loads bpf/ferry.c and attaches it to the named interface.
func LoadXDP(iface string) (*XDP, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
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
	x.link, err = link.AttachXDP(link.XDPOptions{Program: x.objs.XdpFerry, Interface: ifc.Index})
	if err != nil {
		x.objs.Close()
		return nil, fmt.Errorf("attach xdp to %s: %w", iface, err)
	}
	return x, nil
}

func (x *XDP) SetBackend(id uint32, b Backend) error {
	v := backendValue{
		IP:   be32(b.Addr.Addr().As4()),
		Port: be16(b.Addr.Port()),
	}
	if b.Active {
		v.Active = 1
	}
	return x.objs.Backends.Put(id, v)
}

// SetService builds a new inner table and swaps it into the outer map with a
// single update. The outer map holds its own reference to the inner map, so
// our file descriptor is closed as soon as the swap is done.
func (x *XDP) SetService(key ServiceKey, id uint32, slots []uint32) error {
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

func (x *XDP) Close() error {
	return errors.Join(x.link.Close(), x.objs.Close())
}

func toServiceKey(k ServiceKey) serviceKey {
	return serviceKey{VIP: be32(k.VIP.As4()), Port: be16(k.Port), Proto: uint8(k.Proto)}
}

func be32(b [4]byte) uint32 { return binary.NativeEndian.Uint32(b[:]) }

func be16(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}
