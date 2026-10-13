package dataplane

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// Flow is a 5-tuple as the XDP program sees it on ingress.
type Flow struct {
	Src, Dst netip.AddrPort
	Proto    Proto
}

// Service returns the key the XDP program looks the flow up under.
func (f Flow) Service() ServiceKey {
	return ServiceKey{VIP: f.Dst.Addr(), Port: f.Dst.Port(), Proto: f.Proto}
}

// Hash mirrors flow_hash in bpf/ferry.c, so that Go code can predict which
// Maglev slot a flow lands in. The BPF program reads network-order fields as
// host-order integers, hence NativeEndian over big-endian bytes.
// TestHashMatchesBPF checks the two agree.
func (f Flow) Hash() uint32 {
	src, dst := f.Src.Addr().As4(), f.Dst.Addr().As4()
	saddr := binary.NativeEndian.Uint32(src[:])
	daddr := binary.NativeEndian.Uint32(dst[:])
	ports := uint32(be16(f.Src.Port()))<<16 | uint32(be16(f.Dst.Port()))

	h := uint32(0x9747b28c)
	h = bits.RotateLeft32(h^saddr, 13)*5 + 0xe6546b64
	h = bits.RotateLeft32(h^daddr, 13)*5 + 0xe6546b64
	h = bits.RotateLeft32(h^ports, 13)*5 + 0xe6546b64
	h ^= uint32(f.Proto)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// be16 returns p as the BPF program sees a __be16 field: big-endian bytes
// read as a host-order integer.
func be16(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

// be32 is be16 for an IPv4 address.
func be32(b [4]byte) uint32 { return binary.NativeEndian.Uint32(b[:]) }
