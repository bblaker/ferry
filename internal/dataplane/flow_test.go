package dataplane

import (
	"net/netip"
	"testing"
)

// TestHashGolden pins Flow.Hash so a change to it fails on every platform,
// not only where the BPF tests run. The values were checked against
// flow_hash in bpf/ferry.c by TestSelectionMatchesMemory (Linux, root). They
// assume a little-endian host, as are all of Ferry's targets.
func TestHashGolden(t *testing.T) {
	for _, tc := range []struct {
		flow Flow
		want uint32
	}{
		{Flow{netip.MustParseAddrPort("10.1.2.3:40000"), netip.MustParseAddrPort("192.168.1.240:443"), TCP}, 0x98c2a196},
		{Flow{netip.MustParseAddrPort("10.1.2.3:40001"), netip.MustParseAddrPort("192.168.1.240:443"), TCP}, 0x9e1db6c6},
		{Flow{netip.MustParseAddrPort("172.16.0.9:5353"), netip.MustParseAddrPort("192.168.1.241:53"), UDP}, 0x9a68c595},
	} {
		if got := tc.flow.Hash(); got != tc.want {
			t.Errorf("%v: Hash() = %#08x, want %#08x; if flow_hash changed on purpose, update both", tc.flow, got, tc.want)
		}
	}
}
