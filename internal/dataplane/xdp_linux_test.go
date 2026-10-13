//go:build linux

package dataplane

// These tests run bpf/ferry.c in the kernel with BPF_PROG_TEST_RUN: no
// interface, no attach, just crafted frames in and map state out. Loading
// needs root (or CAP_BPF + CAP_NET_ADMIN), so without it they skip; set
// FERRY_REQUIRE_BPF=1 to make that a failure (`make test-bpf` does).
//
// Most of them are differential: the same tables are programmed into XDP and
// Memory, and the BPF program must pick the backend Memory predicts.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/bblaker/ferry/internal/maglev"
)

const (
	xdpPass = 2 // enum xdp_action
	ethIPv4 = 0x0800
	ethIPv6 = 0x86dd
	ethARP  = 0x0806
)

var (
	testVIP = ServiceKey{VIP: netip.MustParseAddr("192.168.1.240"), Port: 443, Proto: TCP}
	testDNS = ServiceKey{VIP: netip.MustParseAddr("192.168.1.241"), Port: 53, Proto: UDP}
)

func newTestXDP(t testing.TB) *XDP {
	t.Helper()
	x, err := loadXDP()
	if err != nil {
		if errors.Is(err, os.ErrPermission) && os.Getenv("FERRY_REQUIRE_BPF") == "" {
			t.Skipf("loading BPF needs root or CAP_BPF+CAP_NET_ADMIN; run `make test-bpf`: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	return x
}

// TestConstantsMatchBPF needs no privileges: it only reads the ELF.
func TestConstantsMatchBPF(t *testing.T) {
	spec, err := loadFerry()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]uint32{
		"services":        MaxServices,
		"maglev_tables":   MaxServices,
		"backends":        MaxBackends,
		"backend_packets": MaxBackends,
		"stats":           statMax,
	} {
		if got := spec.Maps[name].MaxEntries; got != want {
			t.Errorf("%s: bpf max_entries %d, Go expects %d", name, got, want)
		}
	}
	if got := spec.Maps["maglev_tables"].InnerMap.MaxEntries; got != maglev.DefaultSize {
		t.Errorf("MAGLEV_SIZE is %d, maglev.DefaultSize is %d", got, maglev.DefaultSize)
	}
}

// fixture programs identical tables into an XDP and a Memory data plane.
type fixture struct {
	t   testing.TB
	x   *XDP
	mem *Memory
	ids map[netip.AddrPort]uint32
}

func newFixture(t testing.TB) *fixture {
	return &fixture{t: t, x: newTestXDP(t), mem: NewMemory(), ids: map[netip.AddrPort]uint32{}}
}

// program activates backends (allocating IDs in first-seen order) and
// installs the service's table on both data planes, as the reconciler would.
func (f *fixture) program(key ServiceKey, svcID uint32, backends ...string) {
	f.t.Helper()
	names := make([]string, len(backends))
	byName := map[string]uint32{}
	for i, s := range backends {
		b := netip.MustParseAddrPort(s)
		id, ok := f.ids[b]
		if !ok {
			id = uint32(len(f.ids))
			f.ids[b] = id
		}
		f.both(func(dp Dataplane) error { return dp.SetBackend(id, Backend{Addr: b, Active: true}) })
		names[i], byName[s] = s, id
	}
	tbl, err := maglev.Build(names, maglev.DefaultSize)
	if err != nil {
		f.t.Fatal(err)
	}
	slots := make([]uint32, len(tbl.Slots))
	for i, s := range tbl.Slots {
		slots[i] = byName[tbl.Backends[s]]
	}
	f.both(func(dp Dataplane) error { return dp.SetService(key, svcID, slots) })
}

func (f *fixture) retire(backend string) {
	f.t.Helper()
	b := netip.MustParseAddrPort(backend)
	f.both(func(dp Dataplane) error { return dp.SetBackend(f.ids[b], Backend{Addr: b}) })
}

func (f *fixture) both(op func(Dataplane) error) {
	f.t.Helper()
	for _, dp := range []Dataplane{f.x, f.mem} {
		if err := op(dp); err != nil {
			f.t.Fatalf("%T: %v", dp, err)
		}
	}
}

// send runs one frame through the program and returns its XDP action.
func (f *fixture) send(frame []byte) uint32 {
	f.t.Helper()
	ret, err := f.x.objs.FerryIngress.Run(&ebpf.RunOptions{Data: frame})
	if err != nil {
		f.t.Fatal(err)
	}
	return ret
}

// tracked returns the backend conntrack holds for fl, if any.
func (f *fixture) tracked(fl Flow) (netip.AddrPort, bool) {
	f.t.Helper()
	var e ferryCtEntry
	err := f.x.objs.Conntrack.Lookup(flowKey(fl), &e)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return netip.AddrPort{}, false
	} else if err != nil {
		f.t.Fatal(err)
	}
	var b ferryBackend
	if err := f.x.objs.Backends.Lookup(e.BackendId, &b); err != nil {
		f.t.Fatal(err)
	}
	var ip [4]byte
	binary.NativeEndian.PutUint32(ip[:], b.Ip)
	return netip.AddrPortFrom(netip.AddrFrom4(ip), be16(b.Port)), true
}

// steer sends fl and returns the backend the program chose for it.
func (f *fixture) steer(fl Flow) netip.AddrPort {
	f.t.Helper()
	if ret := f.send(frame(fl)); ret != xdpPass {
		f.t.Fatalf("%v: action %d, want XDP_PASS (shadow mode)", fl, ret)
	}
	b, ok := f.tracked(fl)
	if !ok {
		f.t.Fatalf("%v: no conntrack entry after a service hit", fl)
	}
	return b
}

// predict is what Memory would pick for a new flow.
func (f *fixture) predict(fl Flow) netip.AddrPort {
	f.t.Helper()
	b, ok := f.mem.Lookup(fl)
	if !ok {
		f.t.Fatalf("%v: memory data plane has no backend", fl)
	}
	return b.Addr
}

func (f *fixture) stats() Stats {
	f.t.Helper()
	s, err := f.x.Stats()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func flowKey(fl Flow) ferryFlowKey {
	return ferryFlowKey{
		Saddr: be32(fl.Src.Addr().As4()),
		Daddr: be32(fl.Dst.Addr().As4()),
		Sport: be16(fl.Src.Port()),
		Dport: be16(fl.Dst.Port()),
		Proto: uint8(fl.Proto),
	}
}

// randomFlows returns n distinct client flows to key.
func randomFlows(key ServiceKey, n int, seed uint64) []Flow {
	r := rand.New(rand.NewPCG(seed, 0))
	out := make([]Flow, n)
	for i := range out {
		src := netip.AddrFrom4([4]byte{10, byte(r.IntN(256)), byte(r.IntN(256)), byte(i%250 + 1)})
		out[i] = Flow{
			Src:   netip.AddrPortFrom(src, uint16(1024+r.IntN(64000))),
			Dst:   netip.AddrPortFrom(key.VIP, key.Port),
			Proto: key.Proto,
		}
	}
	return out
}

// frame builds an Ethernet + IPv4 + TCP/UDP frame for fl. optWords adds that
// many 4-byte NOP words of IP options. Checksums are left zero; the program
// does not check them.
func frame(fl Flow, optWords ...int) []byte {
	opts := 0
	if len(optWords) > 0 {
		opts = optWords[0] * 4
	}
	l4 := 20
	if fl.Proto == UDP {
		l4 = 8
	}
	b := make([]byte, 14+20+opts+l4)
	binary.BigEndian.PutUint16(b[12:], ethIPv4)
	ip := b[14:]
	ip[0] = 0x40 | byte(5+opts/4) // version 4, ihl
	binary.BigEndian.PutUint16(ip[2:], uint16(20+opts+l4))
	ip[8] = 64
	ip[9] = byte(fl.Proto)
	src, dst := fl.Src.Addr().As4(), fl.Dst.Addr().As4()
	copy(ip[12:], src[:])
	copy(ip[16:], dst[:])
	for i := range opts {
		ip[20+i] = 1 // NOP
	}
	l := ip[20+opts:]
	binary.BigEndian.PutUint16(l[0:], fl.Src.Port())
	binary.BigEndian.PutUint16(l[2:], fl.Dst.Port())
	if fl.Proto == TCP {
		l[12] = 5 << 4 // data offset
		l[13] = 0x02   // SYN
	}
	return b
}

func TestSelectionMatchesMemory(t *testing.T) {
	f := newFixture(t)
	f.program(testVIP, 0, "10.42.0.11:8443", "10.42.1.12:8443", "10.42.2.13:8443")
	f.program(testDNS, 1, "10.42.0.20:53", "10.42.1.21:53")

	for _, key := range []ServiceKey{testVIP, testDNS} {
		seen := map[netip.AddrPort]int{}
		for _, fl := range randomFlows(key, 1000, 1) {
			got, want := f.steer(fl), f.predict(fl)
			if got != want {
				t.Fatalf("%v: bpf chose %s, memory predicts %s (Flow.Hash out of sync with flow_hash?)", fl, got, want)
			}
			seen[got]++
		}
		t.Logf("%s: %v", key, seen)
	}
}

func TestIPOptionsAreSkipped(t *testing.T) {
	f := newFixture(t)
	f.program(testVIP, 0, "10.42.0.11:8443", "10.42.1.12:8443", "10.42.2.13:8443")
	for i, fl := range randomFlows(testVIP, 50, 2) {
		f.send(frame(fl, 1+i%10)) // up to the 40-byte maximum
		got, ok := f.tracked(fl)
		if !ok {
			t.Fatalf("%v with %d option words: not recognised as a service hit", fl, 1+i%10)
		}
		if want := f.predict(fl); got != want {
			t.Fatalf("%v: bpf chose %s, memory predicts %s", fl, got, want)
		}
	}
}

func TestNonServiceTrafficPasses(t *testing.T) {
	f := newFixture(t)
	f.program(testVIP, 0, "10.42.0.11:8443")
	fl := randomFlows(testVIP, 1, 3)[0]

	withEtherType := func(et uint16) []byte {
		b := frame(fl)
		binary.BigEndian.PutUint16(b[12:], et)
		return b
	}
	mutate := func(fn func(ip []byte)) []byte {
		b := frame(fl)
		fn(b[14:])
		return b
	}
	otherPort, otherProto := fl, fl
	otherPort.Dst = netip.AddrPortFrom(fl.Dst.Addr(), 80)
	otherProto.Proto = UDP

	for name, data := range map[string][]byte{
		"arp":              withEtherType(ethARP),
		"ipv6":             withEtherType(ethIPv6),
		"icmp":             mutate(func(ip []byte) { ip[9] = 1 }),
		"unknown vip":      mutate(func(ip []byte) { ip[19] = 99 }),
		"other port":       frame(otherPort),
		"other proto":      frame(otherProto),
		"more fragments":   mutate(func(ip []byte) { ip[6] = 0x20 }),
		"later fragment":   mutate(func(ip []byte) { ip[7] = 0x10 }),
		"ihl below 5":      mutate(func(ip []byte) { ip[0] = 0x44 }),
		"truncated ip":     frame(fl)[:14+12],
		"truncated tcp":    frame(fl)[:14+20+10],
		"options past end": mutate(func(ip []byte) { ip[0] = 0x4f }),
	} {
		t.Run(name, func(t *testing.T) {
			before := f.stats()
			if ret := f.send(data); ret != xdpPass {
				t.Fatalf("action %d, want XDP_PASS", ret)
			}
			after := f.stats()
			if after.ServiceHits != before.ServiceHits {
				t.Error("counted as a service hit")
			}
			if after.Packets != before.Packets+1 {
				t.Errorf("packets: %d -> %d, want +1", before.Packets, after.Packets)
			}
		})
	}
}

// TestConntrackSurvivesTableSwap: a tracked flow keeps its backend when a
// new table would hash it elsewhere. This is the property that lets Ferry
// change backends without resetting connections.
func TestConntrackSurvivesTableSwap(t *testing.T) {
	f := newFixture(t)
	f.program(testVIP, 0, "10.42.0.11:8443", "10.42.1.12:8443")
	flows := randomFlows(testVIP, 300, 4)
	before := make([]netip.AddrPort, len(flows))
	for i, fl := range flows {
		before[i] = f.steer(fl)
	}

	f.program(testVIP, 0, "10.42.0.11:8443", "10.42.1.12:8443", "10.42.2.13:8443", "10.42.3.14:8443")
	s0 := f.stats()
	moved := 0
	for i, fl := range flows {
		if f.predict(fl) != before[i] {
			moved++
		}
		if got := f.steer(fl); got != before[i] {
			t.Fatalf("%v: tracked on %s, moved to %s after table swap", fl, before[i], got)
		}
	}
	if moved == 0 {
		t.Fatal("no flow's slot moved; the test proves nothing")
	}
	if hits := f.stats().ConntrackHits - s0.ConntrackHits; hits != uint64(len(flows)) {
		t.Errorf("conntrack hits = %d, want %d", hits, len(flows))
	}
	t.Logf("%d of %d tracked flows would have moved without conntrack", moved, len(flows))

	// New flows use the new table.
	for _, fl := range randomFlows(testVIP, 300, 5) {
		if got, want := f.steer(fl), f.predict(fl); got != want {
			t.Fatalf("new flow %v: bpf chose %s, memory predicts %s", fl, got, want)
		}
	}
}

// TestRetiredBackendReselects follows the reconciler's ordering: swap the
// table first, then deactivate the backend. Flows tracked on it must move to
// whatever the current table says.
func TestRetiredBackendReselects(t *testing.T) {
	f := newFixture(t)
	const gone = "10.42.1.12:8443"
	f.program(testVIP, 0, "10.42.0.11:8443", gone, "10.42.2.13:8443")
	var victims []Flow
	for _, fl := range randomFlows(testVIP, 300, 6) {
		if f.steer(fl).String() == gone {
			victims = append(victims, fl)
		}
	}
	if len(victims) == 0 {
		t.Fatal("no flow landed on the backend under test")
	}

	f.program(testVIP, 0, "10.42.0.11:8443", "10.42.2.13:8443")
	f.retire(gone)
	s0 := f.stats()
	for _, fl := range victims {
		got := f.steer(fl)
		if got.String() == gone {
			t.Fatalf("%v: still sent to retired backend", fl)
		}
		if want := f.predict(fl); got != want {
			t.Fatalf("%v: reselected %s, current table says %s", fl, got, want)
		}
	}
	if n := f.stats().ConntrackReselects - s0.ConntrackReselects; n != uint64(len(victims)) {
		t.Errorf("reselects = %d, want %d", n, len(victims))
	}
}

func TestDeletedServicePasses(t *testing.T) {
	f := newFixture(t)
	f.program(testVIP, 0, "10.42.0.11:8443")
	fl := randomFlows(testVIP, 1, 7)[0]
	f.steer(fl)
	f.both(func(dp Dataplane) error { return dp.DeleteService(testVIP, 0) })

	s0 := f.stats()
	f.send(frame(fl))
	if f.stats().ServiceHits != s0.ServiceHits {
		t.Error("deleted service still matched")
	}
}

// TestFailureCounters covers states the reconciler never creates but the
// program must survive: a VIP with no table, and a table whose backend is
// inactive. Memory rejects both, so they are set up on XDP alone.
func TestFailureCounters(t *testing.T) {
	x := newTestXDP(t)
	f := &fixture{t: t, x: x, mem: NewMemory(), ids: map[netip.AddrPort]uint32{}}

	if err := x.objs.Services.Put(toServiceKey(testVIP), uint32(7)); err != nil {
		t.Fatal(err)
	}
	f.send(frame(randomFlows(testVIP, 1, 8)[0]))
	if s := f.stats(); s.NoTable != 1 {
		t.Errorf("NoTable = %d, want 1", s.NoTable)
	}

	b := netip.MustParseAddrPort("10.42.0.11:8443")
	if err := x.SetBackend(0, Backend{Addr: b, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := x.SetService(testVIP, 7, make([]uint32, maglev.DefaultSize)); err != nil {
		t.Fatal(err)
	}
	if err := x.SetBackend(0, Backend{Addr: b}); err != nil {
		t.Fatal(err)
	}
	fl := randomFlows(testVIP, 1, 9)[0]
	if ret := f.send(frame(fl)); ret != xdpPass {
		t.Fatalf("action %d, want XDP_PASS", ret)
	}
	if s := f.stats(); s.NoBackend != 1 {
		t.Errorf("NoBackend = %d, want 1", s.NoBackend)
	}
	if _, ok := f.tracked(fl); ok {
		t.Error("flow tracked onto an inactive backend")
	}
}

func TestBackendCounters(t *testing.T) {
	f := newFixture(t)
	f.program(testVIP, 0, "10.42.0.11:8443", "10.42.1.12:8443")
	want := map[uint32]uint64{}
	for _, fl := range randomFlows(testVIP, 200, 10) {
		want[f.ids[f.steer(fl)]]++
	}
	s := f.stats()
	if fmt.Sprint(s.BackendPackets) != fmt.Sprint(want) {
		t.Errorf("BackendPackets = %v, want %v", s.BackendPackets, want)
	}
	if s.ServiceHits != 200 {
		t.Errorf("ServiceHits = %d, want 200", s.ServiceHits)
	}

	// Handing ID 0 to a different address starts its counter over;
	// toggling Active on the same address does not.
	b0 := netip.MustParseAddrPort("10.42.0.11:8443")
	if err := f.x.SetBackend(0, Backend{Addr: b0}); err != nil {
		t.Fatal(err)
	}
	if got := f.stats().BackendPackets[0]; got != want[0] {
		t.Errorf("deactivating reset the counter: %d, want %d", got, want[0])
	}
	if err := f.x.SetBackend(0, Backend{Addr: netip.MustParseAddrPort("10.42.9.9:8443"), Active: true}); err != nil {
		t.Fatal(err)
	}
	if got, ok := f.stats().BackendPackets[0]; ok {
		t.Errorf("reassigned ID kept the old counter: %d", got)
	}
}

func TestSetServiceRejectsWrongTableSize(t *testing.T) {
	x := newTestXDP(t)
	if err := x.SetService(testVIP, 0, make([]uint32, 7)); err == nil {
		t.Fatal("expected an error for a 7-slot table")
	}
}

// BenchmarkIngress reports the kernel's per-packet time for a tracked TCP
// flow, the common case. BPF_PROG_TEST_RUN timing excludes driver and DMA
// costs, so treat it as a regression signal, not a line-rate estimate.
func BenchmarkIngress(b *testing.B) {
	f := newFixture(b)
	f.program(testVIP, 0, "10.42.0.11:8443", "10.42.1.12:8443", "10.42.2.13:8443")
	data := frame(randomFlows(testVIP, 1, 11)[0])
	_, d, err := f.x.objs.FerryIngress.Benchmark(data, b.N, b.ResetTimer)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(d.Nanoseconds()), "ns/pkt")
}
