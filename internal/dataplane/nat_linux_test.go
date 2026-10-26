//go:build linux

package dataplane

// Forwarding (full NAT) tests. The program routes with bpf_fib_lookup, so
// these build a small topology in the current network namespace:
//
//	ferryt0 (veth, 10.98.0.1 = SNAT address, forwarding on)
//	  static neighbors: client 10.98.0.2, backends 10.98.0.11-13,
//	  gateway 10.98.0.254 for 203.0.113.0/24 (a "remote" client)
//	ferryt2 (dummy, 10.97.0.0/24): routes that leave by another interface
//	blackhole 198.51.100.0/24: no usable route
//
// Frames enter as if received on ferryt0. Every output frame's checksums
// are recomputed from scratch and compared, which checks the program's
// incremental updates.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	xdpDrop = 1
	xdpTX   = 3
)

var (
	natSNAT   = netip.MustParseAddr("10.98.0.1")
	natClient = netip.MustParseAddr("10.98.0.2")
	natRemote = netip.MustParseAddr("203.0.113.7")
	natGW     = netip.MustParseAddr("10.98.0.254")
	natWeb    = ServiceKey{VIP: netip.MustParseAddr("10.98.0.240"), Port: 443, Proto: TCP}
	natDNS    = ServiceKey{VIP: netip.MustParseAddr("10.98.0.240"), Port: 53, Proto: UDP}
	natPorts  = PortRange{61000, 61999}
	webPool   = []string{"10.98.0.11:8443", "10.98.0.12:8443", "10.98.0.13:8443"}
)

// macFor is the static MAC given to a neighbor: 02:00:00:00:00:<last octet>.
func macFor(ip netip.Addr) net.HardwareAddr {
	a := ip.As4()
	return net.HardwareAddr{0x02, 0, 0, 0, 0, a[3]}
}

func newNATFixture(t testing.TB, ports PortRange) *fixture {
	t.Helper()
	x := loadTestXDP(t, loadOptions{snat: natSNAT, ports: ports})
	return &fixture{t: t, x: x, mem: NewMemory(), ids: map[netip.AddrPort]uint32{}, ifindex: natTopology(t)}
}

func natTopology(t testing.TB) int {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v\n%s", args, err, out)
		}
	}
	cleanup := func() {
		exec.Command("ip", "link", "del", "ferryt0").Run()
		exec.Command("ip", "link", "del", "ferryt2").Run()
		exec.Command("ip", "route", "del", "blackhole", "198.51.100.0/24").Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	ip("link", "add", "ferryt0", "type", "veth", "peer", "name", "ferryt1")
	ip("link", "set", "ferryt0", "up")
	ip("link", "set", "ferryt1", "up")
	ip("addr", "add", "10.98.0.1/24", "dev", "ferryt0")
	for _, n := range []string{"10.98.0.2", "10.98.0.11", "10.98.0.12", "10.98.0.13", "10.98.0.254"} {
		ip("neigh", "replace", n, "lladdr", macFor(netip.MustParseAddr(n)).String(), "dev", "ferryt0", "nud", "permanent")
	}
	ip("route", "add", "203.0.113.0/24", "via", "10.98.0.254", "dev", "ferryt0")
	ip("link", "add", "ferryt2", "type", "dummy")
	ip("link", "set", "ferryt2", "up")
	ip("addr", "add", "10.97.0.1/24", "dev", "ferryt2")
	ip("route", "add", "blackhole", "198.51.100.0/24")
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/ferryt0/forwarding", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	ifc, err := net.InterfaceByName("ferryt0")
	if err != nil {
		t.Fatal(err)
	}
	return ifc.Index
}

// out is a decoded output frame.
type out struct {
	dstMAC, srcMAC net.HardwareAddr
	src, dst       netip.AddrPort
	ttl            uint8
}

func decode(t testing.TB, b []byte) out {
	t.Helper()
	ip, l4 := headers(b)
	if c := csum(ip, 0); c != 0 {
		t.Fatalf("bad IP checksum in output (residual %#04x)", c)
	}
	off := 16
	if ip[9] == byte(UDP) {
		off = 6
	}
	got := binary.BigEndian.Uint16(l4[off:])
	if !(ip[9] == byte(UDP) && got == 0) && got != l4Checksum(b) {
		t.Fatalf("bad L4 checksum in output: %#04x, want %#04x", got, l4Checksum(b))
	}
	addr := func(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b)) }
	return out{
		dstMAC: net.HardwareAddr(b[0:6]),
		srcMAC: net.HardwareAddr(b[6:12]),
		src:    netip.AddrPortFrom(addr(ip[12:16]), binary.BigEndian.Uint16(l4[0:])),
		dst:    netip.AddrPortFrom(addr(ip[16:20]), binary.BigEndian.Uint16(l4[2:])),
		ttl:    ip[8],
	}
}

// withFlags returns a TCP frame for fl with the given flags.
func withFlags(fl Flow, flags byte) []byte {
	b := frame(fl)
	_, l4 := headers(b)
	l4[13] = flags
	fixChecksums(b)
	return b
}

// forward sends fl's packet and requires it to be transmitted to a backend.
func (f *fixture) forward(data []byte) out {
	f.t.Helper()
	ret, o := f.run(data)
	if ret != xdpTX {
		f.t.Fatalf("action %d, want XDP_TX; stats %+v", ret, f.stats())
	}
	return decode(f.t, o)
}

// replyFrom builds the backend's answer to a forwarded packet.
func replyFrom(fwd out, proto Proto, flags byte) []byte {
	fl := Flow{Src: fwd.dst, Dst: fwd.src, Proto: proto}
	if proto == UDP {
		return frame(fl)
	}
	return withFlags(fl, flags)
}

func (f *fixture) natEntry(backend netip.AddrPort, port uint16, proto Proto) (ferryNatEntry, bool) {
	f.t.Helper()
	k := ferryNatKey{BackendIp: be32(backend.Addr().As4()), BackendPort: be16(backend.Port()), SnatPort: be16(port), Proto: uint8(proto)}
	var e ferryNatEntry
	err := f.x.objs.Nat.Lookup(k, &e)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return e, false
	} else if err != nil {
		f.t.Fatal(err)
	}
	return e, true
}

// expire backdates a flow's NAT entry past its timeout. It also marks the
// flow closed, which has the shortest TCP timeout (10 s): the kernel clock
// counts from boot, so on a freshly booted CI runner no time is long enough
// ago to expire an established flow (900 s).
func (f *fixture) expire(backend netip.AddrPort, port uint16, proto Proto) {
	f.t.Helper()
	e, ok := f.natEntry(backend, port, proto)
	if !ok {
		f.t.Fatalf("no NAT entry for %s port %d", backend, port)
	}
	e.LastSeenNs = 0
	e.State = 3 // FLOW_CLOSED
	k := ferryNatKey{BackendIp: be32(backend.Addr().As4()), BackendPort: be16(backend.Port()), SnatPort: be16(port), Proto: uint8(proto)}
	if err := f.x.objs.Nat.Put(k, e); err != nil {
		f.t.Fatal(err)
	}
}

func natEntries(t testing.TB, x *XDP) int {
	t.Helper()
	var k ferryNatKey
	var e ferryNatEntry
	n := 0
	it := x.objs.Nat.Iterate()
	for it.Next(&k, &e) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

func clientFlows(key ServiceKey, n int, seed uint64) []Flow {
	fls := randomFlows(key, n, seed)
	for i := range fls {
		fls[i].Src = netip.AddrPortFrom(natClient, fls[i].Src.Port())
	}
	return fls
}

func TestForwardRewritesToBackend(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	f.program(natDNS, 1, "10.98.0.11:5353", "10.98.0.12:5353")
	ifMAC := mustMAC(t, "ferryt0")

	for _, key := range []ServiceKey{natWeb, natDNS} {
		used := map[netip.AddrPort]bool{} // (backend IP, SNAT port) must be unique per backend
		for _, fl := range clientFlows(key, 200, 20) {
			o := f.forward(frame(fl))
			if want := f.predict(fl); o.dst != want {
				t.Fatalf("%v: sent to %s, memory predicts %s", fl, o.dst, want)
			}
			if o.src.Addr() != natSNAT || o.src.Port() < natPorts.Min || o.src.Port() > natPorts.Max {
				t.Fatalf("%v: source %s, want %s with a port in %s", fl, o.src, natSNAT, natPorts)
			}
			if o.ttl != 63 {
				t.Errorf("TTL %d, want 63", o.ttl)
			}
			if o.dstMAC.String() != macFor(o.dst.Addr()).String() || o.srcMAC.String() != ifMAC.String() {
				t.Fatalf("MACs %s -> %s, want %s -> %s", o.srcMAC, o.dstMAC, ifMAC, macFor(o.dst.Addr()))
			}
			k := netip.AddrPortFrom(o.dst.Addr(), o.src.Port())
			if used[k] {
				t.Fatalf("SNAT port %d handed out twice toward %s", o.src.Port(), o.dst)
			}
			used[k] = true
		}
	}
	if s := f.stats(); s.Forwarded != 400 {
		t.Errorf("Forwarded = %d, want 400", s.Forwarded)
	}
}

func TestReplyRewritesToClient(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	f.program(natDNS, 1, "10.98.0.11:5353")

	for _, tc := range []struct {
		name    string
		key     ServiceKey
		client  netip.Addr
		nextHop netip.Addr
	}{
		{"tcp on-link client", natWeb, natClient, natClient},
		{"udp on-link client", natDNS, natClient, natClient},
		{"tcp client via gateway", natWeb, natRemote, natGW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fl := Flow{Src: netip.AddrPortFrom(tc.client, 40123), Dst: netip.AddrPortFrom(tc.key.VIP, tc.key.Port), Proto: tc.key.Proto}
			fwd := f.forward(frame(fl))
			before := f.stats().Replied
			ret, data := f.run(replyFrom(fwd, tc.key.Proto, tcpSYN|tcpACK))
			if ret != xdpTX {
				t.Fatalf("reply: action %d, want XDP_TX", ret)
			}
			o := decode(t, data)
			if o.src != fl.Dst || o.dst != fl.Src {
				t.Fatalf("reply %s -> %s, want %s -> %s", o.src, o.dst, fl.Dst, fl.Src)
			}
			if o.dstMAC.String() != macFor(tc.nextHop).String() {
				t.Errorf("reply sent to %s, want next hop %s (%s)", o.dstMAC, tc.nextHop, macFor(tc.nextHop))
			}
			if o.ttl != 63 {
				t.Errorf("TTL %d, want 63", o.ttl)
			}
			if f.stats().Replied != before+1 {
				t.Error("reply not counted")
			}
		})
	}
}

func TestTrackedFlowKeepsMapping(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	fl := clientFlows(natWeb, 1, 21)[0]
	first := f.forward(withFlags(fl, tcpSYN))

	// Even after the table changes, the flow keeps its backend and port.
	f.program(natWeb, 0, append(webPool, "10.98.0.14:8443")...)
	for _, flags := range []byte{tcpACK, tcpACK | 0x08} {
		o := f.forward(withFlags(fl, flags))
		if o.dst != first.dst || o.src != first.src {
			t.Fatalf("mapping changed: %s -> %s, first was %s -> %s", o.src, o.dst, first.src, first.dst)
		}
	}
	if s := f.stats(); s.ConntrackHits != 2 {
		t.Errorf("ConntrackHits = %d, want 2", s.ConntrackHits)
	}
}

func TestFlowState(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	fl := clientFlows(natWeb, 1, 22)[0]
	fwd := f.forward(withFlags(fl, tcpSYN))
	state := func() uint8 {
		e, ok := f.natEntry(fwd.dst, fwd.src.Port(), TCP)
		if !ok {
			t.Fatal("NAT entry missing")
		}
		return e.State
	}
	const (
		stNew = iota
		stEst
		stClosing
		stClosed
	)
	steps := []struct {
		name string
		send func()
		want uint8
	}{
		{"SYN", func() {}, stNew},
		{"SYN-ACK from backend", func() { f.run(replyFrom(fwd, TCP, tcpSYN|tcpACK)) }, stEst},
		{"ACK", func() { f.forward(withFlags(fl, tcpACK)) }, stEst},
		{"FIN", func() { f.forward(withFlags(fl, tcpFIN|tcpACK)) }, stClosing},
		{"RST from backend", func() { f.run(replyFrom(fwd, TCP, tcpRST)) }, stClosed},
		{"new SYN on the same 5-tuple", func() { f.forward(withFlags(fl, tcpSYN)) }, stNew},
	}
	for _, s := range steps {
		s.send()
		if got := state(); got != s.want {
			t.Fatalf("after %s: state %d, want %d", s.name, got, s.want)
		}
	}
}

func TestExpiredFlowStartsOver(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	fl := clientFlows(natWeb, 1, 23)[0]
	fwd := f.forward(frame(fl))
	f.expire(fwd.dst, fwd.src.Port(), TCP)

	// The backend's late reply is no longer translated.
	s0 := f.stats()
	if ret, _ := f.run(replyFrom(fwd, TCP, tcpACK)); ret != xdpPass {
		t.Errorf("reply on an expired flow: action %d, want XDP_PASS", ret)
	}
	// The client's next packet is a new flow, not a conntrack hit.
	f.forward(frame(fl))
	s1 := f.stats()
	if s1.Replied != s0.Replied || s1.ConntrackHits != s0.ConntrackHits {
		t.Errorf("expired flow was still used: %+v -> %+v", s0, s1)
	}
}

// TestSNATExhaustion uses a two-port pool toward a single backend.
func TestSNATExhaustion(t *testing.T) {
	f := newNATFixture(t, PortRange{61000, 61001})
	f.program(natWeb, 0, webPool[0])
	fls := clientFlows(natWeb, 3, 24)
	a := f.forward(frame(fls[0]))
	f.forward(frame(fls[1]))
	if ret, _ := f.run(frame(fls[2])); ret != xdpDrop {
		t.Fatalf("third flow: action %d, want XDP_DROP", ret)
	}
	if s := f.stats(); s.SNATExhausted != 1 {
		t.Errorf("SNATExhausted = %d, want 1", s.SNATExhausted)
	}
	// An idle flow's port is reclaimed.
	f.expire(a.dst, a.src.Port(), TCP)
	if o := f.forward(frame(fls[2])); o.src.Port() != a.src.Port() {
		t.Errorf("reclaimed port %d, want %d", o.src.Port(), a.src.Port())
	}
}

func TestRetiredBackendReleasesPort(t *testing.T) {
	f := newNATFixture(t, natPorts)
	const gone = "10.98.0.12:8443"
	f.program(natWeb, 0, webPool...)
	var fl Flow
	var old out
	for _, c := range clientFlows(natWeb, 100, 25) {
		if o := f.forward(frame(c)); o.dst.String() == gone {
			fl, old = c, o
			break
		}
	}
	if !fl.Src.IsValid() {
		t.Fatal("no flow landed on the backend under test")
	}

	f.program(natWeb, 0, webPool[0], webPool[2])
	f.retire(gone)
	o := f.forward(withFlags(fl, tcpACK))
	if o.dst.String() == gone {
		t.Fatal("still forwarding to a retired backend")
	}
	if want := f.predict(fl); o.dst != want {
		t.Errorf("reselected %s, table says %s", o.dst, want)
	}
	if _, ok := f.natEntry(old.dst, old.src.Port(), TCP); ok {
		t.Error("retired backend's NAT entry was not released")
	}
	if s := f.stats(); s.ConntrackReselects != 1 {
		t.Errorf("ConntrackReselects = %d, want 1", s.ConntrackReselects)
	}
}

func TestUnroutableBackendsDropWithoutState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backend string
		stat    func(Stats) uint64
	}{
		{"no neighbor", "10.98.0.50:8443", func(s Stats) uint64 { return s.NoNeighbor }},
		{"other interface", "10.97.0.5:8443", func(s Stats) uint64 { return s.WrongInterface }},
		{"blackhole", "198.51.100.1:8443", func(s Stats) uint64 { return s.FIBFailed }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNATFixture(t, natPorts)
			f.program(natWeb, 0, tc.backend)
			if ret, _ := f.run(frame(clientFlows(natWeb, 1, 26)[0])); ret != xdpDrop {
				t.Fatalf("action %d, want XDP_DROP", ret)
			}
			if got := tc.stat(f.stats()); got != 1 {
				t.Errorf("drop counter = %d, want 1", got)
			}
			if n := natEntries(t, f.x); n != 0 {
				t.Errorf("%d NAT entries allocated for an unroutable backend", n)
			}
		})
	}
}

func TestTTLExpiry(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	b := frame(clientFlows(natWeb, 1, 27)[0])
	ip, _ := headers(b)
	ip[8] = 1
	fixChecksums(b)
	if ret, _ := f.run(b); ret != xdpDrop {
		t.Fatalf("action %d, want XDP_DROP", ret)
	}
	if s := f.stats(); s.TTLExceeded != 1 {
		t.Errorf("TTLExceeded = %d, want 1", s.TTLExceeded)
	}
}

func TestUDPWithoutChecksum(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natDNS, 1, "10.98.0.11:5353")
	b := frame(clientFlows(natDNS, 1, 28)[0])
	_, l4 := headers(b)
	l4[6], l4[7] = 0, 0
	_, data := f.run(b)
	_, l4 = headers(data)
	if c := binary.BigEndian.Uint16(l4[6:]); c != 0 {
		t.Errorf("UDP checksum %#04x, want 0 (none) to stay 0", c)
	}
	decode(t, data) // IP checksum still valid
}

func TestStrayPacketsToSNATAddressPass(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	backend := netip.MustParseAddrPort(webPool[0])
	for name, dport := range map[string]uint16{"in range, no flow": 61500, "outside range": 22} {
		fl := Flow{Src: backend, Dst: netip.AddrPortFrom(natSNAT, dport), Proto: TCP}
		if ret, _ := f.run(withFlags(fl, tcpACK)); ret != xdpPass {
			t.Errorf("%s: action %d, want XDP_PASS", name, ret)
		}
	}
}

// TestPinnedStateSurvivesReload loads the program twice on the same pinned
// maps, as a restarted ferry does, and checks a flow keeps its mapping.
func TestPinnedStateSurvivesReload(t *testing.T) {
	pin := fmt.Sprintf("/sys/fs/bpf/ferry-test-%d", os.Getpid())
	if err := os.MkdirAll(pin, 0o700); err != nil {
		t.Skipf("no bpffs at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(pin) })

	f := newNATFixture(t, natPorts)
	f.x.Close()
	f.x = loadTestXDP(t, loadOptions{snat: natSNAT, ports: natPorts, pinPath: pin})
	f.program(natWeb, 0, webPool...)
	fl := clientFlows(natWeb, 1, 29)[0]
	first := f.forward(frame(fl))
	f.x.Close()

	f.x = loadTestXDP(t, loadOptions{snat: natSNAT, ports: natPorts, pinPath: pin})
	st, err := f.x.State()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Backends) != 3 || st.Services[natWeb] != 0 || len(st.Services) != 1 {
		t.Fatalf("restored state %+v, want 3 backends and %s as service 0", st, natWeb)
	}
	for id, b := range st.Backends {
		if f.ids[b.Addr] != id || !b.Active {
			t.Errorf("restored backend %d = %+v, want ID %d active", id, b, f.ids[b.Addr])
		}
	}
	if o := f.forward(withFlags(fl, tcpACK)); o.src != first.src || o.dst != first.dst {
		t.Fatalf("after reload %s -> %s, before %s -> %s", o.src, o.dst, first.src, first.dst)
	}
	if s := f.stats(); s.ConntrackHits != 1 || s.Forwarded != 2 {
		t.Errorf("stats after reload %+v: want the pinned counters carried over and one conntrack hit", s)
	}
}

// TestShadowThenForwardOnPinnedMaps: switching a running deployment from
// -shadow to forwarding is a restart on the same pinned maps. Flows tracked
// in shadow mode have no NAT state and must simply start over.
func TestShadowThenForwardOnPinnedMaps(t *testing.T) {
	pin := fmt.Sprintf("/sys/fs/bpf/ferry-test-shadow-%d", os.Getpid())
	if err := os.MkdirAll(pin, 0o700); err != nil {
		t.Skipf("no bpffs at /sys/fs/bpf: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(pin) })

	f := newNATFixture(t, natPorts)
	f.x.Close()
	f.x = loadTestXDP(t, loadOptions{shadow: true, pinPath: pin})
	f.program(natWeb, 0, webPool...)
	fl := clientFlows(natWeb, 1, 31)[0]
	if ret, _ := f.run(frame(fl)); ret != xdpPass {
		t.Fatalf("shadow mode: action %d, want XDP_PASS", ret)
	}
	shadowPick, ok := f.tracked(fl)
	if !ok {
		t.Fatal("shadow mode did not track the flow")
	}
	f.x.Close()

	f.x = loadTestXDP(t, loadOptions{snat: natSNAT, ports: natPorts, pinPath: pin})
	o := f.forward(withFlags(fl, tcpACK))
	if o.dst != shadowPick || o.src.Addr() != natSNAT {
		t.Errorf("forwarded %s -> %s; want from %s to the backend shadow mode picked, %s", o.src, o.dst, natSNAT, shadowPick)
	}
}

func mustMAC(t testing.TB, iface string) net.HardwareAddr {
	t.Helper()
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		t.Fatal(err)
	}
	return ifc.HardwareAddr
}

// BenchmarkIngressForward: in-kernel time per packet of a tracked TCP flow
// in forwarding mode (rewrite, checksums, FIB lookup).
func BenchmarkIngressForward(b *testing.B) {
	f := newNATFixture(b, natPorts)
	f.program(natWeb, 0, webPool...)
	fl := clientFlows(natWeb, 1, 30)[0]
	f.forward(frame(fl))
	data := withFlags(fl, tcpACK)
	_, d, err := f.x.objs.FerryIngress.Benchmark(data, b.N, b.ResetTimer)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(d.Nanoseconds()), "ns/pkt")
}
