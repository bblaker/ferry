//go:build linux

package dataplane

// ICMP error translation tests, on the forwarding topology from
// nat_linux_test.go. An error is built the way the kernel builds one: it
// quotes the packet as its sender received it. After translation, the quote
// must match the packet the error's new recipient sent, byte for byte apart
// from the TTL, and every checksum is recomputed from scratch.

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

const (
	protoICMP      = 1
	icmpUnreach    = 3
	icmpTimeExceed = 11
	icmpEcho       = 8
	codePort       = 3 // with icmpUnreach
	codeFragNeeded = 4 // with icmpUnreach
	errMTU         = 1400
)

// icmpError builds an ICMP error from src to dst quoting the IP packet in
// frame pkt: its IP header and then n bytes (at most what there is).
func icmpError(src, dst netip.Addr, typ, code byte, pkt []byte, n int) []byte {
	ip, l4 := headers(pkt)
	quote := append(append([]byte(nil), ip...), l4[:min(n, len(l4))]...)
	b := make([]byte, 14+20+8+len(quote))
	binary.BigEndian.PutUint16(b[12:], ethIPv4)
	oip := b[14:34]
	oip[0] = 0x45
	binary.BigEndian.PutUint16(oip[2:], uint16(20+8+len(quote)))
	oip[8] = 64
	oip[9] = protoICMP
	s, d := src.As4(), dst.As4()
	copy(oip[12:], s[:])
	copy(oip[16:], d[:])
	binary.BigEndian.PutUint16(oip[10:], csum(oip, 0))
	icmp := b[34:]
	icmp[0], icmp[1] = typ, code
	if typ == icmpUnreach && code == codeFragNeeded {
		binary.BigEndian.PutUint16(icmp[6:], errMTU)
	}
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:], csum(icmp, 0))
	return b
}

// decodeICMP checks an output ICMP error's checksums, including the quoted
// IP header's, and returns its outer header and the ICMP message.
func decodeICMP(t testing.TB, b []byte) (out, []byte) {
	t.Helper()
	ip, icmp := headers(b)
	if c := csum(ip, 0); c != 0 {
		t.Fatalf("bad IP checksum in output (residual %#04x)", c)
	}
	if c := csum(icmp, 0); c != 0 {
		t.Fatalf("bad ICMP checksum in output (residual %#04x)", c)
	}
	qip := icmp[8 : 8+int(icmp[8]&0x0f)*4]
	if c := csum(qip, 0); c != 0 {
		t.Fatalf("bad checksum in the quoted IP header (residual %#04x)", c)
	}
	addr := func(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b)) }
	return out{
		dstMAC: b[0:6],
		srcMAC: b[6:12],
		src:    netip.AddrPortFrom(addr(ip[12:16]), 0),
		dst:    netip.AddrPortFrom(addr(ip[16:20]), 0),
		ttl:    ip[8],
	}, icmp
}

// wantQuote is what an error quoting n bytes past the IP header of the
// packet in frame pkt should carry, once pkt has crossed Ferry (TTL - 1).
func wantQuote(pkt []byte, n int) []byte {
	b := bytes.Clone(pkt)
	ip, l4 := headers(b)
	ip[8]--
	fixChecksums(b)
	return append(append([]byte(nil), ip...), l4[:min(n, len(l4))]...)
}

func checkTranslated(t testing.TB, icmp []byte, typ, code byte, want []byte) {
	t.Helper()
	if icmp[0] != typ || icmp[1] != code {
		t.Errorf("type/code %d/%d, want %d/%d", icmp[0], icmp[1], typ, code)
	}
	if typ == icmpUnreach && code == codeFragNeeded {
		if mtu := binary.BigEndian.Uint16(icmp[6:]); mtu != errMTU {
			t.Errorf("next-hop MTU %d, want %d unchanged", mtu, errMTU)
		}
	}
	if got := icmp[8:]; !bytes.Equal(got, want) {
		t.Errorf("quote\n got %x\nwant %x", got, want)
	}
}

// TestICMPErrorReachesClient: an error about a packet Ferry sent to a
// backend goes to the client, about the packet the client sent.
func TestICMPErrorReachesClient(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	f.program(natDNS, 1, "10.98.0.11:5353")

	for _, tc := range []struct {
		name       string
		key        ServiceKey
		client     netip.Addr
		nextHop    netip.Addr
		fromRouter bool // sent by a router on the way to the backend, not the backend
		typ, code  byte
		quote      int // bytes quoted past the IP header
		ipOptWords int
	}{
		{"frag needed from the backend", natWeb, natClient, natClient, false, icmpUnreach, codeFragNeeded, 20, 0},
		{"port unreachable, udp", natDNS, natClient, natClient, false, icmpUnreach, codePort, 8, 0},
		{"time exceeded from a router, 8-byte quote", natWeb, natClient, natClient, true, icmpTimeExceed, 0, 8, 0},
		{"quoted header with IP options", natWeb, natClient, natClient, false, icmpUnreach, codeFragNeeded, 20, 2},
		{"client via gateway", natWeb, natRemote, natGW, false, icmpUnreach, codeFragNeeded, 20, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fl := Flow{Src: netip.AddrPortFrom(tc.client, 40123), Dst: netip.AddrPortFrom(tc.key.VIP, tc.key.Port), Proto: tc.key.Proto}
			sent := frame(fl, tc.ipOptWords)
			ret, fwd := f.run(sent)
			if ret != xdpTX {
				t.Fatalf("forward: action %d, want XDP_TX", ret)
			}
			backend := decode(t, fwd).dst.Addr()
			from := backend
			if tc.fromRouter {
				from = natGW
			}

			before := f.stats().ICMPToClient
			ret, data := f.run(icmpError(from, natSNAT, tc.typ, tc.code, fwd, tc.quote))
			if ret != xdpTX {
				t.Fatalf("error: action %d, want XDP_TX; stats %+v", ret, f.stats())
			}
			o, icmp := decodeICMP(t, data)
			if o.src.Addr() != tc.key.VIP || o.dst.Addr() != tc.client {
				t.Errorf("error sent %s -> %s, want %s -> %s", o.src.Addr(), o.dst.Addr(), tc.key.VIP, tc.client)
			}
			if o.dstMAC.String() != macFor(tc.nextHop).String() {
				t.Errorf("error sent to %s, want next hop %s (%s)", o.dstMAC, tc.nextHop, macFor(tc.nextHop))
			}
			if o.ttl != 63 {
				t.Errorf("TTL %d, want 63", o.ttl)
			}
			checkTranslated(t, icmp, tc.typ, tc.code, wantQuote(sent, tc.quote))
			if f.stats().ICMPToClient != before+1 {
				t.Error("error not counted")
			}
		})
	}
}

// TestICMPErrorReachesBackend: an error about a reply Ferry sent to a client
// goes to the backend, about the reply the backend sent.
func TestICMPErrorReachesBackend(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	f.program(natDNS, 1, "10.98.0.11:5353")

	for _, tc := range []struct {
		name      string
		key       ServiceKey
		client    netip.Addr
		from      netip.Addr // the error's sender
		typ, code byte
		quote     int
	}{
		{"frag needed from a router near the client", natWeb, natRemote, natGW, icmpUnreach, codeFragNeeded, 20},
		{"port unreachable from the client, udp", natDNS, natClient, natClient, icmpUnreach, codePort, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fl := Flow{Src: netip.AddrPortFrom(tc.client, 40124), Dst: netip.AddrPortFrom(tc.key.VIP, tc.key.Port), Proto: tc.key.Proto}
			fwd := f.forward(frame(fl))
			sent := replyFrom(fwd, tc.key.Proto, tcpSYN|tcpACK)
			ret, rep := f.run(sent)
			if ret != xdpTX {
				t.Fatalf("reply: action %d, want XDP_TX", ret)
			}

			before := f.stats().ICMPToBackend
			ret, data := f.run(icmpError(tc.from, tc.key.VIP, tc.typ, tc.code, rep, tc.quote))
			if ret != xdpTX {
				t.Fatalf("error: action %d, want XDP_TX; stats %+v", ret, f.stats())
			}
			o, icmp := decodeICMP(t, data)
			if o.src.Addr() != natSNAT || o.dst.Addr() != fwd.dst.Addr() {
				t.Errorf("error sent %s -> %s, want %s -> %s", o.src.Addr(), o.dst.Addr(), natSNAT, fwd.dst.Addr())
			}
			if o.dstMAC.String() != macFor(fwd.dst.Addr()).String() {
				t.Errorf("error sent to %s, want the backend's %s", o.dstMAC, macFor(fwd.dst.Addr()))
			}
			checkTranslated(t, icmp, tc.typ, tc.code, wantQuote(sent, tc.quote))
			if f.stats().ICMPToBackend != before+1 {
				t.Error("error not counted")
			}
		})
	}
}

// TestICMPNotAboutAFlow: anything that isn't an error about a live NATed
// flow goes to the kernel untouched.
func TestICMPNotAboutAFlow(t *testing.T) {
	f := newNATFixture(t, natPorts)
	f.program(natWeb, 0, webPool...)
	fl := clientFlows(natWeb, 1, 40)[0]
	_, fwd := f.run(frame(fl))
	toBackend := decode(t, fwd)
	backend := toBackend.dst.Addr()
	untracked := natPorts.Max
	if untracked == toBackend.src.Port() {
		untracked--
	}

	// with returns a copy of the forwarded frame, changed by edit.
	with := func(edit func(ip, l4 []byte)) []byte {
		b := bytes.Clone(fwd)
		ip, l4 := headers(b)
		edit(ip, l4)
		fixChecksums(b)
		return b
	}
	for _, tc := range []struct {
		name string
		data []byte
		want uint32
	}{
		{"echo request to the SNAT address", icmpError(backend, natSNAT, icmpEcho, 0, fwd, 8), xdpPass},
		{"quoting the host's own traffic", icmpError(backend, natSNAT, icmpUnreach, codePort,
			with(func(_, l4 []byte) { binary.BigEndian.PutUint16(l4, 22) }), 8), xdpPass},
		{"quoting an untracked SNAT port", icmpError(backend, natSNAT, icmpUnreach, codePort,
			with(func(_, l4 []byte) { binary.BigEndian.PutUint16(l4, untracked) }), 8), xdpPass},
		{"quote too short for the ports", icmpError(backend, natSNAT, icmpUnreach, codePort, fwd, 2), xdpPass},
		{"quoting a non-first fragment", icmpError(backend, natSNAT, icmpUnreach, codePort,
			with(func(ip, _ []byte) { binary.BigEndian.PutUint16(ip[6:], 100) }), 8), xdpPass},
		{"not sent to the quoted packet's source", icmpError(backend, natClient, icmpUnreach, codePort, fwd, 8), xdpPass},
		{"to a VIP, quoting no tracked flow", icmpError(natClient, natWeb.VIP, icmpUnreach, codePort,
			frame(Flow{Src: netip.AddrPortFrom(natWeb.VIP, 443), Dst: netip.AddrPortFrom(natClient, 9), Proto: TCP}), 8), xdpPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ret, data := f.run(tc.data); ret != tc.want {
				t.Errorf("action %d, want %d", ret, tc.want)
			} else if ret == xdpPass && !bytes.Equal(data, tc.data) {
				t.Error("passed packet was modified")
			}
		})
	}

	t.Run("TTL would reach zero", func(t *testing.T) {
		b := icmpError(backend, natSNAT, icmpUnreach, codePort, fwd, 8)
		ip, _ := headers(b)
		ip[8] = 1
		ip[10], ip[11] = 0, 0
		binary.BigEndian.PutUint16(ip[10:], csum(ip, 0))
		before := f.stats().TTLExceeded
		if ret, _ := f.run(b); ret != xdpDrop {
			t.Errorf("action %d, want XDP_DROP", ret)
		}
		if f.stats().TTLExceeded != before+1 {
			t.Error("drop not counted")
		}
	})

	// Last: it ends the flow.
	t.Run("about an expired flow", func(t *testing.T) {
		f.expire(toBackend.dst, toBackend.src.Port(), TCP)
		if ret, _ := f.run(icmpError(backend, natSNAT, icmpUnreach, codePort, fwd, 8)); ret != xdpPass {
			t.Errorf("action %d, want XDP_PASS", ret)
		}
	})

	if s := f.stats(); s.ICMPToClient != 0 || s.ICMPToBackend != 0 {
		t.Errorf("translated %d errors to clients and %d to backends, want none", s.ICMPToClient, s.ICMPToBackend)
	}
}

// TestICMPAboutAnEndedFlowFromClientSide: a client-side error names its flow
// by client and VIP, and conntrack may still map that flow to a SNAT port
// after the flow has expired, or after the port has gone to another flow.
// Neither may reach the backend. A one-port pool forces the reuse.
func TestICMPAboutAnEndedFlowFromClientSide(t *testing.T) {
	f := newNATFixture(t, PortRange{61000, 61000})
	f.program(natWeb, 0, webPool[0])
	fls := clientFlows(natWeb, 2, 41)
	errorAbout := func(fl Flow) []byte {
		fwd := f.forward(frame(fl))
		_, rep := f.run(replyFrom(fwd, TCP, tcpACK))
		return icmpError(natClient, natWeb.VIP, icmpUnreach, codeFragNeeded, rep, 20)
	}
	oldErr := errorAbout(fls[0])
	backend := netip.MustParseAddrPort(webPool[0])

	f.expire(backend, 61000, TCP)
	if ret, _ := f.run(oldErr); ret != xdpPass {
		t.Errorf("about an expired flow: action %d, want XDP_PASS", ret)
	}
	newErr := errorAbout(fls[1]) // takes over port 61000
	if ret, _ := f.run(oldErr); ret != xdpPass {
		t.Errorf("about a flow whose port was reused: action %d, want XDP_PASS", ret)
	}
	if ret, _ := f.run(newErr); ret != xdpTX {
		t.Errorf("about the port's current flow: action %d, want XDP_TX", ret)
	}
}

func TestICMPPassesInShadowMode(t *testing.T) {
	f := newFixture(t)
	f.program(testVIP, 0, "10.0.0.1:8443")
	fl := Flow{Src: netip.MustParseAddrPort("192.168.1.10:40000"), Dst: netip.AddrPortFrom(testVIP.VIP, testVIP.Port), Proto: TCP}
	f.send(frame(fl)) // tracked, with no NAT state
	reply := frame(Flow{Src: fl.Dst, Dst: fl.Src, Proto: TCP})
	if ret, _ := f.run(icmpError(fl.Src.Addr(), testVIP.VIP, icmpUnreach, codeFragNeeded, reply, 20)); ret != xdpPass {
		t.Errorf("action %d, want XDP_PASS", ret)
	}
}
