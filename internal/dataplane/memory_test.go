package dataplane

import (
	"net/netip"
	"testing"
)

var (
	memVIP = ServiceKey{VIP: netip.MustParseAddr("192.168.1.240"), Port: 443, Proto: TCP}
	memB0  = netip.MustParseAddrPort("10.0.0.1:8443")
)

func TestMemoryEnforcesOrdering(t *testing.T) {
	m := NewMemory()
	if err := m.SetService(memVIP, 0, []uint32{0, 0, 0}); err == nil {
		t.Error("table installed before its backend was activated")
	}
	if err := m.SetBackend(0, Backend{Addr: memB0, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetService(memVIP, 0, []uint32{0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetBackend(0, Backend{Addr: memB0}); err == nil {
		t.Error("backend deactivated while an installed table references it")
	}
	if err := m.DeleteService(memVIP, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.SetBackend(0, Backend{Addr: memB0}); err != nil {
		t.Errorf("deactivating an unreferenced backend: %v", err)
	}
}

func TestMemoryRejectsBadInput(t *testing.T) {
	m := NewMemory()
	if err := m.SetBackend(MaxBackends, Backend{Addr: memB0}); err == nil {
		t.Error("backend id out of range accepted")
	}
	if err := m.SetBackend(0, Backend{Addr: netip.MustParseAddrPort("[fd00::1]:80")}); err == nil {
		t.Error("IPv6 backend accepted")
	}
	if err := m.SetService(memVIP, MaxServices, []uint32{0}); err == nil {
		t.Error("service id out of range accepted")
	}
	if err := m.SetService(memVIP, 0, nil); err == nil {
		t.Error("empty table accepted")
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"xdp-native", "xdp-generic"} {
		if _, err := ParseMode(s); err != nil {
			t.Errorf("ParseMode(%q): %v", s, err)
		}
	}
	if _, err := ParseMode("native"); err == nil {
		t.Error(`ParseMode("native") accepted`)
	}
}
