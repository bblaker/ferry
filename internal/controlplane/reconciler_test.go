package controlplane

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/bblaker/ferry/internal/dataplane"
	"github.com/bblaker/ferry/internal/discovery"
	"github.com/bblaker/ferry/internal/maglev"
)

var web = dataplane.ServiceKey{VIP: netip.MustParseAddr("192.168.1.240"), Port: 443, Proto: dataplane.TCP}

func svc(key dataplane.ServiceKey, backends ...string) discovery.Service {
	s := discovery.Service{Name: key.String(), Key: key}
	for _, b := range backends {
		s.Backends = append(s.Backends, netip.MustParseAddrPort(b))
	}
	return s
}

func client(key dataplane.ServiceKey, src string) dataplane.Flow {
	return dataplane.Flow{Src: netip.MustParseAddrPort(src), Dst: netip.AddrPortFrom(key.VIP, key.Port), Proto: key.Proto}
}

func newTest(t *testing.T) (*Reconciler, *dataplane.Memory) {
	t.Helper()
	dp := dataplane.NewMemory()
	return NewReconciler(dp, maglev.DefaultSize, slog.New(slog.NewTextHandler(io.Discard, nil))), dp
}

func TestApplyProgramsAndRemovesServices(t *testing.T) {
	r, dp := newTest(t)
	if err := r.Apply([]discovery.Service{svc(web, "10.0.0.1:8443", "10.0.0.2:8443")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dp.Lookup(client(web, "10.1.2.3:40000")); !ok {
		t.Fatal("service not routable after Apply")
	}
	if err := r.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if dp.Services() != 0 {
		t.Fatal("service still programmed after removal")
	}
}

func TestRemovedBackendIsDeactivatedNotReused(t *testing.T) {
	r, dp := newTest(t)
	if err := r.Apply([]discovery.Service{svc(web, "10.0.0.1:8443", "10.0.0.2:8443")}); err != nil {
		t.Fatal(err)
	}
	goneID := r.backendIDs[netip.MustParseAddrPort("10.0.0.2:8443")]

	if err := r.Apply([]discovery.Service{svc(web, "10.0.0.1:8443", "10.0.0.3:8443")}); err != nil {
		t.Fatal(err)
	}
	if b, _ := dp.Backend(goneID); b.Active {
		t.Error("removed backend still active; conntrack entries would keep using it")
	}
	if id := r.backendIDs[netip.MustParseAddrPort("10.0.0.3:8443")]; id == goneID {
		t.Error("new backend reused a just-retired ID")
	}
}

func TestUnchangedServiceIsNotReprogrammed(t *testing.T) {
	r, _ := newTest(t)
	snap := []discovery.Service{svc(web, "10.0.0.1:8443", "10.0.0.2:8443")}
	if err := r.Apply(snap); err != nil {
		t.Fatal(err)
	}
	before := r.services[web]
	// Same set in a different order must not count as a change.
	if err := r.Apply([]discovery.Service{svc(web, "10.0.0.2:8443", "10.0.0.1:8443")}); err != nil {
		t.Fatal(err)
	}
	if r.services[web] != before {
		t.Error("table was rebuilt for an unchanged backend set")
	}
}

func TestEmptyServiceIsRemoved(t *testing.T) {
	r, dp := newTest(t)
	if err := r.Apply([]discovery.Service{svc(web, "10.0.0.1:8443")}); err != nil {
		t.Fatal(err)
	}
	if err := r.Apply([]discovery.Service{svc(web)}); err != nil {
		t.Fatal(err)
	}
	if dp.Services() != 0 {
		t.Error("service with no backends should be removed from the data plane")
	}
}

// TestRestoreKeepsIDs: a reconciler restarted on a surviving data plane must
// reuse its backend IDs, or tracked flows would resolve to whichever backend
// a fresh allocator handed their old ID to.
func TestRestoreKeepsIDs(t *testing.T) {
	r1, dp := newTest(t)
	snap := []discovery.Service{svc(web, "10.0.0.1:8443", "10.0.0.2:8443", "10.0.0.3:8443")}
	if err := r1.Apply(snap); err != nil {
		t.Fatal(err)
	}
	// Retire one so the restored allocator has a gap to respect.
	if err := r1.Apply([]discovery.Service{svc(web, "10.0.0.2:8443", "10.0.0.3:8443")}); err != nil {
		t.Fatal(err)
	}
	before := r1.Backends()

	st, err := dp.State()
	if err != nil {
		t.Fatal(err)
	}
	r2 := NewReconciler(dp, maglev.DefaultSize, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r2.Restore(st)
	snap = []discovery.Service{svc(web, "10.0.0.2:8443", "10.0.0.3:8443", "10.0.0.4:8443")}
	if err := r2.Apply(snap); err != nil {
		t.Fatal(err)
	}
	after := r2.Backends()
	for id, addr := range before {
		if after[id] != addr {
			t.Errorf("backend %s had ID %d; after restore ID %d is %s", addr, id, id, after[id])
		}
	}
	for id, addr := range after {
		if addr.String() == "10.0.0.4:8443" && id <= 2 {
			t.Errorf("new backend got ID %d, which the previous run used (IDs 0-2)", id)
		}
	}
	if dp.Services() != 1 {
		t.Errorf("%d services programmed, want 1", dp.Services())
	}
}

// addrs returns n backends 10.<net>.x.y:8443.
func addrs(net byte, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.%d.%d.%d:8443", net, i/256, i%256)
	}
	return out
}

// TestApplyRejectsWhatCanNeverFit: a snapshot that can't be applied fails
// with ErrInvalid before the data plane changes, so the daemon knows not to
// retry it and the running tables stay whole.
func TestApplyRejectsWhatCanNeverFit(t *testing.T) {
	manyServices := make([]discovery.Service, dataplane.MaxServices+1)
	for i := range manyServices {
		key := dataplane.ServiceKey{VIP: netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)}), Port: 443, Proto: dataplane.TCP}
		manyServices[i] = svc(key, "10.0.0.1:8443")
	}
	for _, tc := range []struct {
		name string
		snap []discovery.Service
	}{
		{"duplicate service", []discovery.Service{svc(web, "10.0.0.1:8443"), svc(web, "10.0.0.2:8443")}},
		{"too many services", manyServices},
		// 1000 running + 100 new > 1024, though the result would hold 100.
		{"old and new backends together", []discovery.Service{svc(web, addrs(2, 100)...)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, dp := newTest(t)
			if err := r.Apply([]discovery.Service{svc(web, addrs(1, 1000)...)}); err != nil {
				t.Fatal(err)
			}
			err := r.Apply(tc.snap)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Apply = %v, want ErrInvalid", err)
			}
			if dp.Services() != 1 || dp.ActiveBackends() != 1000 || len(r.Backends()) != 1000 {
				t.Errorf("data plane changed: %d services, %d active backends, %d IDs", dp.Services(), dp.ActiveBackends(), len(r.Backends()))
			}
		})
	}
}

// TestBackendSwapInTwoSteps follows the advice in the capacity error:
// shrink the old set first, then bring in the new one.
func TestBackendSwapInTwoSteps(t *testing.T) {
	r, dp := newTest(t)
	for _, bs := range [][]string{addrs(1, 1000), addrs(1, 924), addrs(2, 100)} {
		if err := r.Apply([]discovery.Service{svc(web, bs...)}); err != nil {
			t.Fatalf("%d backends: %v", len(bs), err)
		}
	}
	if got := dp.ServiceBackends(web); len(got) != 100 || got[0].Addr().As4()[1] != 2 {
		t.Errorf("serving %d backends starting %v, want the 100 new ones", len(got), got[0])
	}
}
