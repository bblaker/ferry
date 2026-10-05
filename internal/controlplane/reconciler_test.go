package controlplane

import (
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
	if _, ok := dp.Lookup(web, 12345); !ok {
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
