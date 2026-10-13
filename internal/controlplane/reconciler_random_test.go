package controlplane

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/bblaker/ferry/internal/dataplane"
	"github.com/bblaker/ferry/internal/discovery"
)

var errInjected = errors.New("injected failure")

// flaky fails a fraction of data plane calls before they take effect, the
// way a kernel map update can fail (ENOMEM, E2BIG) partway through Apply.
type flaky struct {
	*dataplane.Memory
	r    *rand.Rand
	rate float64
}

func (f *flaky) fail() bool { return f.r.Float64() < f.rate }

func (f *flaky) SetBackend(id uint32, b dataplane.Backend) error {
	if f.fail() {
		return errInjected
	}
	return f.Memory.SetBackend(id, b)
}

func (f *flaky) SetService(key dataplane.ServiceKey, id uint32, slots []uint32) error {
	if f.fail() {
		return errInjected
	}
	return f.Memory.SetService(key, id, slots)
}

func (f *flaky) DeleteService(key dataplane.ServiceKey, id uint32) error {
	if f.fail() {
		return errInjected
	}
	return f.Memory.DeleteService(key, id)
}

// randomSnapshot draws services from a small pool of VIPs and backends so
// consecutive snapshots overlap: backends move between services, services
// empty out and come back.
func randomSnapshot(r *rand.Rand) []discovery.Service {
	var out []discovery.Service
	for v := range 6 {
		if r.IntN(4) == 0 {
			continue // service absent
		}
		key := dataplane.ServiceKey{VIP: netip.AddrFrom4([4]byte{192, 168, 1, byte(240 + v)}), Port: 443, Proto: dataplane.TCP}
		s := discovery.Service{Name: fmt.Sprint(v), Key: key}
		for range r.IntN(7) { // 0..6 backends, duplicates allowed
			s.Backends = append(s.Backends, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(1 + r.IntN(20))}), 8443))
		}
		out = append(out, s)
	}
	return out
}

// TestApplyRandomized drives the reconciler through random snapshot
// sequences with injected failures. Memory rejects any update that breaks
// the Dataplane ordering contract, so the only errors allowed out of Apply
// are injected ones, and a clean retry must always converge.
func TestApplyRandomized(t *testing.T) {
	for seed := range uint64(100) {
		r := rand.New(rand.NewPCG(seed, 1))
		mem := dataplane.NewMemory()
		dp := &flaky{Memory: mem, r: r}
		// A small prime table keeps thousands of rebuilds fast; Memory accepts
		// any size.
		rec := NewReconciler(dp, 251, slog.New(slog.NewTextHandler(io.Discard, nil)))

		for step := range 30 {
			snap := randomSnapshot(r)
			dp.rate = 0.05
			if err := rec.Apply(snap); err != nil && !errors.Is(err, errInjected) {
				t.Fatalf("seed %d step %d: contract violation: %v", seed, step, err)
			}
			dp.rate = 0
			if err := rec.Apply(snap); err != nil {
				t.Fatalf("seed %d step %d: retry failed: %v", seed, step, err)
			}
			checkConverged(t, mem, rec, snap, fmt.Sprintf("seed %d step %d", seed, step))
		}
	}
}

func checkConverged(t *testing.T, mem *dataplane.Memory, rec *Reconciler, snap []discovery.Service, at string) {
	t.Helper()
	used := map[netip.AddrPort]bool{}
	services := 0
	for _, s := range snap {
		want := slices.Clone(s.Backends)
		slices.SortFunc(want, netip.AddrPort.Compare)
		want = slices.Compact(want)
		if len(want) > 0 {
			services++
		}
		if got := mem.ServiceBackends(s.Key); !slices.Equal(got, want) {
			t.Fatalf("%s: %s serves %v, want %v", at, s.Key, got, want)
		}
		for _, b := range want {
			used[b] = true
		}
	}
	if got := mem.Services(); got != services {
		t.Fatalf("%s: %d services programmed, want %d", at, got, services)
	}
	if got := mem.ActiveBackends(); got != len(used) {
		t.Fatalf("%s: %d active backends, want %d (leaked or missing)", at, got, len(used))
	}
	if got := len(rec.Backends()); got != len(used) {
		t.Fatalf("%s: reconciler tracks %d backend IDs, want %d", at, got, len(used))
	}
}

// TestFullServiceTableCanChange: with every service slot in use, replacing
// one VIP must still work. It needs the old service deleted before the new
// one is allocated.
func TestFullServiceTableCanChange(t *testing.T) {
	r, dp := newTest(t)
	snap := make([]discovery.Service, dataplane.MaxServices)
	for i := range snap {
		key := dataplane.ServiceKey{VIP: netip.AddrFrom4([4]byte{192, 168, byte(i / 256), byte(i % 256)}), Port: 443, Proto: dataplane.TCP}
		snap[i] = svc(key, "10.0.0.1:8443")
	}
	if err := r.Apply(snap); err != nil {
		t.Fatal(err)
	}
	snap[0] = svc(dataplane.ServiceKey{VIP: netip.MustParseAddr("192.168.200.1"), Port: 443, Proto: dataplane.TCP}, "10.0.0.1:8443")
	if err := r.Apply(snap); err != nil {
		t.Fatalf("replacing one of %d services: %v", dataplane.MaxServices, err)
	}
	if dp.Services() != dataplane.MaxServices {
		t.Errorf("%d services programmed, want %d", dp.Services(), dataplane.MaxServices)
	}
}
