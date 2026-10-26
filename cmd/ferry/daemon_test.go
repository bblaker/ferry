package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bblaker/ferry/internal/dataplane"
)

const (
	twoBackends = `{"services": [{"name": "web", "vip": "192.168.1.240:443", "backends": ["10.0.0.1:8443", "10.0.0.2:8443"]}]}`
	oneBackend  = `{"services": [{"name": "web", "vip": "192.168.1.240:443", "backends": ["10.0.0.1:8443"]}]}`
)

var web = dataplane.ServiceKey{VIP: netip.MustParseAddr("192.168.1.240"), Port: 443, Proto: dataplane.TCP}

// counting is a Memory data plane with canned packet counters.
type counting struct {
	*dataplane.Memory
	stats dataplane.Stats
}

func (c *counting) Stats() (dataplane.Stats, error) { return c.stats, nil }

func newTestDaemon(t *testing.T, config string) (*daemon, *counting, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ferry.json")
	writeFile(t, path, config)
	dp := &counting{Memory: dataplane.NewMemory()}
	d := newDaemon(dp, path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := d.reload(); err != nil {
		t.Fatal(err)
	}
	return d, dp, path
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReload(t *testing.T) {
	d, dp, path := newTestDaemon(t, twoBackends)
	if got := len(dp.ServiceBackends(web)); got != 2 {
		t.Fatalf("%d backends programmed, want 2", got)
	}

	writeFile(t, path, oneBackend)
	if err := d.reload(); err != nil {
		t.Fatal(err)
	}
	if got := len(dp.ServiceBackends(web)); got != 1 {
		t.Fatalf("after reload: %d backends programmed, want 1", got)
	}
}

func TestBadReloadKeepsTables(t *testing.T) {
	d, dp, path := newTestDaemon(t, twoBackends)
	for _, bad := range []string{
		`{"services": [`,
		`{"services": [{"name": "web", "vip": "192.168.1.240:443", "backend": ["10.0.0.9:8443"]}]}`,
	} {
		writeFile(t, path, bad)
		if err := d.reload(); err == nil {
			t.Fatalf("reload of %q succeeded", bad)
		}
		if got := len(dp.ServiceBackends(web)); got != 2 {
			t.Fatalf("rejected config changed the data plane: %d backends", got)
		}
	}
	body := get(t, d, "/healthz", http.StatusOK)
	if !strings.Contains(body, "last reload failed") {
		t.Errorf("healthz = %q, want it to report the failed reload", body)
	}
	m := get(t, d, "/metrics", http.StatusOK)
	for _, want := range []string{
		`ferry_config_reloads_total{result="success"} 1`,
		`ferry_config_reloads_total{result="failure"} 2`,
		`ferry_config_last_reload_successful 0`,
	} {
		if !strings.Contains(m, want+"\n") {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestMetrics(t *testing.T) {
	d, dp, _ := newTestDaemon(t, twoBackends)
	ids := d.rec.Backends()
	byAddr := map[string]uint32{}
	for id, a := range ids {
		byAddr[a.String()] = id
	}
	dp.stats = dataplane.Stats{
		Packets: 100, ServiceHits: 60, ConntrackHits: 50, ConntrackReselects: 2, NoTable: 1, NoBackend: 3,
		Forwarded: 58, Replied: 40, SNATExhausted: 4, NoNeighbor: 5, FIBFailed: 6, WrongInterface: 7, TTLExceeded: 8,
		BackendPackets: map[uint32]uint64{byAddr["10.0.0.1:8443"]: 35, byAddr["10.0.0.2:8443"]: 25},
	}

	m := get(t, d, "/metrics", http.StatusOK)
	for _, want := range []string{
		"ferry_packets_total 100",
		"ferry_service_hits_total 60",
		"ferry_conntrack_hits_total 50",
		"ferry_conntrack_reselects_total 2",
		"ferry_no_table_total 1",
		"ferry_no_backend_total 3",
		`ferry_forwarded_packets_total{direction="to_backend"} 58`,
		`ferry_forwarded_packets_total{direction="to_client"} 40`,
		`ferry_dropped_packets_total{reason="snat_exhausted"} 4`,
		`ferry_dropped_packets_total{reason="no_neighbor"} 5`,
		`ferry_dropped_packets_total{reason="fib_failed"} 6`,
		`ferry_dropped_packets_total{reason="wrong_interface"} 7`,
		`ferry_dropped_packets_total{reason="ttl_exceeded"} 8`,
		`ferry_backend_packets_total{backend="10.0.0.1:8443"} 35`,
		`ferry_backend_packets_total{backend="10.0.0.2:8443"} 25`,
		"ferry_services 1",
		"ferry_backends 2",
		`ferry_config_reloads_total{result="success"} 1`,
		"ferry_config_last_reload_successful 1",
		"# TYPE ferry_packets_total counter",
	} {
		if !strings.Contains(m, want+"\n") {
			t.Errorf("metrics missing %q", want)
		}
	}
	if t.Failed() {
		t.Log(m)
	}
	// Every sample line must be "name[{labels}] value".
	for line := range strings.Lines(m) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if f := strings.Fields(line); len(f) != 2 || !strings.HasPrefix(f[0], "ferry_") {
			t.Errorf("malformed sample line %q", line)
		}
	}
}

func get(t *testing.T, d *daemon, path string, wantCode int) string {
	t.Helper()
	rec := httptest.NewRecorder()
	d.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != wantCode {
		t.Fatalf("GET %s: %d, want %d", path, rec.Code, wantCode)
	}
	return rec.Body.String()
}
