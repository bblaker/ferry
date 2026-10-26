package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bblaker/ferry/internal/controlplane"
	"github.com/bblaker/ferry/internal/dataplane"
)

const (
	twoBackends = `{"services": [{"name": "web", "vip": "192.168.1.240:443", "backends": ["10.0.0.1:8443", "10.0.0.2:8443"]}]}`
	oneBackend  = `{"services": [{"name": "web", "vip": "192.168.1.240:443", "backends": ["10.0.0.1:8443"]}]}`
)

var web = dataplane.ServiceKey{VIP: netip.MustParseAddr("192.168.1.240"), Port: 443, Proto: dataplane.TCP}

// counting is a Memory data plane with canned packet counters. It fails its
// next failN updates, as a kernel map update can (ENOMEM).
type counting struct {
	*dataplane.Memory
	stats dataplane.Stats
	failN int
}

var errNoMem = errors.New("update map: cannot allocate memory")

func (c *counting) Stats() (dataplane.Stats, error) { return c.stats, nil }

func (c *counting) fail() bool {
	if c.failN > 0 {
		c.failN--
		return true
	}
	return false
}

func (c *counting) SetBackend(id uint32, b dataplane.Backend) error {
	if c.fail() {
		return errNoMem
	}
	return c.Memory.SetBackend(id, b)
}

func (c *counting) SetService(key dataplane.ServiceKey, id uint32, slots []uint32) error {
	if c.fail() {
		return errNoMem
	}
	return c.Memory.SetService(key, id, slots)
}

func (c *counting) DeleteService(key dataplane.ServiceKey, id uint32) error {
	if c.fail() {
		return errNoMem
	}
	return c.Memory.DeleteService(key, id)
}

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
		"ferry_dataplane_converged 1",
		`ferry_dataplane_apply_retries_total{result="failure"} 0`,
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

// metricsHave fails the test unless every sample is in d's metrics.
func metricsHave(t *testing.T, d *daemon, samples ...string) {
	t.Helper()
	m := get(t, d, "/metrics", http.StatusOK)
	for _, want := range samples {
		if !strings.Contains(m, want+"\n") {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func wantRetryIn(t *testing.T, d *daemon, want time.Duration) {
	t.Helper()
	got, ok := d.retryDelay()
	switch {
	case want == 0 && ok:
		t.Errorf("retry scheduled in %v, want none (converged)", got)
	case want != 0 && !ok:
		t.Errorf("no retry scheduled, want one in %v", want)
	case got != want:
		t.Errorf("retry in %v, want %v", got, want)
	}
}

// TestRetryAfterPartialFailure: a valid config whose programming fails is
// accepted, reported as not converged, and retried with backoff until it
// lands.
func TestRetryAfterPartialFailure(t *testing.T) {
	d, dp, path := newTestDaemon(t, twoBackends)
	writeFile(t, path, oneBackend)
	dp.failN = 2 // the reload and the first retry
	if err := d.reload(); !errors.Is(err, errNoMem) {
		t.Fatalf("reload = %v, want the data plane error", err)
	}
	metricsHave(t, d, "ferry_config_last_reload_successful 1", "ferry_dataplane_converged 0")
	if body := get(t, d, "/healthz", http.StatusOK); !strings.Contains(body, "not converged") {
		t.Errorf("healthz = %q, want it to report the pending update", body)
	}
	wantRetryIn(t, d, time.Second)

	if err := d.retry(); !errors.Is(err, errNoMem) {
		t.Fatalf("first retry = %v, want the data plane error", err)
	}
	wantRetryIn(t, d, 2*time.Second)

	if err := d.retry(); err != nil {
		t.Fatalf("second retry: %v", err)
	}
	wantRetryIn(t, d, 0)
	if got := len(dp.ServiceBackends(web)); got != 1 {
		t.Errorf("%d backends programmed after the retry, want 1", got)
	}
	metricsHave(t, d,
		"ferry_dataplane_converged 1",
		`ferry_dataplane_apply_retries_total{result="success"} 1`,
		`ferry_dataplane_apply_retries_total{result="failure"} 1`,
		`ferry_config_reloads_total{result="failure"} 0`,
	)
	if body := get(t, d, "/healthz", http.StatusOK); body != "ok\n" {
		t.Errorf("healthz = %q, want ok", body)
	}
}

// TestRejectedReloadKeepsRetrying: a bad config arriving mid-retry is
// rejected, and the retry still converges on the last accepted config.
func TestRejectedReloadKeepsRetrying(t *testing.T) {
	d, dp, path := newTestDaemon(t, twoBackends)
	writeFile(t, path, oneBackend)
	dp.failN = 1
	d.reload()
	writeFile(t, path, `{"services": [`)
	if err := d.reload(); err == nil {
		t.Fatal("bad config accepted")
	}
	wantRetryIn(t, d, time.Second)
	if err := d.retry(); err != nil {
		t.Fatal(err)
	}
	if got := len(dp.ServiceBackends(web)); got != 1 {
		t.Errorf("%d backends programmed, want 1 (the last accepted config)", got)
	}
	metricsHave(t, d, "ferry_config_last_reload_successful 0", "ferry_dataplane_converged 1")
}

// TestReloadReplacesRetry: a newer config replaces the one being retried,
// and its retries back off from the start.
func TestReloadReplacesRetry(t *testing.T) {
	d, dp, path := newTestDaemon(t, twoBackends)
	writeFile(t, path, oneBackend)
	dp.failN = 2
	d.reload()
	d.retry()
	wantRetryIn(t, d, 2*time.Second)

	writeFile(t, path, twoBackends)
	dp.failN = 1
	if err := d.reload(); !errors.Is(err, errNoMem) {
		t.Fatalf("reload = %v, want the data plane error", err)
	}
	wantRetryIn(t, d, time.Second)
	if err := d.retry(); err != nil {
		t.Fatal(err)
	}
	if got := len(dp.ServiceBackends(web)); got != 2 {
		t.Errorf("%d backends programmed, want 2 (the newer config)", got)
	}
}

// TestConfigThatCannotFitIsRejected: a config the tables can't hold is
// rejected outright, not retried, and the running tables stay whole.
func TestConfigThatCannotFitIsRejected(t *testing.T) {
	d, dp, path := newTestDaemon(t, twoBackends)
	var bs []string
	for i := range dataplane.MaxBackends + 1 {
		bs = append(bs, fmt.Sprintf("%q", fmt.Sprintf("10.1.%d.%d:8443", i/256, i%256)))
	}
	writeFile(t, path, `{"services": [{"name": "web", "vip": "192.168.1.240:443", "backends": [`+strings.Join(bs, ",")+`]}]}`)
	if err := d.reload(); !errors.Is(err, controlplane.ErrInvalid) {
		t.Fatalf("reload = %v, want ErrInvalid", err)
	}
	wantRetryIn(t, d, 0)
	if got := len(dp.ServiceBackends(web)); got != 2 {
		t.Errorf("%d backends programmed, want the original 2", got)
	}
	metricsHave(t, d, "ferry_config_last_reload_successful 0", "ferry_dataplane_converged 1")
}

func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{
		1: time.Second, 2: 2 * time.Second, 6: 32 * time.Second, 7: time.Minute, 100: time.Minute,
	} {
		if got := backoff(n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}
