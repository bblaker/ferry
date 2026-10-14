package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/bblaker/ferry/internal/controlplane"
	"github.com/bblaker/ferry/internal/dataplane"
	"github.com/bblaker/ferry/internal/discovery"
	"github.com/bblaker/ferry/internal/maglev"
)

// daemon serializes reloads and metric reads around the reconciler, which is
// not safe for concurrent use.
type daemon struct {
	dp     dataplane.Dataplane
	config string
	log    *slog.Logger

	applied chan struct{} // signalled after each successful apply

	mu        sync.Mutex
	rec       *controlplane.Reconciler
	reloads   map[string]uint64 // by result: "success", "failure"
	lastOK    time.Time
	lastError error
}

func newDaemon(dp dataplane.Dataplane, config string, log *slog.Logger) *daemon {
	return &daemon{
		dp:      dp,
		config:  config,
		log:     log,
		applied: make(chan struct{}, 1),
		rec:     controlplane.NewReconciler(dp, maglev.DefaultSize, log),
		reloads: map[string]uint64{"success": 0, "failure": 0},
	}
}

// apply programs a snapshot and records the outcome.
func (d *daemon) apply(services []discovery.Service) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	err := d.rec.Apply(services)
	d.record(err)
	if err == nil {
		select {
		case d.applied <- struct{}{}:
		default:
		}
	}
	return err
}

// warmNeighbors keeps the kernel's neighbor (ARP) entries for each
// backend's next hop resolved. The XDP program reads them through
// bpf_fib_lookup but can't trigger resolution: a miss drops the packet and
// counts it as no_neighbor. Sending a zero-length UDP datagram to the
// backend's discard port makes the kernel resolve the next hop.
//
// It also warns about backends routed out of another interface, which
// one-armed forwarding can't reach.
func (d *daemon) warmNeighbors(ctx context.Context, iface string, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	warned := map[netip.Addr]bool{}
	for {
		d.mu.Lock()
		backends := d.rec.Backends()
		d.mu.Unlock()
		local, _ := ifaceAddrs(iface)

		seen := map[netip.Addr]bool{}
		for _, b := range backends {
			ip := b.Addr()
			if seen[ip] {
				continue
			}
			seen[ip] = true
			c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 9)))
			if err != nil {
				if !warned[ip] {
					d.log.Warn("backend unreachable", "backend", ip, "err", err)
					warned[ip] = true
				}
				continue
			}
			src := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
			c.Write(nil)
			c.Close()
			if len(local) > 0 && !slices.Contains(local, src) && !warned[ip] {
				d.log.Warn("backend is routed out of another interface; ferry only forwards out of "+iface, "backend", ip, "source", src)
				warned[ip] = true
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.applied:
		}
	}
}

func (d *daemon) record(err error) {
	if err != nil {
		d.reloads["failure"]++
		d.lastError = err
		return
	}
	d.reloads["success"]++
	d.lastOK = time.Now()
	d.lastError = nil
}

// reload re-reads the config file. If the file is invalid, the data plane is
// left exactly as it was. If programming fails partway, it is left partially
// updated, which the next successful reload repairs.
func (d *daemon) reload() error {
	services, err := discovery.LoadFile(d.config)
	if err != nil {
		d.mu.Lock()
		d.record(err)
		d.mu.Unlock()
		d.log.Error("reload: config rejected; keeping current tables", "err", err)
		return err
	}
	if err := d.apply(services); err != nil {
		d.log.Error("reload: programming failed; data plane may be partially updated", "err", err)
		return err
	}
	d.log.Info("reloaded", "config", d.config, "services", len(services))
	return nil
}

func (d *daemon) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", d.serveMetrics)
	mux.HandleFunc("GET /healthz", d.serveHealth)
	return mux
}

// serveHealth reports 200 whenever the daemon is up: the data plane is
// attached and programmed, even if the latest reload was rejected. The body
// says which.
func (d *daemon) serveHealth(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	lastErr := d.lastError
	d.mu.Unlock()
	if lastErr != nil {
		fmt.Fprintf(w, "ok; last reload failed: %v\n", lastErr)
		return
	}
	fmt.Fprintln(w, "ok")
}

// serveMetrics writes the Prometheus text format by hand; there are few
// enough series that a client library would be the larger dependency.
func (d *daemon) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	backends := d.rec.Backends()
	services := d.rec.Services()
	ok, failed := d.reloads["success"], d.reloads["failure"]
	lastOK, lastErr := d.lastOK, d.lastError
	d.mu.Unlock()

	stats, err := d.dp.Stats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(w, metricsSnapshot{
		stats:    stats,
		backends: backends,
		services: services,
		reloadOK: ok, reloadFailed: failed,
		lastOK: lastOK, lastFailed: lastErr != nil,
	})
}

type metricsSnapshot struct {
	stats                  dataplane.Stats
	backends               map[uint32]netip.AddrPort
	services               int
	reloadOK, reloadFailed uint64
	lastOK                 time.Time
	lastFailed             bool
}

func writeMetrics(w io.Writer, m metricsSnapshot) {
	metric := func(name, typ, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	metric("ferry_build_info", "gauge", "Ferry build; always 1.")
	fmt.Fprintf(w, "ferry_build_info{version=%q,goversion=%q} 1\n", version(), runtime.Version())

	for _, c := range []struct {
		name, help string
		v          uint64
	}{
		{"ferry_packets_total", "Packets seen by the XDP program.", m.stats.Packets},
		{"ferry_service_hits_total", "Packets addressed to a configured VIP.", m.stats.ServiceHits},
		{"ferry_conntrack_hits_total", "Packets that reused a tracked, active backend.", m.stats.ConntrackHits},
		{"ferry_conntrack_reselects_total", "Tracked flows whose backend was retired and were rehashed.", m.stats.ConntrackReselects},
		{"ferry_no_table_total", "Packets to a VIP with no Maglev table installed.", m.stats.NoTable},
		{"ferry_no_backend_total", "Packets whose Maglev slot held an inactive backend.", m.stats.NoBackend},
	} {
		metric(c.name, "counter", c.help)
		fmt.Fprintf(w, "%s %d\n", c.name, c.v)
	}

	metric("ferry_forwarded_packets_total", "counter", "Packets NATed and transmitted, by direction.")
	fmt.Fprintf(w, "ferry_forwarded_packets_total{direction=\"to_backend\"} %d\n", m.stats.Forwarded)
	fmt.Fprintf(w, "ferry_forwarded_packets_total{direction=\"to_client\"} %d\n", m.stats.Replied)
	metric("ferry_dropped_packets_total", "counter", "Packets dropped while forwarding, by reason.")
	for _, d := range []struct {
		reason string
		v      uint64
	}{
		{"snat_exhausted", m.stats.SNATExhausted},
		{"no_neighbor", m.stats.NoNeighbor},
		{"fib_failed", m.stats.FIBFailed},
		{"wrong_interface", m.stats.WrongInterface},
		{"ttl_exceeded", m.stats.TTLExceeded},
	} {
		fmt.Fprintf(w, "ferry_dropped_packets_total{reason=%q} %d\n", d.reason, d.v)
	}

	type backend struct {
		addr netip.AddrPort
		id   uint32
	}
	var bs []backend
	for id, addr := range m.backends {
		bs = append(bs, backend{addr, id})
	}
	slices.SortFunc(bs, func(a, b backend) int { return cmp.Compare(a.addr.String(), b.addr.String()) })
	metric("ferry_backend_packets_total", "counter", "Packets steered to each active backend.")
	for _, b := range bs {
		fmt.Fprintf(w, "ferry_backend_packets_total{backend=%q} %d\n", b.addr, m.stats.BackendPackets[b.id])
	}

	metric("ferry_services", "gauge", "Services programmed into the data plane.")
	fmt.Fprintf(w, "ferry_services %d\n", m.services)
	metric("ferry_backends", "gauge", "Active backends.")
	fmt.Fprintf(w, "ferry_backends %d\n", len(m.backends))

	metric("ferry_config_reloads_total", "counter", "Config applications, including the initial one, by result.")
	fmt.Fprintf(w, "ferry_config_reloads_total{result=\"success\"} %d\n", m.reloadOK)
	fmt.Fprintf(w, "ferry_config_reloads_total{result=\"failure\"} %d\n", m.reloadFailed)
	metric("ferry_config_last_reload_successful", "gauge", "1 if the most recent config application succeeded.")
	fmt.Fprintf(w, "ferry_config_last_reload_successful %d\n", b2i(!m.lastFailed))
	metric("ferry_config_last_reload_success_timestamp_seconds", "gauge", "Unix time of the last successful config application.")
	var ts int64
	if !m.lastOK.IsZero() {
		ts = m.lastOK.Unix()
	}
	fmt.Fprintf(w, "ferry_config_last_reload_success_timestamp_seconds %d\n", ts)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
