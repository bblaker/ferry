package main

import (
	"cmp"
	"context"
	"errors"
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

// Retries of a partially applied config back off exponentially between
// these bounds.
const (
	retryMin = time.Second
	retryMax = time.Minute
)

// daemon serializes reloads, retries and metric reads around the
// reconciler, which is not safe for concurrent use.
//
// It tracks two things separately: whether the latest config was accepted
// (valid, and fits the tables), and whether the data plane has converged on
// the latest accepted config. A data plane update can fail partway (a map
// update returning ENOMEM, say); the daemon then retries the same snapshot
// with backoff until it converges or a newer config replaces it.
type daemon struct {
	dp     dataplane.Dataplane
	config string
	log    *slog.Logger

	applied chan struct{} // signalled each time the data plane converges

	mu        sync.Mutex
	rec       *controlplane.Reconciler
	reloads   map[string]uint64 // configs by result: "success" (accepted), "failure" (rejected)
	reloadErr error             // why the latest config was rejected; nil if accepted

	desired  []discovery.Service // latest accepted config
	applyErr error               // why the data plane hasn't converged on desired; nil once it has
	failures int                 // consecutive failed applies of desired
	retries  map[string]uint64   // retry attempts by result
	lastOK   time.Time           // when the data plane last converged
}

func newDaemon(dp dataplane.Dataplane, config string, log *slog.Logger) *daemon {
	return &daemon{
		dp:      dp,
		config:  config,
		log:     log,
		applied: make(chan struct{}, 1),
		rec:     controlplane.NewReconciler(dp, maglev.DefaultSize, log),
		reloads: map[string]uint64{"success": 0, "failure": 0},
		retries: map[string]uint64{"success": 0, "failure": 0},
	}
}

// apply makes services the desired state and programs it. A snapshot the
// reconciler rejects leaves the data plane, and any retry in progress,
// untouched. Otherwise it is accepted even if programming fails: the error
// is returned and retry finishes the job.
func (d *daemon) apply(services []discovery.Service) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	err := d.rec.Apply(services)
	if errors.Is(err, controlplane.ErrInvalid) {
		d.recordReload(err)
		return err
	}
	d.recordReload(nil)
	d.desired = services
	d.failures = 0
	d.recordApply(err)
	return err
}

// retry re-applies the desired state if the data plane hasn't converged on
// it. It returns the error from that attempt.
func (d *daemon) retry() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.applyErr == nil {
		return nil
	}
	err := d.rec.Apply(d.desired)
	if err != nil {
		d.retries["failure"]++
	} else {
		d.retries["success"]++
	}
	attempts := d.failures + 1
	d.recordApply(err)
	if err != nil {
		d.log.Warn("retry: programming failed", "attempt", attempts, "next", backoff(d.failures), "err", err)
	} else {
		d.log.Info("retry: data plane converged", "attempts", attempts)
	}
	return err
}

// retryDelay reports how long to wait before the next retry, or false if
// the data plane has converged.
func (d *daemon) retryDelay() (time.Duration, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.applyErr == nil {
		return 0, false
	}
	return backoff(d.failures), true
}

// backoff is the wait after n consecutive failures (n >= 1).
func backoff(n int) time.Duration {
	if n > 10 { // 2^10 s is far past retryMax; avoid overflowing the shift
		return retryMax
	}
	return min(retryMin<<(n-1), retryMax)
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

func (d *daemon) recordReload(err error) {
	if err != nil {
		d.reloads["failure"]++
	} else {
		d.reloads["success"]++
	}
	d.reloadErr = err
}

func (d *daemon) recordApply(err error) {
	d.applyErr = err
	if err != nil {
		d.failures++
		return
	}
	d.failures = 0
	d.lastOK = time.Now()
	select {
	case d.applied <- struct{}{}:
	default:
	}
}

// reload re-reads the config file. If the file is invalid or doesn't fit,
// the data plane is left exactly as it was. If programming fails partway,
// the data plane is left partially updated (still routing correctly) and
// retry finishes the job.
func (d *daemon) reload() error {
	services, err := discovery.LoadFile(d.config)
	if err != nil {
		d.mu.Lock()
		d.recordReload(err)
		d.mu.Unlock()
		d.log.Error("reload: config rejected; keeping current tables", "err", err)
		return err
	}
	switch err := d.apply(services); {
	case errors.Is(err, controlplane.ErrInvalid):
		d.log.Error("reload: config rejected; keeping current tables", "err", err)
		return err
	case err != nil:
		d.log.Error("reload: programming failed; data plane partially updated, retrying", "next", retryMin, "err", err)
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
// attached and forwarding, even if the latest reload was rejected or an
// update is still being retried. The body says which.
func (d *daemon) serveHealth(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	reloadErr, applyErr := d.reloadErr, d.applyErr
	d.mu.Unlock()
	msg := "ok"
	if reloadErr != nil {
		msg += fmt.Sprintf("; last reload failed: %v", reloadErr)
	}
	if applyErr != nil {
		msg += fmt.Sprintf("; data plane not converged, retrying: %v", applyErr)
	}
	fmt.Fprintln(w, msg)
}

// serveMetrics writes the Prometheus text format by hand; there are few
// enough series that a client library would be the larger dependency.
func (d *daemon) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	backends := d.rec.Backends()
	services := d.rec.Services()
	snap := metricsSnapshot{
		backends: backends,
		services: services,
		reloadOK: d.reloads["success"], reloadFailed: d.reloads["failure"],
		lastOK: d.lastOK, lastFailed: d.reloadErr != nil,
		converged: d.applyErr == nil,
		retryOK:   d.retries["success"], retryFailed: d.retries["failure"],
	}
	d.mu.Unlock()

	stats, err := d.dp.Stats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	snap.stats = stats
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeMetrics(w, snap)
}

type metricsSnapshot struct {
	stats                  dataplane.Stats
	backends               map[uint32]netip.AddrPort
	services               int
	reloadOK, reloadFailed uint64
	lastOK                 time.Time
	lastFailed             bool
	converged              bool
	retryOK, retryFailed   uint64
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

	metric("ferry_config_reloads_total", "counter", "Config loads, including the initial one, by result: success if accepted, failure if rejected.")
	fmt.Fprintf(w, "ferry_config_reloads_total{result=\"success\"} %d\n", m.reloadOK)
	fmt.Fprintf(w, "ferry_config_reloads_total{result=\"failure\"} %d\n", m.reloadFailed)
	metric("ferry_config_last_reload_successful", "gauge", "1 if the most recent config was accepted; see ferry_dataplane_converged for whether it is fully programmed.")
	fmt.Fprintf(w, "ferry_config_last_reload_successful %d\n", b2i(!m.lastFailed))
	metric("ferry_dataplane_converged", "gauge", "1 if the data plane holds the latest accepted config; 0 while a failed update is retried.")
	fmt.Fprintf(w, "ferry_dataplane_converged %d\n", b2i(m.converged))
	metric("ferry_dataplane_apply_retries_total", "counter", "Retries of a partially applied config, by result.")
	fmt.Fprintf(w, "ferry_dataplane_apply_retries_total{result=\"success\"} %d\n", m.retryOK)
	fmt.Fprintf(w, "ferry_dataplane_apply_retries_total{result=\"failure\"} %d\n", m.retryFailed)
	metric("ferry_config_last_reload_success_timestamp_seconds", "gauge", "Unix time the data plane last converged on an accepted config.")
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
