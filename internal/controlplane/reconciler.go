// Package controlplane turns discovery snapshots into data plane updates.
package controlplane

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/bblaker/ferry/internal/dataplane"
	"github.com/bblaker/ferry/internal/discovery"
	"github.com/bblaker/ferry/internal/maglev"
)

// Reconciler owns ID allocation and drives a Dataplane toward the desired
// state. It is not safe for concurrent use; run Apply from one goroutine.
//
// Update ordering, per Apply:
//  1. Activate every backend the new tables reference.
//  2. Swap each changed service's table (atomic per service).
//  3. Delete services that disappeared.
//  4. Deactivate backends no longer referenced. Conntrack entries that still
//     point at them see Active=false in the XDP program and reselect.
//
// Backend IDs are allocated round-robin and are not reused until the
// allocator wraps, so a stale conntrack entry cannot silently land on a
// different backend that inherited its ID.
type Reconciler struct {
	dp        dataplane.Dataplane
	tableSize uint64
	log       *slog.Logger

	backendIDs  map[netip.AddrPort]uint32
	nextBackend uint32

	services    map[dataplane.ServiceKey]*serviceState
	nextService uint32
}

type serviceState struct {
	id       uint32
	backends []netip.AddrPort // sorted; what is currently programmed
}

func NewReconciler(dp dataplane.Dataplane, tableSize uint64, log *slog.Logger) *Reconciler {
	return &Reconciler{
		dp:         dp,
		tableSize:  tableSize,
		log:        log,
		backendIDs: map[netip.AddrPort]uint32{},
		services:   map[dataplane.ServiceKey]*serviceState{},
	}
}

// Apply converges the data plane on the given snapshot. On error the data
// plane may be partially updated; calling Apply again with the same snapshot
// finishes the job.
func (r *Reconciler) Apply(snapshot []discovery.Service) error {
	desired := make(map[dataplane.ServiceKey][]netip.AddrPort, len(snapshot))
	for _, s := range snapshot {
		if _, dup := desired[s.Key]; dup {
			return fmt.Errorf("duplicate service %s", s.Key)
		}
		bs := slices.Clone(s.Backends)
		slices.SortFunc(bs, netip.AddrPort.Compare)
		desired[s.Key] = slices.Compact(bs)
	}

	// 1. Activate referenced backends.
	referenced := map[netip.AddrPort]bool{}
	for _, bs := range desired {
		for _, b := range bs {
			if referenced[b] {
				continue
			}
			referenced[b] = true
			id, err := r.backendID(b)
			if err != nil {
				return err
			}
			if err := r.dp.SetBackend(id, dataplane.Backend{Addr: b, Active: true}); err != nil {
				return fmt.Errorf("activate backend %s: %w", b, err)
			}
		}
	}

	// 2. Swap tables for new or changed services. A service with no backends
	// is removed from the data plane so its traffic falls through to the
	// kernel rather than hashing into an empty table.
	for key, bs := range desired {
		if len(bs) == 0 {
			continue
		}
		st := r.services[key]
		if st != nil && slices.Equal(st.backends, bs) {
			continue
		}
		var id uint32
		if st != nil {
			id = st.id
		} else {
			var err error
			if id, err = r.serviceID(); err != nil {
				return fmt.Errorf("service %s: %w", key, err)
			}
		}
		slots, err := r.buildSlots(bs)
		if err != nil {
			return fmt.Errorf("service %s: %w", key, err)
		}
		if err := r.dp.SetService(key, id, slots); err != nil {
			return fmt.Errorf("service %s: swap table: %w", key, err)
		}
		r.services[key] = &serviceState{id: id, backends: bs}
		r.log.Info("programmed service", "service", key, "id", id, "backends", len(bs))
	}

	// 3. Delete services that are gone or empty.
	for key, st := range r.services {
		if len(desired[key]) > 0 {
			continue
		}
		if err := r.dp.DeleteService(key, st.id); err != nil {
			return fmt.Errorf("service %s: delete: %w", key, err)
		}
		delete(r.services, key)
		r.log.Info("removed service", "service", key, "id", st.id)
	}

	// 4. Retire unreferenced backends.
	for b, id := range r.backendIDs {
		if referenced[b] {
			continue
		}
		if err := r.dp.SetBackend(id, dataplane.Backend{Addr: b, Active: false}); err != nil {
			return fmt.Errorf("retire backend %s: %w", b, err)
		}
		delete(r.backendIDs, b)
		r.log.Info("retired backend", "backend", b, "id", id)
	}
	return nil
}

func (r *Reconciler) buildSlots(bs []netip.AddrPort) ([]uint32, error) {
	names := make([]string, len(bs))
	byName := make(map[string]uint32, len(bs))
	for i, b := range bs {
		names[i] = b.String()
		byName[names[i]] = r.backendIDs[b]
	}
	t, err := maglev.Build(names, r.tableSize)
	if err != nil {
		return nil, err
	}
	slots := make([]uint32, len(t.Slots))
	for i, s := range t.Slots {
		slots[i] = byName[t.Backends[s]]
	}
	return slots, nil
}

func (r *Reconciler) backendID(b netip.AddrPort) (uint32, error) {
	if id, ok := r.backendIDs[b]; ok {
		return id, nil
	}
	if len(r.backendIDs) >= dataplane.MaxBackends {
		return 0, fmt.Errorf("backend table full (%d)", dataplane.MaxBackends)
	}
	inUse := make(map[uint32]bool, len(r.backendIDs))
	for _, id := range r.backendIDs {
		inUse[id] = true
	}
	for inUse[r.nextBackend] {
		r.nextBackend = (r.nextBackend + 1) % dataplane.MaxBackends
	}
	id := r.nextBackend
	r.nextBackend = (r.nextBackend + 1) % dataplane.MaxBackends
	r.backendIDs[b] = id
	return id, nil
}

func (r *Reconciler) serviceID() (uint32, error) {
	if len(r.services) >= dataplane.MaxServices {
		return 0, fmt.Errorf("service table full (%d)", dataplane.MaxServices)
	}
	inUse := make(map[uint32]bool, len(r.services))
	for _, st := range r.services {
		inUse[st.id] = true
	}
	for inUse[r.nextService] {
		r.nextService = (r.nextService + 1) % dataplane.MaxServices
	}
	id := r.nextService
	r.nextService = (r.nextService + 1) % dataplane.MaxServices
	return id, nil
}
