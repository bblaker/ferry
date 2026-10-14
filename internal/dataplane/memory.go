package dataplane

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
)

// Memory is an in-process Dataplane. It backs the control plane's tests and
// lets ferry run on machines without XDP (e.g. a macOS dev box).
//
// It is stricter than the kernel: it rejects updates that break the
// Dataplane ordering contract, so tests fail where XDP would misroute.
type Memory struct {
	mu       sync.RWMutex
	backends map[uint32]Backend
	services map[ServiceKey]uint32
	tables   map[uint32][]uint32
}

func NewMemory() *Memory {
	return &Memory{
		backends: map[uint32]Backend{},
		services: map[ServiceKey]uint32{},
		tables:   map[uint32][]uint32{},
	}
}

func (m *Memory) SetBackend(id uint32, b Backend) error {
	if id >= MaxBackends {
		return fmt.Errorf("backend id %d out of range", id)
	}
	if !b.Addr.Addr().Is4() {
		return fmt.Errorf("backend %s: only IPv4 is supported", b.Addr)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !b.Active {
		for tid, t := range m.tables {
			if slices.Contains(t, id) {
				return fmt.Errorf("deactivate backend %d (%s): still referenced by table %d", id, b.Addr, tid)
			}
		}
	}
	m.backends[id] = b
	return nil
}

func (m *Memory) SetService(key ServiceKey, id uint32, slots []uint32) error {
	if id >= MaxServices {
		return fmt.Errorf("service id %d out of range", id)
	}
	if len(slots) == 0 {
		return fmt.Errorf("service %s: empty table", key)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range slots {
		if !m.backends[b].Active {
			return fmt.Errorf("service %s: table references inactive or unknown backend %d", key, b)
		}
	}
	m.tables[id] = slices.Clone(slots)
	m.services[key] = id
	return nil
}

func (m *Memory) DeleteService(key ServiceKey, id uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, key)
	delete(m.tables, id)
	return nil
}

// Stats returns zeros: Memory does not see packets.
func (m *Memory) Stats() (Stats, error) { return Stats{}, nil }

// State returns a copy of what is programmed.
func (m *Memory) State() (State, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := State{Backends: map[uint32]Backend{}, Services: map[ServiceKey]uint32{}}
	for id, b := range m.backends {
		st.Backends[id] = b
	}
	for k, id := range m.services {
		st.Services[k] = id
	}
	return st, nil
}

func (m *Memory) Close() error { return nil }

// Lookup mirrors the XDP program's table lookup (without connection
// tracking): it returns the backend a new flow would be sent to.
func (m *Memory) Lookup(f Flow) (Backend, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.services[f.Service()]
	if !ok {
		return Backend{}, false
	}
	t := m.tables[id]
	b, ok := m.backends[t[f.Hash()%uint32(len(t))]]
	return b, ok && b.Active
}

// Backend returns the programmed state of backend id.
func (m *Memory) Backend(id uint32) (Backend, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.backends[id]
	return b, ok
}

// ServiceBackends returns the distinct backends in key's table, sorted.
func (m *Memory) ServiceBackends(key ServiceKey) []netip.AddrPort {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.services[key]
	if !ok {
		return nil
	}
	var out []netip.AddrPort
	for _, b := range m.tables[id] {
		out = append(out, m.backends[b].Addr)
	}
	slices.SortFunc(out, netip.AddrPort.Compare)
	return slices.Compact(out)
}

// ActiveBackends returns how many backends are marked active.
func (m *Memory) ActiveBackends() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, b := range m.backends {
		if b.Active {
			n++
		}
	}
	return n
}

// Services returns how many services are programmed.
func (m *Memory) Services() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.services)
}
