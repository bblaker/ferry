package dataplane

import (
	"fmt"
	"slices"
	"sync"
)

// Memory is an in-process Dataplane. It backs the control plane's tests and
// lets ferry run on machines without XDP (e.g. a macOS dev box).
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
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backends[id] = b
	return nil
}

func (m *Memory) SetService(key ServiceKey, id uint32, slots []uint32) error {
	if id >= MaxServices {
		return fmt.Errorf("service id %d out of range", id)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range slots {
		if _, ok := m.backends[b]; !ok {
			return fmt.Errorf("service %s: table references unknown backend %d", key, b)
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

func (m *Memory) Close() error { return nil }

// Lookup mirrors the XDP program's table lookup (without connection
// tracking): it returns the backend a flow with hash h would be sent to.
func (m *Memory) Lookup(key ServiceKey, h uint32) (Backend, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.services[key]
	if !ok {
		return Backend{}, false
	}
	t := m.tables[id]
	b, ok := m.backends[t[h%uint32(len(t))]]
	return b, ok && b.Active
}

// Backend returns the programmed state of backend id.
func (m *Memory) Backend(id uint32) (Backend, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.backends[id]
	return b, ok
}

// Services returns how many services are programmed.
func (m *Memory) Services() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.services)
}
