// Package maglev builds Maglev consistent-hashing lookup tables
// (Eisenbud et al., NSDI 2016).
//
// A table is a fixed-size array of M slots, each holding a backend index.
// The data plane hashes a flow's 5-tuple, takes it mod M, and reads the slot.
// The property that matters for Ferry: when a backend is added or removed,
// only about 1/N of the slots change owner, so most flows keep their backend
// even before connection tracking gets involved.
package maglev

import (
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
)

// DefaultSize is the default table size. It must be prime. The paper
// recommends M > 100*N for good balance, so this supports ~160 backends per
// service while keeping each inner BPF map at 64 KiB.
const DefaultSize = 16381

var ErrNoBackends = errors.New("maglev: no backends")

// Table is a populated lookup table. Slots[i] is an index into Backends.
type Table struct {
	Backends []string
	Slots    []uint32
}

// Build populates a table of the given prime size for the named backends.
//
// Names must be unique and stable across rebuilds (Ferry uses "ip:port"):
// a backend's permutation is derived only from its name, which is what keeps
// rebuilds minimally disruptive. Input order does not matter; names are
// sorted so that the same set always yields the same table.
func Build(names []string, size uint64) (*Table, error) {
	if len(names) == 0 {
		return nil, ErrNoBackends
	}
	if !isPrime(size) {
		return nil, fmt.Errorf("maglev: table size %d is not prime", size)
	}
	if uint64(len(names)) > size {
		return nil, fmt.Errorf("maglev: %d backends exceed table size %d", len(names), size)
	}

	backends := slices.Clone(names)
	slices.Sort(backends)
	if i := firstDup(backends); i >= 0 {
		return nil, fmt.Errorf("maglev: duplicate backend %q", backends[i])
	}

	n := uint64(len(backends))
	offset := make([]uint64, n)
	skip := make([]uint64, n)
	for i, b := range backends {
		offset[i] = hash(b, 0) % size
		skip[i] = hash(b, 1)%(size-1) + 1
	}

	const empty = ^uint32(0)
	slots := make([]uint32, size)
	for i := range slots {
		slots[i] = empty
	}
	next := make([]uint64, n)

	// Backends take turns claiming their next preferred free slot until the
	// table is full. Because skip is in [1, size-1] and size is prime, each
	// backend's permutation visits every slot, so this always terminates.
	var filled uint64
	for {
		for i := range n {
			c := (offset[i] + next[i]*skip[i]) % size
			for slots[c] != empty {
				next[i]++
				c = (offset[i] + next[i]*skip[i]) % size
			}
			slots[c] = uint32(i)
			next[i]++
			filled++
			if filled == size {
				return &Table{Backends: backends, Slots: slots}, nil
			}
		}
	}
}

// Lookup returns the backend name for a flow hash.
func (t *Table) Lookup(h uint64) string {
	return t.Backends[t.Slots[h%uint64(len(t.Slots))]]
}

// hash is FNV-1a over a seed byte followed by the name. It must be
// deterministic across processes (unlike hash/maphash) so that a restarted
// control plane rebuilds the same table the data plane already has.
func hash(s string, seed byte) uint64 {
	h := fnv.New64a()
	h.Write([]byte{seed})
	h.Write([]byte(s))
	return h.Sum64()
}

func firstDup(sorted []string) int {
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return i
		}
	}
	return -1
}

func isPrime(n uint64) bool {
	if n < 2 {
		return false
	}
	for d := uint64(2); d*d <= n; d++ {
		if n%d == 0 {
			return false
		}
	}
	return true
}
