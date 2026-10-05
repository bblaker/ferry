package maglev

import (
	"fmt"
	"slices"
	"testing"
)

func names(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.%d.%d:8080", i/256, i%256)
	}
	return out
}

func TestBuildErrors(t *testing.T) {
	if _, err := Build(nil, DefaultSize); err != ErrNoBackends {
		t.Errorf("empty: got %v, want ErrNoBackends", err)
	}
	if _, err := Build(names(3), 16384); err == nil {
		t.Error("non-prime size: expected error")
	}
	if _, err := Build([]string{"a", "b", "a"}, 7); err == nil {
		t.Error("duplicate backend: expected error")
	}
	if _, err := Build(names(8), 7); err == nil {
		t.Error("more backends than slots: expected error")
	}
}

func TestEveryBackendGetsFairShare(t *testing.T) {
	for _, n := range []int{1, 2, 3, 10, 100} {
		tbl, err := Build(names(n), DefaultSize)
		if err != nil {
			t.Fatal(err)
		}
		counts := make([]int, n)
		for _, s := range tbl.Slots {
			counts[s]++
		}
		ideal := float64(DefaultSize) / float64(n)
		for i, c := range counts {
			// Maglev's round-robin fill guarantees each backend is within one
			// slot of every other.
			if float64(c) < ideal-1 || float64(c) > ideal+1 {
				t.Errorf("n=%d backend %d: %d slots, ideal %.1f", n, i, c, ideal)
			}
		}
	}
}

func TestInputOrderDoesNotMatter(t *testing.T) {
	a := names(20)
	b := slices.Clone(a)
	slices.Reverse(b)
	ta, _ := Build(a, DefaultSize)
	tb, _ := Build(b, DefaultSize)
	if !slices.Equal(ta.Slots, tb.Slots) {
		t.Fatal("same backend set in different order produced different tables")
	}
}

// TestRemovalDisruption checks the property Ferry depends on: removing one of
// N backends moves that backend's slots plus only a small number of others.
func TestRemovalDisruption(t *testing.T) {
	const n = 10
	all := names(n)
	before, _ := Build(all, DefaultSize)
	removed := all[3]
	after, _ := Build(slices.Delete(slices.Clone(all), 3, 4), DefaultSize)

	var forced, collateral int
	for i := range before.Slots {
		was, now := before.Backends[before.Slots[i]], after.Backends[after.Slots[i]]
		switch {
		case was == removed:
			forced++
		case was != now:
			collateral++
		}
	}
	// The paper reports collateral movement well under the 1/N that a forced
	// reassignment costs. Allow up to 2% of the table here.
	if limit := DefaultSize / 50; collateral > limit {
		t.Errorf("collateral moves = %d (forced %d), want <= %d", collateral, forced, limit)
	}
	t.Logf("removed 1/%d backends: %d forced, %d collateral of %d slots", n, forced, collateral, DefaultSize)
}

func BenchmarkBuild100(b *testing.B) {
	ns := names(100)
	for b.Loop() {
		Build(ns, DefaultSize)
	}
}
