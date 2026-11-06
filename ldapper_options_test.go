// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"sync"
	"testing"
	"time"
)

// ---------- normalizeSearchLimits ----------

// TestNormalizeSearchLimits verifies the simple clamping rule: negative
// values collapse to 0; everything else is preserved.
func TestNormalizeSearchLimits(t *testing.T) {
	tests := []struct {
		name string
		in   SearchLimits
		want SearchLimits
	}{
		{"negative size clamped", SearchLimits{SizeLimit: -10, TimeLimit: 0}, SearchLimits{SizeLimit: 0, TimeLimit: 0}},
		{"negative time clamped", SearchLimits{SizeLimit: 0, TimeLimit: -1}, SearchLimits{SizeLimit: 0, TimeLimit: 0}},
		{"both negative clamped", SearchLimits{SizeLimit: -5, TimeLimit: -5}, SearchLimits{SizeLimit: 0, TimeLimit: 0}},
		{"zeros preserved", SearchLimits{}, SearchLimits{}},
		{"positive preserved", SearchLimits{SizeLimit: 100, TimeLimit: 30}, SearchLimits{SizeLimit: 100, TimeLimit: 30}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeSearchLimits(tc.in); got != tc.want {
				t.Fatalf("normalizeSearchLimits(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// ---------- WithSearchLimits ----------

// TestWithSearchLimits verifies that the option mutates only the search
// limits and clamps negatives.
func TestWithSearchLimits(t *testing.T) {
	t.Run("positive values applied", func(t *testing.T) {
		l := &LDAPper{}
		WithSearchLimits(250, 15)(l)
		want := SearchLimits{SizeLimit: 250, TimeLimit: 15}
		if l.searchLimits != want {
			t.Fatalf("searchLimits = %+v, want %+v", l.searchLimits, want)
		}
	})

	t.Run("negative values clamped", func(t *testing.T) {
		l := &LDAPper{}
		WithSearchLimits(-1, -1)(l)
		want := SearchLimits{SizeLimit: 0, TimeLimit: 0}
		if l.searchLimits != want {
			t.Fatalf("searchLimits = %+v, want %+v", l.searchLimits, want)
		}
	})
}

// ---------- Set/GetSearchLimits ----------

// TestSetGetSearchLimits covers the public mutator/getter pair, including
// the clamping on Set.
func TestSetGetSearchLimits(t *testing.T) {
	t.Run("roundtrip positive", func(t *testing.T) {
		l := &LDAPper{}
		l.SetSearchLimits(500, 60)
		if got := l.GetSearchLimits(); got != (SearchLimits{SizeLimit: 500, TimeLimit: 60}) {
			t.Fatalf("GetSearchLimits() = %+v", got)
		}
	})

	t.Run("zero resets to defaults", func(t *testing.T) {
		l := &LDAPper{searchLimits: SearchLimits{SizeLimit: 500, TimeLimit: 60}}
		l.SetSearchLimits(0, 0)
		if got := l.GetSearchLimits(); got != (SearchLimits{}) {
			t.Fatalf("GetSearchLimits() = %+v, want zero value", got)
		}
	})

	t.Run("negative set clamps", func(t *testing.T) {
		l := &LDAPper{}
		l.SetSearchLimits(-100, -1)
		if got := l.GetSearchLimits(); got != (SearchLimits{}) {
			t.Fatalf("GetSearchLimits() = %+v, want zero value", got)
		}
	})

	t.Run("zero value getter on fresh LDAPper", func(t *testing.T) {
		l := &LDAPper{}
		if got := l.GetSearchLimits(); got != (SearchLimits{}) {
			t.Fatalf("GetSearchLimits() = %+v, want zero value", got)
		}
	})
}

// TestSearchLimits_ConcurrentSetGet is a race-detector guard. With -race
// enabled this test will fail if Set/Get ever stop taking opMu.
func TestSearchLimits_ConcurrentSetGet(t *testing.T) {
	l := &LDAPper{}
	var wg sync.WaitGroup

	for i := 0; i < 200; i++ {
		n := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.SetSearchLimits(n, n)
		}()
		go func() {
			defer wg.Done()
			_ = l.GetSearchLimits()
		}()
	}
	wg.Wait()
}

// ---------- normalizeDialTimeout ----------

// TestNormalizeDialTimeout verifies the timeout clamp.
func TestNormalizeDialTimeout(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"negative clamped", -5 * time.Second, 0},
		{"zero preserved", 0, 0},
		{"positive preserved", 3 * time.Second, 3 * time.Second},
		{"sub-second preserved", 250 * time.Millisecond, 250 * time.Millisecond},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeDialTimeout(tc.in); got != tc.want {
				t.Fatalf("normalizeDialTimeout(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// ---------- WithDialTimeout ----------

// TestWithDialTimeout verifies that the option applies and clamps.
func TestWithDialTimeout(t *testing.T) {
	t.Run("positive applied", func(t *testing.T) {
		l := &LDAPper{}
		WithDialTimeout(2 * time.Second)(l)
		if l.dialTimeout != 2*time.Second {
			t.Fatalf("dialTimeout = %v, want %v", l.dialTimeout, 2*time.Second)
		}
	})

	t.Run("negative clamped to zero", func(t *testing.T) {
		l := &LDAPper{dialTimeout: time.Second}
		WithDialTimeout(-1 * time.Second)(l)
		if l.dialTimeout != 0 {
			t.Fatalf("dialTimeout = %v, want 0", l.dialTimeout)
		}
	})
}

// ---------- Set/GetDialTimeout ----------

// TestSetGetDialTimeout covers the public mutator/getter pair.
func TestSetGetDialTimeout(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		l := &LDAPper{}
		l.SetDialTimeout(4 * time.Second)
		if got := l.GetDialTimeout(); got != 4*time.Second {
			t.Fatalf("GetDialTimeout() = %v, want %v", got, 4*time.Second)
		}
	})

	t.Run("negative set clamps", func(t *testing.T) {
		l := &LDAPper{dialTimeout: time.Second}
		l.SetDialTimeout(-3 * time.Second)
		if got := l.GetDialTimeout(); got != 0 {
			t.Fatalf("GetDialTimeout() = %v, want 0", got)
		}
	})

	t.Run("zero value getter on fresh LDAPper", func(t *testing.T) {
		l := &LDAPper{}
		if got := l.GetDialTimeout(); got != 0 {
			t.Fatalf("GetDialTimeout() = %v, want 0", got)
		}
	})
}

// TestDialTimeout_ConcurrentSetGet mirrors the search-limits race guard.
func TestDialTimeout_ConcurrentSetGet(t *testing.T) {
	l := &LDAPper{}
	var wg sync.WaitGroup

	for i := 0; i < 200; i++ {
		d := time.Duration(i) * time.Millisecond
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.SetDialTimeout(d)
		}()
		go func() {
			defer wg.Done()
			_ = l.GetDialTimeout()
		}()
	}
	wg.Wait()
}

func TestWithPagingLimits(t *testing.T) {
	t.Run("positive applied", func(t *testing.T) {
		l := &LDAPper{}
		WithPagingLimits(100, 50000)(l)
		if l.searchLimits.MaxPages != 100 || l.searchLimits.MaxEntries != 50000 {
			t.Fatalf("limits = %+v", l.searchLimits)
		}
	})
	t.Run("negative clamped", func(t *testing.T) {
		l := &LDAPper{}
		WithPagingLimits(-1, -1)(l)
		if l.searchLimits.MaxPages != 0 || l.searchLimits.MaxEntries != 0 {
			t.Fatalf("limits = %+v", l.searchLimits)
		}
	})
}

func TestSetGetPagingLimits(t *testing.T) {
	l := &LDAPper{}
	l.SetPagingLimits(50, 10000)
	maxPages, maxEntries := l.GetPagingLimits()
	if maxPages != 50 || maxEntries != 10000 {
		t.Fatalf("got %d/%d", maxPages, maxEntries)
	}
	l.SetPagingLimits(-1, -1)
	maxPages, maxEntries = l.GetPagingLimits()
	if maxPages != 0 || maxEntries != 0 {
		t.Fatalf("negative not clamped: %d/%d", maxPages, maxEntries)
	}
}

func TestPagingLimits_ConcurrentSetGet(t *testing.T) {
	l := &LDAPper{}
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		n := i
		wg.Add(2)
		go func() { defer wg.Done(); l.SetPagingLimits(n, n*100) }()
		go func() { defer wg.Done(); _, _ = l.GetPagingLimits() }()
	}
	wg.Wait()
}

func TestWithOperationTimeout(t *testing.T) {
	t.Run("positive applied", func(t *testing.T) {
		l := &LDAPper{}
		WithOperationTimeout(OperationTimeouts{Bind: 5 * time.Second, Search: 30 * time.Second})(l)
		if l.opTimeouts.Bind != 5*time.Second || l.opTimeouts.Search != 30*time.Second {
			t.Fatalf("opTimeouts = %+v", l.opTimeouts)
		}
	})
	t.Run("negative clamped", func(t *testing.T) {
		l := &LDAPper{}
		WithOperationTimeout(OperationTimeouts{Bind: -1, Search: -1})(l)
		if l.opTimeouts.Bind != 0 || l.opTimeouts.Search != 0 {
			t.Fatalf("opTimeouts = %+v", l.opTimeouts)
		}
	})
}

func TestSetGetOperationTimeout(t *testing.T) {
	l := &LDAPper{}
	l.SetOperationTimeout(OperationTimeouts{Bind: 2 * time.Second, Search: 10 * time.Second})
	got := l.GetOperationTimeout()
	if got.Bind != 2*time.Second || got.Search != 10*time.Second {
		t.Fatalf("got %+v", got)
	}
}
