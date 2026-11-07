// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/constants"
)

// --- DefaultSearchLimits ---

func TestDefaultSearchLimits(t *testing.T) {
	t.Parallel()

	got := DefaultSearchLimits()

	assert.Equal(t, constants.DefaultSearchSizeLimit, got.SizeLimit)
	assert.Equal(t, constants.DefaultSearchTimeLimit, got.TimeLimit)
	assert.Zero(t, got.MaxPages)
	assert.Zero(t, got.MaxEntries)
	assert.True(t, got.RequirePaging,
		"RequirePaging must default to true: completeness matters in security paths")
}

// --- normalizeSearchLimits ---

func TestNormalizeSearchLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   SearchLimits
		want SearchLimits
	}{
		{
			name: "zero value stays zero",
			in:   SearchLimits{},
			want: SearchLimits{},
		},
		{
			name: "positive values untouched",
			in: SearchLimits{
				SizeLimit: 500, TimeLimit: 30,
				MaxPages: 10, MaxEntries: 1000, RequirePaging: true,
			},
			want: SearchLimits{
				SizeLimit: 500, TimeLimit: 30,
				MaxPages: 10, MaxEntries: 1000, RequirePaging: true,
			},
		},
		{
			name: "negative values clamped to zero",
			in: SearchLimits{
				SizeLimit: -1, TimeLimit: -5,
				MaxPages: -2, MaxEntries: -100,
			},
			want: SearchLimits{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, normalizeSearchLimits(tt.in))
		})
	}
}

// --- WithSearchLimits ---

func TestWithSearchLimits_ReplacesWholeStruct(t *testing.T) {
	t.Parallel()

	// Documented behaviour: WithSearchLimits is a wholesale replacement,
	// not a merge. Fields omitted from the input get Go zero values, NOT
	// the DefaultSearchLimits() values. This is easy to break accidentally.
	l := &LDAPper{searchLimits: DefaultSearchLimits()}

	WithSearchLimits(SearchLimits{SizeLimit: 42})(l)

	assert.Equal(t, 42, l.searchLimits.SizeLimit)
	assert.Zero(t, l.searchLimits.TimeLimit, "TimeLimit must NOT inherit the default")
	assert.False(t, l.searchLimits.RequirePaging,
		"RequirePaging must NOT inherit the default")
}

func TestWithSearchLimits_NormalizesNegative(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	WithSearchLimits(SearchLimits{SizeLimit: -10, MaxPages: -3})(l)

	assert.Zero(t, l.searchLimits.SizeLimit)
	assert.Zero(t, l.searchLimits.MaxPages)
}

// --- SetSearchLimits / GetSearchLimits ---

func TestSetGetSearchLimits(t *testing.T) {
	t.Parallel()

	l := &LDAPper{searchLimits: DefaultSearchLimits()}

	want := SearchLimits{
		SizeLimit: 100, TimeLimit: 5,
		MaxPages: 3, MaxEntries: 300, RequirePaging: false,
	}
	l.SetSearchLimits(want)

	assert.Equal(t, want, l.GetSearchLimits())
}

func TestSetSearchLimits_NormalizesNegative(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	l.SetSearchLimits(SearchLimits{SizeLimit: -1, TimeLimit: -1, MaxPages: -1, MaxEntries: -1})

	got := l.GetSearchLimits()
	assert.Zero(t, got.SizeLimit)
	assert.Zero(t, got.TimeLimit)
	assert.Zero(t, got.MaxPages)
	assert.Zero(t, got.MaxEntries)
}

func TestGetSearchLimits_ReturnsCopy(t *testing.T) {
	t.Parallel()

	// SearchLimits is a plain struct (no slices/maps/pointers), so value
	// semantics are automatic. This test exists to catch a future change
	// to a reference-containing type: a caller mutating the returned
	// value must not affect the stored one.
	l := &LDAPper{searchLimits: SearchLimits{SizeLimit: 1}}

	got := l.GetSearchLimits()
	got.SizeLimit = 999

	assert.Equal(t, 1, l.GetSearchLimits().SizeLimit)
}

// --- normalizeDialTimeout ---

func TestNormalizeDialTimeout(t *testing.T) {
	t.Parallel()

	assert.Equal(t, time.Duration(0), normalizeDialTimeout(-time.Second))
	assert.Equal(t, time.Duration(0), normalizeDialTimeout(0))
	assert.Equal(t, 5*time.Second, normalizeDialTimeout(5*time.Second))
}

// --- WithDialTimeout ---

func TestWithDialTimeout(t *testing.T) {
	t.Parallel()

	l := &LDAPper{dialTimeout: constants.DefaultDialTimeout}
	WithDialTimeout(3 * time.Second)(l)
	assert.Equal(t, 3*time.Second, l.dialTimeout)
}

func TestWithDialTimeout_NegativeClampedToZero(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	WithDialTimeout(-time.Second)(l)
	assert.Equal(t, time.Duration(0), l.dialTimeout)
}

// --- SetDialTimeout / GetDialTimeout ---

func TestSetGetDialTimeout(t *testing.T) {
	t.Parallel()

	l := &LDAPper{dialTimeout: constants.DefaultDialTimeout}
	l.SetDialTimeout(7 * time.Second)
	assert.Equal(t, 7*time.Second, l.GetDialTimeout())

	l.SetDialTimeout(-time.Second)
	assert.Equal(t, time.Duration(0), l.GetDialTimeout())
}

// --- normalizeOperationTimeouts ---

func TestNormalizeOperationTimeouts(t *testing.T) {
	t.Parallel()

	// Both fields negative -> both zero.
	assert.Equal(t, OperationTimeouts{}, normalizeOperationTimeouts(
		OperationTimeouts{Bind: -time.Second, Search: -2 * time.Second}))

	// Mixed: only the negative field is clamped.
	got := normalizeOperationTimeouts(OperationTimeouts{
		Bind: -time.Second, Search: 3 * time.Second,
	})
	assert.Equal(t, time.Duration(0), got.Bind)
	assert.Equal(t, 3*time.Second, got.Search)
}

// --- WithOperationTimeout ---

func TestWithOperationTimeout(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	WithOperationTimeout(OperationTimeouts{Bind: time.Second, Search: 2 * time.Second})(l)

	assert.Equal(t, time.Second, l.opTimeouts.Bind)
	assert.Equal(t, 2*time.Second, l.opTimeouts.Search)
}

func TestWithOperationTimeout_NegativeClampedToZero(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	WithOperationTimeout(OperationTimeouts{Bind: -time.Second, Search: -time.Second})(l)

	assert.Equal(t, OperationTimeouts{}, l.opTimeouts)
}

// --- SetOperationTimeout / GetOperationTimeout ---

func TestSetGetOperationTimeout(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}

	want := OperationTimeouts{Bind: time.Second, Search: 4 * time.Second}
	l.SetOperationTimeout(want)
	assert.Equal(t, want, l.GetOperationTimeout())

	l.SetOperationTimeout(OperationTimeouts{Bind: -time.Second, Search: -time.Second})
	assert.Equal(t, OperationTimeouts{}, l.GetOperationTimeout())
}

// --- concurrency: Set/Get must hold opMu ---

func TestSearchLimits_ConcurrentSetGet(t *testing.T) {
	t.Parallel()

	// Runs under -race. If Set/Get stop taking opMu, this test fails.
	l := &LDAPper{searchLimits: DefaultSearchLimits()}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.SetSearchLimits(SearchLimits{SizeLimit: i})
		}()
		go func() {
			defer wg.Done()
			_ = l.GetSearchLimits()
		}()
	}
	wg.Wait()

	// Just assert the object is still coherent — the real check is -race.
	got := l.GetSearchLimits()
	assert.GreaterOrEqual(t, got.SizeLimit, 0)
}

func TestDialTimeout_ConcurrentSetGet(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.SetDialTimeout(time.Duration(i) * time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			_ = l.GetDialTimeout()
		}()
	}
	wg.Wait()
}

func TestOperationTimeout_ConcurrentSetGet(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			l.SetOperationTimeout(OperationTimeouts{
				Bind:   time.Duration(i) * time.Millisecond,
				Search: time.Duration(i) * time.Millisecond,
			})
		}()
		go func() {
			defer wg.Done()
			_ = l.GetOperationTimeout()
		}()
	}
	wg.Wait()
}

// --- Option type ---

func TestOption_NilIsCallerResponsibility(t *testing.T) {
	t.Parallel()

	// NewLDAPper rejects nil options explicitly; the Option contract itself
	// does not need to guard against nil — a bare call panics, which is
	// fine because production code never reaches this point. This test
	// documents the assumption rather than testing NewLDAPper (that lives
	// in ldapper_test.go).
	require.NotPanics(t, func() {
		_ = Option(func(*LDAPper) {})
	})
}
