// Copyright 2020-2026 NGR Softlab
package ldapper

import "time"

// Option configures optional LDAPper parameters.
type Option func(*LDAPper)

// -- SearchLimits -- //

// SearchLimits holds connection-level search limits.
//
// SizeLimit == 0 means "no size limit" (server default); otherwise it is
// the total number of entries across the entire paged operation, as
// interpreted by RFC 2696 and most mainstream servers.
//
// TimeLimit == 0 means "no time limit" (server-side; seconds).
//
// MaxPages == 0 means "no page limit"; otherwise paged searches stop after
// MaxPages successful pages and return ErrPartialResult together with the
// entries collected so far. Guards against servers that never send an
// empty paging cookie.
//
// MaxEntries == 0 means "no entry limit"; otherwise paged searches stop
// after MaxEntries entries have been accumulated and return ErrPartialResult
// with the truncated slice. Bounds client-side memory for very large
// subtrees.
//
// NB: SizeLimit and MaxEntries are complementary. SizeLimit is enforced
// by the server; MaxEntries is enforced locally and works even against
// servers that ignore SizeLimit.
type SearchLimits struct {
	SizeLimit  int
	TimeLimit  int
	MaxPages   int
	MaxEntries int
}

// WithSearchLimits overrides default search size/time limits applied to
// every search request built by the connection. Negative values are clamped
// to 0 ("no limit").
//
// NB: SizeLimit is applied per request, so when combined with the
// automatic paging (GetCatalogTree, GetOUUsers, ...), the total number of
// returned entries will be SizeLimit * <number of pages>. Set to 0 to let
// paging return the full result set.
func WithSearchLimits(sizeLimit, timeLimit int) Option {
	return func(conn *LDAPper) {
		// NB: applied by NewLDAPper before the LDAPper is returned to caller;
		// no concurrent access is possible at this point.
		conn.searchLimits = normalizeSearchLimits(SearchLimits{
			SizeLimit: sizeLimit,
			TimeLimit: timeLimit,
		})
	}
}

func normalizeSearchLimits(l SearchLimits) SearchLimits {
	if l.SizeLimit < 0 {
		l.SizeLimit = 0
	}
	if l.TimeLimit < 0 {
		l.TimeLimit = 0
	}
	if l.MaxPages < 0 {
		l.MaxPages = 0
	}
	if l.MaxEntries < 0 {
		l.MaxEntries = 0
	}
	return l
}

// WithPagingLimits overrides the page-count and entry-count budgets applied
// to every paged search (GetCatalogTree, GetOUUsers, GetUserGroups,
// GetSubOUs, ListSingleLevelOUs, CustomSearchPaged). Zero values disable
// the corresponding budget; negative values are clamped to zero.
//
// When a budget is exceeded, the search returns ErrPartialResult together
// with the entries/pages collected so far. The error wraps the underlying
// sentinel so errors.Is(err, ErrPartialResult) keeps working.
func WithPagingLimits(maxPages, maxEntries int) Option {
	return func(l *LDAPper) {
		if maxPages < 0 {
			maxPages = 0
		}
		if maxEntries < 0 {
			maxEntries = 0
		}
		l.searchLimits.MaxPages = maxPages
		l.searchLimits.MaxEntries = maxEntries
	}
}

// SetSearchLimits overrides connection-level search limits at runtime.
// Negative values are clamped to 0 ("no limit").
func (ldapper *LDAPper) SetSearchLimits(sizeLimit, timeLimit int) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	normalized := normalizeSearchLimits(SearchLimits{
		SizeLimit: sizeLimit,
		TimeLimit: timeLimit,
	})

	// Preserve paging budgets — they were set via WithPagingLimits or
	// SetPagingLimits and are orthogonal to size/time limits.
	ldapper.searchLimits.SizeLimit = normalized.SizeLimit
	ldapper.searchLimits.TimeLimit = normalized.TimeLimit
}

// SetPagingLimits overrides the connection-level paging budgets at runtime.
// Negative values are clamped to zero. Takes opMu, so safe to call
// concurrently with searches; the new values apply to the next request.
func (ldapper *LDAPper) SetPagingLimits(maxPages, maxEntries int) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if maxPages < 0 {
		maxPages = 0
	}
	if maxEntries < 0 {
		maxEntries = 0
	}

	ldapper.searchLimits.MaxPages = maxPages
	ldapper.searchLimits.MaxEntries = maxEntries
}

// GetPagingLimits returns the current connection-level paging budgets.
func (ldapper *LDAPper) GetPagingLimits() (maxPages, maxEntries int) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.searchLimits.MaxPages, ldapper.searchLimits.MaxEntries
}

// GetSearchLimits returns current connection-level search limits.
func (ldapper *LDAPper) GetSearchLimits() SearchLimits {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	return ldapper.searchLimits
}

// -- DialTimeout -- //

// WithDialTimeout overrides default connect/reconnect dial timeout.
// Negative values are clamped to 0 ("no timeout").
func WithDialTimeout(d time.Duration) Option {
	return func(l *LDAPper) {
		// NB: negative is normalized to zero — same convention as search limits.
		// NB: applied by NewLDAPper before the LDAPper is returned to caller;
		// no concurrent access is possible at this point.
		if d < 0 {
			d = 0
		}
		l.dialTimeout = d
	}
}

func normalizeDialTimeout(d time.Duration) time.Duration {
	if d < 0 {
		d = 0
	}
	return d
}

// SetDialTimeout overrides connect/reconnect dial timeout in runtime
func (ldapper *LDAPper) SetDialTimeout(d time.Duration) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	ldapper.dialTimeout = normalizeDialTimeout(d)
}

// GetDialTimeout returns current connect/reconnect dial timeout
func (ldapper *LDAPper) GetDialTimeout() time.Duration {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	return ldapper.dialTimeout
}

// -- OperationTimeouts -- //

// OperationTimeouts holds connection-level client-side timeouts applied
// around individual Bind and Search calls. They complement, but do not
// replace, SearchRequest.TimeLimit (which is a server-side limit, not a
// client-side deadline).
//
// Zero values disable the corresponding timeout (fall back to whatever the
// underlying go-ldap Conn has configured — by default, no timeout).
type OperationTimeouts struct {
	Bind   time.Duration
	Search time.Duration
}

// WithOperationTimeout overrides connection-level client-side timeouts.
// Negative durations are clamped to zero.
//
// The timeout is applied via LDAPConn.SetTimeout if the underlying
// implementation supports it (production *ldap.Conn does; test mocks may
// not). After the operation, the timeout is reset to zero so it does not
// cap subsequent operations.
func WithOperationTimeout(t OperationTimeouts) Option {
	return func(l *LDAPper) {
		if t.Bind < 0 {
			t.Bind = 0
		}
		if t.Search < 0 {
			t.Search = 0
		}
		l.opTimeouts = t
	}
}

// SetOperationTimeout overrides connection-level client-side timeouts at
// runtime. Negative durations are clamped to zero.
func (ldapper *LDAPper) SetOperationTimeout(t OperationTimeouts) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	if t.Bind < 0 {
		t.Bind = 0
	}
	if t.Search < 0 {
		t.Search = 0
	}
	ldapper.opTimeouts = t
}

// GetOperationTimeout returns current connection-level client-side timeouts.
func (ldapper *LDAPper) GetOperationTimeout() OperationTimeouts {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.opTimeouts
}
