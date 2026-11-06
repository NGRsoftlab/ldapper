// Copyright 2020-2026 NGR Softlab
package ldapper

import "time"

// SearchLimits holds default LDAP search request limits.
// TimeLimit == 0 means "no time limit" (server default)
// SizeLimit == 0 means "no size limit" (server default); otherwise it is
// the total number of entries across the entire paged operation, as
// interpreted by RFC 2696 and most mainstream servers.
type SearchLimits struct {
	SizeLimit int
	TimeLimit int
}

// Option configures optional LDAPper parameters.
type Option func(*LDAPper)

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
	return l
}

// SetSearchLimits overrides connection-level search limits at runtime.
// Negative values are clamped to 0 ("no limit").
func (ldapper *LDAPper) SetSearchLimits(sizeLimit, timeLimit int) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	ldapper.searchLimits = normalizeSearchLimits(SearchLimits{
		SizeLimit: sizeLimit,
		TimeLimit: timeLimit,
	})
}

// GetSearchLimits returns current connection-level search limits.
func (ldapper *LDAPper) GetSearchLimits() SearchLimits {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	return ldapper.searchLimits
}

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
