// Copyright 2020-2026 NGR Softlab
package ldapper

import "github.com/go-ldap/ldap/v3"

// WithSearchLimits overrides default search size/time limits applied to
// every search request built by the connection. Negative values are clamped
// to 0 ("no limit").
func WithSearchLimits(sizeLimit, timeLimit int) Option {
	return func(conn *LDAPper) {
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

// newSearchRequest builds a search request using connection-level limits.
// All search methods should use it instead of calling ldap.NewSearchRequest directly.
func (conn *LDAPper) newSearchRequest(
	baseDN string,
	scope int,
	derefAliases int,
	typesOnly bool,
	filter string,
	attributes []string,
	controls []ldap.Control,
) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		scope,
		derefAliases,
		conn.searchLimits.SizeLimit,
		conn.searchLimits.TimeLimit,
		typesOnly,
		filter,
		attributes,
		controls,
	)
}

// SetSearchLimits overrides connection-level search limits at runtime.
// Negative values are clamped to 0 ("no limit").
// NB: not concurrency-safe — do not call while searches are in flight.
func (conn *LDAPper) SetSearchLimits(sizeLimit, timeLimit int) {
	conn.searchLimits = normalizeSearchLimits(SearchLimits{
		SizeLimit: sizeLimit,
		TimeLimit: timeLimit,
	})
}

// GetSearchLimits returns current connection-level search limits.
func (conn *LDAPper) GetSearchLimits() SearchLimits {
	return conn.searchLimits
}
