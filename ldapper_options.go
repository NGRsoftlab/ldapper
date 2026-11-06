// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"time"

	"github.com/NGRsoftlab/ldapper/constants"
)

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
// entries collected so far. Complements the seenCookies check: MaxPages
// bounds the total work regardless of cookie behavior, while seenCookies
// catches the specific A→B→A cycle that MaxPages would only stop late.
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

	// RequirePaging makes paged searches fail with ErrPartialResult when
	// the server does not return a paging control. Without this flag the
	// result is returned as-is, because a server that ignored paging may
	// still have returned the complete set — the caller cannot tell.
	//
	// Enable this when completeness of the result is part of the contract
	// (e.g., security decisions based on "user belongs to ALL groups").
	RequirePaging bool
}

// DefaultSearchLimits returns SearchLimits populated with the library
// defaults: SizeLimit=0 (server default), TimeLimit=30, MaxPages=0,
// MaxEntries=0 (no client-side budget), RequirePaging=true.
//
// Useful for building a SearchLimits value incrementally before passing it
// to WithSearchLimits or SetSearchLimits:
//
//	limits := ldapper.DefaultSearchLimits()
//	limits.SizeLimit = 500
//	limits.MaxPages = 100
//	conn, _ := ldapper.NewLDAPper(..., ldapper.WithSearchLimits(limits))
//
// The same pattern works after construction via GetSearchLimits /
// SetSearchLimits.
func DefaultSearchLimits() SearchLimits {
	return SearchLimits{
		SizeLimit:     constants.DefaultSearchSizeLimit,
		TimeLimit:     constants.DefaultSearchTimeLimit,
		MaxPages:      0,
		MaxEntries:    0,
		RequirePaging: true,
	}
}

// WithSearchLimits replaces the entire connection-level search limits
// structure. Negative fields are clamped to zero.
//
// NB: WithSearchLimits replaces the whole struct. Fields omitted in
// `limits` get Go zero values, NOT the values from DefaultSearchLimits().
// In particular:
//   - a zero TimeLimit means "no server-side time limit";
//   - a zero RequirePaging means "silently accept missing paging control"
//     even though DefaultSearchLimits() sets it to true.
//
// Pass DefaultSearchLimits() as the base if you want to keep the defaults:
//
//	limits := ldapper.DefaultSearchLimits()
//	limits.SizeLimit = 100
//	conn, _ := ldapper.NewLDAPper(..., ldapper.WithSearchLimits(limits))
func WithSearchLimits(limits SearchLimits) Option {
	return func(l *LDAPper) {
		// NB: applied by NewLDAPper before the LDAPper is returned to
		// caller; no concurrent access is possible at this point.
		l.searchLimits = normalizeSearchLimits(limits)
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

// SetSearchLimits replaces the entire connection-level search limits at
// runtime. Negative fields are clamped to zero. Takes opMu, so safe to call
// concurrently with searches; the new values apply to the next request.
//
// NB: this is a wholesale replacement — see WithSearchLimits for the
// read-modify-write pattern when only a subset of fields should change.
func (ldapper *LDAPper) SetSearchLimits(limits SearchLimits) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	ldapper.searchLimits = normalizeSearchLimits(limits)
}

// GetSearchLimits returns a copy of the current connection-level search
// limits. Use together with SetSearchLimits for read-modify-write.
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
		l.dialTimeout = normalizeDialTimeout(d)
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

func normalizeOperationTimeouts(t OperationTimeouts) OperationTimeouts {
	if t.Bind < 0 {
		t.Bind = 0
	}
	if t.Search < 0 {
		t.Search = 0
	}

	return t
}

// WithOperationTimeout overrides connection-level client-side timeouts.
// Negative durations are clamped to zero.
//
// The timeout is applied via LDAPConn.SetTimeout, which is part of the
// interface contract — every implementation, including mocks, must
// support it. After the operation, the timeout is reset to zero so it
// does not cap subsequent operations.
func WithOperationTimeout(t OperationTimeouts) Option {
	return func(l *LDAPper) {
		l.opTimeouts = normalizeOperationTimeouts(t)
	}
}

// SetOperationTimeout overrides connection-level client-side timeouts at
// runtime. Negative durations are clamped to zero.
func (ldapper *LDAPper) SetOperationTimeout(t OperationTimeouts) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	ldapper.opTimeouts = normalizeOperationTimeouts(t)
}

// GetOperationTimeout returns current connection-level client-side timeouts.
func (ldapper *LDAPper) GetOperationTimeout() OperationTimeouts {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	return ldapper.opTimeouts
}
