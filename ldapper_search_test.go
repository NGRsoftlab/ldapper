// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/mocks"
)

// ---------- test helpers ----------

// searchCall is a snapshot of a single Search invocation. Fields are copied
// at call time because searchPaged reuses the same *ldap.ControlPaging
// object across pages and mutates its cookie between requests — inspecting
// req.Controls after the loop would yield the final cookie for every call.
type searchCall struct {
	baseDN       string
	scope        int
	sizeLimit    int
	timeLimit    int
	filter       string
	attributes   []string
	nonPaging    []ldap.Control // non-paging controls preserved by the caller
	hasPaging    bool           // true if a *ldap.ControlPaging was present
	pagingCookie []byte         // copy of the paging control's cookie
}

// pagedPage describes one response returned by the mock.
//
//   - err != nil              → Search returns the error directly.
//   - nextCookie == nil       → response has NO paging control (server
//     does not honor paging); loop terminates after one page.
//   - nextCookie is non-nil   → response carries a paging control with this
//     cookie; empty cookie terminates the loop normally.
type pagedPage struct {
	entries    []*ldap.Entry
	nextCookie []byte
	err        error
}

// captureMock yields the configured pages in order and records every
// Search request. Extra calls beyond the prepared pages are an error,
// so tests fail loudly on unexpected paging behaviour.
type captureMock struct {
	mock  *mocks.MockLDAPConn
	calls []searchCall
	idx   int
	pages []pagedPage
}

func newCaptureMock(t *testing.T, pages ...pagedPage) *captureMock {
	t.Helper()
	cm := &captureMock{pages: pages}
	cm.mock = &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			cm.calls = append(cm.calls, snapshotRequest(req))
			if cm.idx >= len(cm.pages) {
				return nil, errors.New("mock: unexpected extra search call")
			}
			p := cm.pages[cm.idx]
			cm.idx++
			if p.err != nil {
				return nil, p.err
			}
			res := &ldap.SearchResult{Entries: p.entries}
			if p.nextCookie != nil {
				ctrl := ldap.NewControlPaging(1000)
				ctrl.SetCookie(p.nextCookie)
				res.Controls = append(res.Controls, ctrl)
			}
			return res, nil
		},
	}
	return cm
}

// snapshotRequest copies wire-relevant fields of req, isolating the captured
// state from later mutations of shared control objects.
func snapshotRequest(req *ldap.SearchRequest) searchCall {
	c := searchCall{
		baseDN:     req.BaseDN,
		scope:      req.Scope,
		sizeLimit:  req.SizeLimit,
		timeLimit:  req.TimeLimit,
		filter:     req.Filter,
		attributes: append([]string(nil), req.Attributes...),
	}
	for _, ctrl := range req.Controls {
		if pc, ok := ctrl.(*ldap.ControlPaging); ok {
			c.hasPaging = true
			c.pagingCookie = append([]byte(nil), pc.Cookie...)
			continue
		}
		c.nonPaging = append(c.nonPaging, ctrl)
	}
	return c
}

func newLDAPperWithCapture(cm *captureMock) *LDAPper {
	return &LDAPper{connection: cm.mock}
}

// ---------- newSearchRequest ----------

// TestNewSearchRequest asserts the low-level request builder propagates
// connection-level limits and every argument verbatim.
func TestNewSearchRequest(t *testing.T) {
	t.Run("uses connection-level size and time limits", func(t *testing.T) {
		l := &LDAPper{searchLimits: SearchLimits{SizeLimit: 42, TimeLimit: 7}}
		req := l.newSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.DerefFindingBaseObj,
			true,
			"(cn=a)",
			[]string{"cn", "mail"},
			nil,
		)
		if req.BaseDN != "dc=example,dc=com" {
			t.Fatalf("BaseDN = %q", req.BaseDN)
		}
		if req.Scope != ldap.ScopeSingleLevel {
			t.Fatalf("Scope = %d", req.Scope)
		}
		if req.DerefAliases != ldap.DerefFindingBaseObj {
			t.Fatalf("DerefAliases = %d", req.DerefAliases)
		}
		if req.SizeLimit != 42 || req.TimeLimit != 7 {
			t.Fatalf("limits not propagated: size=%d time=%d", req.SizeLimit, req.TimeLimit)
		}
		if !req.TypesOnly {
			t.Fatalf("TypesOnly = false, want true")
		}
		if req.Filter != "(cn=a)" {
			t.Fatalf("Filter = %q", req.Filter)
		}
		if len(req.Attributes) != 2 || req.Attributes[0] != "cn" {
			t.Fatalf("Attributes = %v", req.Attributes)
		}
	})

	t.Run("zero limits pass through", func(t *testing.T) {
		l := &LDAPper{}
		req := l.newSearchRequest(
			"dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			false, "(objectClass=*)", nil, nil,
		)
		if req.SizeLimit != 0 || req.TimeLimit != 0 {
			t.Fatalf("zero limits expected, got size=%d time=%d", req.SizeLimit, req.TimeLimit)
		}
		if req.Attributes != nil {
			t.Fatalf("nil attributes expected, got %v", req.Attributes)
		}
	})
}

// ---------- searchSingleEntryLocked ----------

// TestSearchSingleEntryLocked covers the 0 / 1 / >1 contract, input
// validation, filter escaping and the SizeLimit=2 invariant.
func TestSearchSingleEntryLocked(t *testing.T) {
	const template = "(&(objectClass=user)(uid=%s))"
	attrs := []string{"uid", "cn"}

	t.Run("nil connection returns ErrClosed", func(t *testing.T) {
		l := &LDAPper{}
		_, err := l.searchSingleEntryLocked(kindUser, "alice", "dc=x", template, attrs)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty baseDN rejected", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		_, err := l.searchSingleEntryLocked(kindUser, "alice", "", template, attrs)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
		if len(cm.calls) != 0 {
			t.Fatalf("no search should have been issued, got %d", len(cm.calls))
		}
	})

	t.Run("malformed baseDN rejected", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		_, err := l.searchSingleEntryLocked(kindUser, "alice", "not a dn", template, attrs)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("empty name rejected with kind label", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		_, err := l.searchSingleEntryLocked(kindGroup, "", "dc=x", template, attrs)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
		if !strings.Contains(err.Error(), "group") {
			t.Fatalf("error message should mention kind 'group': %v", err)
		}
	})

	t.Run("search error classified", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("server down")}
		cm := newCaptureMock(t, pagedPage{err: raw})
		l := newLDAPperWithCapture(cm)
		_, err := l.searchSingleEntryLocked(kindUser, "alice", "dc=x", template, attrs)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
		// Underlying *ldap.Error must remain reachable through the chain.
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) {
			t.Fatalf("errors.As did not recover *ldap.Error from %v", err)
		}
	})

	t.Run("zero entries returns ErrNotFound", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		_, err := l.searchSingleEntryLocked(kindUser, "alice", "dc=x", template, attrs)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
		if !strings.Contains(err.Error(), `"alice"`) {
			t.Fatalf("error should quote the name: %v", err)
		}
	})

	t.Run("exactly one entry returned", func(t *testing.T) {
		e := newLDAPEntry("cn=Alice,dc=x", map[string][]string{"cn": {"Alice"}, "uid": {"alice"}})
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{e}})
		l := newLDAPperWithCapture(cm)
		got, err := l.searchSingleEntryLocked(kindUser, "alice", "dc=x", template, attrs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.DN != e.DN {
			t.Fatalf("DN = %q, want %q", got.DN, e.DN)
		}
	})

	t.Run("multiple entries returns ErrAmbiguousResult", func(t *testing.T) {
		e1 := newLDAPEntry("cn=A1,dc=x", nil)
		e2 := newLDAPEntry("cn=A2,dc=x", nil)
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{e1, e2}})
		l := newLDAPperWithCapture(cm)
		_, err := l.searchSingleEntryLocked(kindUser, "alice", "dc=x", template, attrs)
		if !errors.Is(err, ErrAmbiguousResult) {
			t.Fatalf("errors.Is(%v, ErrAmbiguousResult) = false", err)
		}
	})

	t.Run("filter is escaped", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		_, _ = l.searchSingleEntryLocked(kindUser, "a(b*c)", "dc=x", template, attrs)
		if len(cm.calls) != 1 {
			t.Fatalf("expected one call, got %d", len(cm.calls))
		}
		if !strings.Contains(cm.calls[0].filter, `a\28b\2ac\29`) {
			t.Fatalf("filter not escaped: %q", cm.calls[0].filter)
		}
	})

	t.Run("size limit is fixed to 2; time limit from searchLimits", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		l.searchLimits = SearchLimits{SizeLimit: 100, TimeLimit: 15}
		_, _ = l.searchSingleEntryLocked(kindUser, "alice", "dc=x", template, attrs)
		if len(cm.calls) != 1 {
			t.Fatalf("expected one call, got %d", len(cm.calls))
		}
		if cm.calls[0].sizeLimit != 2 {
			t.Fatalf("size limit = %d, want 2 (independent of searchLimits)", cm.calls[0].sizeLimit)
		}
		if cm.calls[0].timeLimit != 15 {
			t.Fatalf("time limit = %d, want 15 (from searchLimits)", cm.calls[0].timeLimit)
		}
	})
}

// ---------- searchPaged ----------

// TestSearchPaged exercises the paging protocol: cookie propagation, page
// concatenation, error classification behaviour and the partial-result
// preservation contract.
func TestSearchPaged(t *testing.T) {
	e1 := newLDAPEntry("cn=A,dc=x", nil)
	e2 := newLDAPEntry("cn=B,dc=x", nil)
	e3 := newLDAPEntry("cn=C,dc=x", nil)

	t.Run("nil connection returns ErrClosed", func(t *testing.T) {
		l := &LDAPper{}
		_, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty baseDN rejected", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		_, err := l.searchPaged("", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("server does not honor paging: single page returned", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{e1, e2}})
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("got %d entries, want 2", len(entries))
		}
		if len(cm.calls) != 1 {
			t.Fatalf("got %d calls, want 1", len(cm.calls))
		}
	})

	t.Run("server returns empty cookie: single page returned", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{e1}, nextCookie: []byte{}})
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(entries) != 1 || len(cm.calls) != 1 {
			t.Fatalf("got %d entries / %d calls, want 1/1", len(entries), len(cm.calls))
		}
	})

	t.Run("multiple pages concatenated in order", func(t *testing.T) {
		cm := newCaptureMock(t,
			pagedPage{entries: []*ldap.Entry{e1}, nextCookie: []byte("p2")},
			pagedPage{entries: []*ldap.Entry{e2}, nextCookie: []byte("p3")},
			pagedPage{entries: []*ldap.Entry{e3}, nextCookie: []byte{}},
		)
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(entries) != 3 || len(cm.calls) != 3 {
			t.Fatalf("got %d entries / %d calls, want 3/3", len(entries), len(cm.calls))
		}
		if entries[0].DN != e1.DN || entries[1].DN != e2.DN || entries[2].DN != e3.DN {
			t.Fatalf("entries order not preserved")
		}
	})

	t.Run("paging cookies propagated across calls", func(t *testing.T) {
		cm := newCaptureMock(t,
			pagedPage{nextCookie: []byte("p2")},
			pagedPage{nextCookie: []byte("p3")},
			pagedPage{nextCookie: []byte{}},
		)
		l := newLDAPperWithCapture(cm)
		_, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cm.calls) != 3 {
			t.Fatalf("got %d calls, want 3", len(cm.calls))
		}
		// Call 0: fresh paging control (empty cookie).
		if !cm.calls[0].hasPaging || len(cm.calls[0].pagingCookie) != 0 {
			t.Fatalf("call 0 paging cookie = %q, want empty with control present", cm.calls[0].pagingCookie)
		}
		// Call 1: cookie echoed from page 1.
		if got := string(cm.calls[1].pagingCookie); got != "p2" {
			t.Fatalf("call 1 paging cookie = %q, want %q", got, "p2")
		}
		// Call 2: cookie echoed from page 2.
		if got := string(cm.calls[2].pagingCookie); got != "p3" {
			t.Fatalf("call 2 paging cookie = %q, want %q", got, "p3")
		}
	})

	t.Run("caller controls preserved in every request", func(t *testing.T) {
		callerCtrl := ldap.NewControlManageDsaIT(true)
		cm := newCaptureMock(t,
			pagedPage{nextCookie: []byte("p2")},
			pagedPage{nextCookie: []byte{}},
		)
		l := newLDAPperWithCapture(cm)
		_, _ = l.searchPaged(
			"dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false,
			"(cn=*)", nil, []ldap.Control{callerCtrl},
		)
		for i, c := range cm.calls {
			if !c.hasPaging {
				t.Fatalf("call %d: paging control missing", i)
			}
			if len(c.nonPaging) != 1 {
				t.Fatalf("call %d: expected 1 non-paging control, got %d", i, len(c.nonPaging))
			}
		}
	})

	t.Run("search limits applied to each page request", func(t *testing.T) {
		cm := newCaptureMock(t,
			pagedPage{nextCookie: []byte("p2")},
			pagedPage{nextCookie: []byte{}},
		)
		l := newLDAPperWithCapture(cm)
		l.searchLimits = SearchLimits{SizeLimit: 100, TimeLimit: 15}
		_, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for i, c := range cm.calls {
			if c.sizeLimit != 100 || c.timeLimit != 15 {
				t.Fatalf("call %d: limits not applied: size=%d time=%d", i, c.sizeLimit, c.timeLimit)
			}
		}
	})

	t.Run("search error on first page propagates raw", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("down")}
		cm := newCaptureMock(t, pagedPage{err: raw})
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err == nil || len(entries) != 0 {
			t.Fatalf("expected nil entries + error, got entries=%d err=%v", len(entries), err)
		}
		// searchPaged is a raw primitive: caller is expected to classify.
		if !errors.Is(err, raw) {
			t.Fatalf("errors.Is(err, raw) = false")
		}
		if errors.Is(err, ErrUnavailable) {
			t.Fatalf("searchPaged must not classify errors on its own")
		}
	})

	t.Run("non-size-limit error after entries discards them", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultOperationsError, Err: errors.New("boom")}
		cm := newCaptureMock(t,
			pagedPage{entries: []*ldap.Entry{e1}, nextCookie: []byte("p2")},
			pagedPage{err: raw},
		)
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err == nil || len(entries) != 0 {
			t.Fatalf("expected nil entries + error, got entries=%d err=%v", len(entries), err)
		}
		if !errors.Is(err, raw) {
			t.Fatalf("raw error should be preserved")
		}
	})

	t.Run("size-limit exceeded after entries: partial preserved", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultSizeLimitExceeded, Err: errors.New("size limit")}
		cm := newCaptureMock(t,
			pagedPage{entries: []*ldap.Entry{e1}, nextCookie: []byte("p2")},
			pagedPage{err: raw},
		)
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if !errors.Is(err, ErrPartialResult) {
			t.Fatalf("errors.Is(%v, ErrPartialResult) = false", err)
		}
		if len(entries) != 1 || entries[0].DN != e1.DN {
			t.Fatalf("expected 1 preserved entry, got %d", len(entries))
		}
		// Both sentinel and original *ldap.Error must be reachable.
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) {
			t.Fatalf("errors.As did not recover *ldap.Error from %v", err)
		}
		if ldapErr.ResultCode != ldap.LDAPResultSizeLimitExceeded {
			t.Fatalf("recovered code = %d", ldapErr.ResultCode)
		}
	})

	t.Run("size-limit exceeded on first page: nil entries, raw error", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultSizeLimitExceeded, Err: errors.New("size limit")}
		cm := newCaptureMock(t, pagedPage{err: raw})
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if len(entries) != 0 {
			t.Fatalf("expected nil entries, got %d", len(entries))
		}
		if !errors.Is(err, raw) {
			t.Fatalf("errors.Is(err, raw) = false; got %v", err)
		}
		// Without a partial result there is nothing to mark partial —
		// ErrPartialResult must not appear.
		if errors.Is(err, ErrPartialResult) {
			t.Fatalf("did not expect ErrPartialResult when zero entries collected")
		}
	})

	t.Run("empty page without paging terminates cleanly", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		entries, err := l.searchPaged("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)
		if err != nil || len(entries) != 0 {
			t.Fatalf("expected empty result, got entries=%d err=%v", len(entries), err)
		}
	})
}

// ---------- CustomSearch ----------

// TestCustomSearch verifies the pass-through contract: no validation, no
// paging, caller owns request semantics; only the error is classified.
func TestCustomSearch(t *testing.T) {
	t.Run("nil connection returns ErrClosed", func(t *testing.T) {
		l := &LDAPper{}
		req := ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil)
		_, err := l.CustomSearch(req)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("nil request returns ErrInvalidArgument", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		_, err := l.CustomSearch(nil)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("request passed through unchanged", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{newLDAPEntry("cn=A,dc=x", nil)}})
		l := newLDAPperWithCapture(cm)
		req := ldap.NewSearchRequest(
			"ou=Users,dc=x",
			ldap.ScopeSingleLevel,
			ldap.DerefInSearching,
			42, // size limit: CustomSearch must NOT touch it
			7,  // time limit
			true,
			"(cn=alice)",
			[]string{"cn", "mail"},
			nil,
		)
		res, err := l.CustomSearch(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res == nil || len(res.Entries) != 1 {
			t.Fatalf("unexpected result: %+v", res)
		}
		if len(cm.calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(cm.calls))
		}
		got := cm.calls[0]
		if got.baseDN != "ou=Users,dc=x" || got.scope != ldap.ScopeSingleLevel {
			t.Fatalf("request fields not preserved: %+v", got)
		}
		if got.sizeLimit != 42 || got.timeLimit != 7 {
			t.Fatalf("limits not preserved: size=%d time=%d", got.sizeLimit, got.timeLimit)
		}
		if got.filter != "(cn=alice)" {
			t.Fatalf("filter not preserved: %q", got.filter)
		}
		// No paging control should have been injected by CustomSearch.
		if got.hasPaging {
			t.Fatalf("CustomSearch must not add a paging control")
		}
	})

	t.Run("error classified", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject, Err: errors.New("gone")}
		cm := newCaptureMock(t, pagedPage{err: raw})
		l := newLDAPperWithCapture(cm)
		req := ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil)
		_, err := l.CustomSearch(req)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
	})
}

// ---------- CustomSearchPaged ----------

// TestCustomSearchPaged verifies both the proxy contract (pass-through to
// searchPaged with paging) and the input-validation order: nil request is
// rejected BEFORE the connection is touched, so a zero-value LDAPper
// returns ErrInvalidArgument rather than ErrClosed.
func TestCustomSearchPaged(t *testing.T) {
	t.Run("nil request rejected before locking", func(t *testing.T) {
		// Zero-value LDAPper: no connection, no search limits.
		l := &LDAPper{}
		_, err := l.CustomSearchPaged(nil)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
		if errors.Is(err, ErrClosed) {
			t.Fatalf("nil-request check must precede the connection check")
		}
	})

	t.Run("nil connection returns ErrClosed", func(t *testing.T) {
		l := &LDAPper{}
		req := ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil)
		_, err := l.CustomSearchPaged(req)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty baseDN in request rejected", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", nil, nil)
		_, err := l.CustomSearchPaged(req)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("pages across responses", func(t *testing.T) {
		e1 := newLDAPEntry("cn=A,dc=x", nil)
		e2 := newLDAPEntry("cn=B,dc=x", nil)
		cm := newCaptureMock(t,
			pagedPage{entries: []*ldap.Entry{e1}, nextCookie: []byte("p2")},
			pagedPage{entries: []*ldap.Entry{e2}, nextCookie: []byte{}},
		)
		l := newLDAPperWithCapture(cm)
		req := ldap.NewSearchRequest("dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, "(cn=*)", []string{"cn"}, nil)
		entries, err := l.CustomSearchPaged(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("got %d entries, want 2", len(entries))
		}
	})

	t.Run("caller controls preserved alongside paging", func(t *testing.T) {
		callerCtrl := ldap.NewControlManageDsaIT(true)
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		req := ldap.NewSearchRequest(
			"dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(cn=*)", nil, []ldap.Control{callerCtrl},
		)
		_, _ = l.CustomSearchPaged(req)
		if len(cm.calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(cm.calls))
		}
		if len(cm.calls[0].nonPaging) != 1 || !cm.calls[0].hasPaging {
			t.Fatalf("controls not preserved: %+v", cm.calls[0])
		}
	})
}
