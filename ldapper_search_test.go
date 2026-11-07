// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/mocks"
)

// ---------- helpers ----------

// newTestLDAPper returns a minimal LDAPper wired to conn with default
// search limits. No real dialing or auth is performed; suitable for
// driving search helpers in isolation.
func newTestLDAPper(conn *mocks.MockLDAPConn) *LDAPper {
	l := &LDAPper{searchLimits: DefaultSearchLimits()}
	if conn != nil {
		l.connection = conn
	}
	return l
}

// searchCookie extracts the current paging cookie from a search request —
// this is what the server would receive on the next round-trip.
func searchCookie(req *ldap.SearchRequest) []byte {
	ctrl := ldap.FindControl(req.Controls, ldap.ControlTypePaging)
	if ctrl == nil {
		return nil
	}
	pc, ok := ctrl.(*ldap.ControlPaging)
	if !ok {
		return nil
	}
	return pc.Cookie
}

// pagedResponse builds a *ldap.SearchResult with a paging control carrying
// the given cookie. Nil/empty cookie signals "last page".
func pagedResponse(entries []*ldap.Entry, cookie []byte) *ldap.SearchResult {
	ctrl := ldap.NewControlPaging(1000)
	ctrl.SetCookie(cookie)
	return &ldap.SearchResult{Entries: entries, Controls: []ldap.Control{ctrl}}
}

// ================== searchSingleEntryLocked ==================

func TestSearchSingleEntryLocked_ConnRequired(t *testing.T) {
	t.Parallel()

	l := &LDAPper{} // no connection
	_, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"alice", "dc=example", "(cn=%s)", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestSearchSingleEntryLocked_ClosedClient(t *testing.T) {
	t.Parallel()

	l := newTestLDAPper(&mocks.MockLDAPConn{})
	l.closed = true

	_, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"alice", "dc=example", "(cn=%s)", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
	assert.Contains(t, err.Error(), "closed")
}

func TestSearchSingleEntryLocked_BaseDNValidation(t *testing.T) {
	t.Parallel()

	l := newTestLDAPper(&mocks.MockLDAPConn{})
	_, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"alice", "", "(cn=%s)", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestSearchSingleEntryLocked_EmptyName(t *testing.T) {
	t.Parallel()

	l := newTestLDAPper(&mocks.MockLDAPConn{})
	_, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"", "dc=example", "(cn=%s)", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "empty user name")
}

func TestSearchSingleEntryLocked_NotFound(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: nil}, nil
		},
	}
	l := newTestLDAPper(conn)

	_, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"ghost", "dc=example", "(cn=%s)", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFoundOrNotVisible)
	assert.Contains(t, err.Error(), "user")
	assert.Contains(t, err.Error(), "ghost")
}

func TestSearchSingleEntryLocked_Ambiguous(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=a,dc=x", nil),
				newLDAPEntry("cn=b,dc=x", nil),
			}}, nil
		},
	}
	l := newTestLDAPper(conn)

	_, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"dup", "dc=example", "(cn=%s)", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAmbiguousResult)
}

func TestSearchSingleEntryLocked_Success(t *testing.T) {
	t.Parallel()

	want := newLDAPEntry("cn=alice,dc=example", map[string][]string{"cn": {"alice"}})
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{want}}, nil
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"alice", "dc=example", "(cn=%s)", []string{"cn"})

	require.NoError(t, err)
	assert.Equal(t, want.DN, got.DN)
}

func TestSearchSingleEntryLocked_UsesSizeLimitTwo(t *testing.T) {
	t.Parallel()

	// Contract: SizeLimit=2 is hardcoded so duplicates are detected
	// without over-fetching, independent of user-configured limits.
	var capturedSizeLimit int
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			capturedSizeLimit = req.SizeLimit
			return &ldap.SearchResult{}, nil
		},
	}
	l := newTestLDAPper(conn)
	l.searchLimits.SizeLimit = 999 // must be ignored

	_, _ = l.searchSingleEntryLocked(context.Background(), kindUser,
		"x", "dc=example", "(cn=%s)", nil)

	assert.Equal(t, 2, capturedSizeLimit)
}

func TestSearchSingleEntryLocked_EscapesFilterValue(t *testing.T) {
	t.Parallel()

	var capturedFilter string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			capturedFilter = req.Filter
			return &ldap.SearchResult{}, nil
		},
	}
	l := newTestLDAPper(conn)

	_, _ = l.searchSingleEntryLocked(context.Background(), kindUser,
		"a*b(c)", "dc=example", "(cn=%s)", nil)

	// Special characters in the name must be escaped before substitution.
	assert.Contains(t, capturedFilter, `a\2ab\28c\29`)
}

func TestSearchSingleEntryLocked_LDAPErrorClassified(t *testing.T) {
	t.Parallel()

	// searchSingleEntryLocked wraps the raw error via classifyLDAPError,
	// so the ldapper sentinel must be reachable through errors.Is.
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("server down"))
		},
	}
	l := newTestLDAPper(conn)

	_, err := l.searchSingleEntryLocked(context.Background(), kindUser,
		"x", "dc=example", "(cn=%s)", nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
}

// ================== searchPaged ==================

func TestSearchPaged_ConnRequired(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	_, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestSearchPaged_BaseDNValidation(t *testing.T) {
	t.Parallel()

	l := newTestLDAPper(&mocks.MockLDAPConn{})
	_, err := l.searchPaged(context.Background(), "",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestSearchPaged_SinglePage(t *testing.T) {
	t.Parallel()

	entries := []*ldap.Entry{newLDAPEntry("cn=a,dc=x", nil)}
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return pagedResponse(entries, nil), nil
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "cn=a,dc=x", got[0].DN)
}

func TestSearchPaged_MultiplePages(t *testing.T) {
	t.Parallel()

	page1 := []*ldap.Entry{newLDAPEntry("cn=a,dc=x", nil)}
	page2 := []*ldap.Entry{newLDAPEntry("cn=b,dc=x", nil)}
	calls := 0

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			if len(searchCookie(req)) == 0 {
				// first page: server hands out the next cookie
				return pagedResponse(page1, []byte("page2")), nil
			}
			// second page: empty cookie = end of results
			return pagedResponse(page2, nil), nil
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	require.Len(t, got, 2)
	assert.Equal(t, "cn=a,dc=x", got[0].DN)
	assert.Equal(t, "cn=b,dc=x", got[1].DN)
}

func TestSearchPaged_MaxPagesBudget(t *testing.T) {
	t.Parallel()

	calls := 0
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			// Non-empty but DIFFERENT cookie per call: the repeated-cookie
			// detector must not fire before MaxPages.
			return pagedResponse(
				[]*ldap.Entry{newLDAPEntry("cn=x,dc=x", nil)},
				[]byte{byte(calls)},
			), nil
		},
	}
	l := newTestLDAPper(conn)
	l.searchLimits.MaxPages = 2

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPartialResult)
	assert.Contains(t, err.Error(), "page budget")
	// Two successful pages were collected before the budget triggered.
	assert.Len(t, got, 2)
	assert.Equal(t, 2, calls)
}

func TestSearchPaged_MaxEntriesBudget(t *testing.T) {
	t.Parallel()

	// 3 entries per page, budget of 5: two pages accumulated -> 6 > 5,
	// result truncated to 5 and ErrPartialResult is returned.
	calls := 0
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			return pagedResponse([]*ldap.Entry{
				newLDAPEntry("cn=a,dc=x", nil),
				newLDAPEntry("cn=b,dc=x", nil),
				newLDAPEntry("cn=c,dc=x", nil),
			}, []byte("next")), nil
		},
	}
	l := newTestLDAPper(conn)
	l.searchLimits.MaxEntries = 5

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPartialResult)
	assert.Contains(t, err.Error(), "entry budget")
	assert.Len(t, got, 5)
	assert.Equal(t, 2, calls)
}

func TestSearchPaged_RequirePagingFalse_NoControl(t *testing.T) {
	t.Parallel()

	// Server ignores paging; RequirePaging=false means "accept what we got".
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=a,dc=x", nil),
			}}, nil
		},
	}
	l := newTestLDAPper(conn)
	l.searchLimits.RequirePaging = false

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestSearchPaged_RequirePagingTrue_NoControl(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=a,dc=x", nil),
			}}, nil
		},
	}
	l := newTestLDAPper(conn)
	l.searchLimits.RequirePaging = true

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPartialResult)
	assert.Contains(t, err.Error(), "did not honor paging")
	assert.Len(t, got, 1)
}

func TestSearchPaged_RepeatedCookie(t *testing.T) {
	t.Parallel()

	// Server returns the same non-empty cookie forever: runaway.
	// Both pages are appended before the duplicate is detected, so the
	// caller still sees everything that was fetched before the error.
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return pagedResponse(
				[]*ldap.Entry{newLDAPEntry("cn=x,dc=x", nil)},
				[]byte("stuck"),
			), nil
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPartialResult)
	assert.Contains(t, err.Error(), "repeated cookie")
	assert.Len(t, got, 2)
}

func TestSearchPaged_SizeLimitExceededPreservesEntries(t *testing.T) {
	t.Parallel()

	calls := 0
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			if calls == 1 {
				return pagedResponse([]*ldap.Entry{
					newLDAPEntry("cn=a,dc=x", nil),
				}, []byte("next")), nil
			}
			return nil, ldap.NewError(ldap.LDAPResultSizeLimitExceeded,
				errors.New("size limit"))
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPartialResult)
	assert.Len(t, got, 1, "already-fetched entries must be preserved")
}

func TestSearchPaged_ContextCancelledDuringFirstPage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			// Cancel inside the first page's SearchFunc. withCtxResult
			// consults ctx.Err() after fn returns, so this page's
			// entries are discarded rather than appended.
			cancel()
			return pagedResponse([]*ldap.Entry{
				newLDAPEntry("cn=a,dc=x", nil),
			}, []byte("next")), nil
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.searchPaged(ctx, "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, got,
		"entries from an aborted page must be discarded")
}

func TestSearchPaged_ContextCancelledBetweenPagesPreservesEarlierPages(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	calls := 0
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			if calls == 1 {
				// First page: return normally with a non-empty cookie
				// so the loop proceeds to a second iteration.
				return pagedResponse([]*ldap.Entry{
					newLDAPEntry("cn=a,dc=x", nil),
				}, []byte("page2")), nil
			}
			// Second page: cancel before returning. This page is
			// discarded, but page-1 entries were already appended
			// before this iteration began and must survive.
			cancel()
			return pagedResponse([]*ldap.Entry{
				newLDAPEntry("cn=b,dc=x", nil),
			}, nil), nil
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.searchPaged(ctx, "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	require.Len(t, got, 1, "page-1 entries must be preserved")
	assert.Equal(t, "cn=a,dc=x", got[0].DN)
}

func TestSearchPaged_RawLDAPErrorPropagates(t *testing.T) {
	t.Parallel()

	// searchPaged does NOT classify non-size-limit errors: it returns them
	// raw. Callers (e.g. getUserGroupsLocked) do the classification.
	// Therefore *ldap.Error must be reachable via errors.As, and the
	// ldapper sentinel must NOT be in the chain here.
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newTestLDAPper(conn)

	_, err := l.searchPaged(context.Background(), "dc=example",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false, "(cn=*)", nil, nil)

	require.Error(t, err)
	var ldapErr *ldap.Error
	assert.ErrorAs(t, err, &ldapErr)
	assert.NotErrorIs(t, err, ErrUnavailable,
		"classification must happen at the caller, not inside searchPaged")
}

// ================== CustomSearch ==================

func TestCustomSearch_NilRequest(t *testing.T) {
	t.Parallel()

	l := newTestLDAPper(&mocks.MockLDAPConn{})
	_, err := l.CustomSearch(context.Background(), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestCustomSearch_ConnRequired(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	_, err := l.CustomSearch(context.Background(),
		ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, 1, false, "(objectClass=*)", nil, nil))

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestCustomSearch_Success(t *testing.T) {
	t.Parallel()

	want := &ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("cn=a,dc=x", nil),
	}}
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return want, nil
		},
	}
	l := newTestLDAPper(conn)

	got, err := l.CustomSearch(context.Background(),
		ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, 1, false, "(objectClass=*)", nil, nil))

	require.NoError(t, err)
	assert.Same(t, want, got)
}

func TestCustomSearch_LDAPErrorClassified(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("nope"))
		},
	}
	l := newTestLDAPper(conn)

	_, err := l.CustomSearch(context.Background(),
		ldap.NewSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, 1, false, "(objectClass=*)", nil, nil))

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

// ================== CustomSearchPaged ==================

func TestCustomSearchPaged_NilRequest(t *testing.T) {
	t.Parallel()

	// Nil check happens BEFORE locking and BEFORE the connection check —
	// unlike CustomSearch, which checks conn first. Documented asymmetry.
	l := newTestLDAPper(&mocks.MockLDAPConn{})
	_, err := l.CustomSearchPaged(context.Background(), nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestCustomSearchPaged_NoConn(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	req := ldap.NewSearchRequest("dc=x", ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)

	_, err := l.CustomSearchPaged(context.Background(), req)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestCustomSearchPaged_ProxiesToSearchPaged(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return pagedResponse([]*ldap.Entry{
				newLDAPEntry("cn=a,dc=x", nil),
			}, nil), nil
		},
	}
	l := newTestLDAPper(conn)

	req := ldap.NewSearchRequest("dc=x", ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)

	got, err := l.CustomSearchPaged(context.Background(), req)

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "cn=a,dc=x", got[0].DN)
}

func TestCustomSearchPaged_PreservesCallerControls(t *testing.T) {
	t.Parallel()

	// Caller controls must be forwarded to the server AND the paging
	// control must be appended on top. Verified by inspecting the request
	// inside the mock.
	marker := ldap.NewControlManageDsaIT(true)
	var sawMarker bool
	var sawPaging bool

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			for _, c := range req.Controls {
				switch c.GetControlType() {
				case marker.GetControlType():
					sawMarker = true
				case ldap.ControlTypePaging:
					sawPaging = true
				}
			}
			return pagedResponse(nil, nil), nil
		},
	}
	l := newTestLDAPper(conn)

	req := ldap.NewSearchRequest("dc=x", ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil,
		[]ldap.Control{marker})

	_, err := l.CustomSearchPaged(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, sawMarker, "caller-supplied control must reach the server")
	assert.True(t, sawPaging, "paging control must be added on top")
}
