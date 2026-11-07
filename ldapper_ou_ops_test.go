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

// ouAdapter extends fakeAdapter with the OU-specific bits used by
// getOULocked. Only OUAttrs / SearchOUFilterTemplate are meaningfully
// implemented; the rest come from fakeAdapter.
type ouAdapter struct {
	fakeAdapter
	ouAttrs  []string
	ouFilter string
}

func (a ouAdapter) OUAttrs() []string {
	if a.ouAttrs != nil {
		return a.ouAttrs
	}
	return []string{"ou"}
}

func (a ouAdapter) SearchOUFilterTemplate() string {
	if a.ouFilter != "" {
		return a.ouFilter
	}
	return "(ou=%s)"
}

func newOUOpsLDAPper(conn *mocks.MockLDAPConn, adapter ouAdapter) *LDAPper {
	l := &LDAPper{
		catalogAdapter: adapter,
		searchLimits:   DefaultSearchLimits(),
	}
	// NB: do not assign a typed-nil *MockLDAPConn to interfaces.LDAPConn.
	// It becomes a non-nil interface and bypasses requireConnLocked's
	// nil check, causing a nil-pointer dereference on the first Search.
	if conn != nil {
		l.connection = conn
	}
	return l
}

// ================== GetOU ==================

func TestGetOU_NoConnection(t *testing.T) {
	t.Parallel()

	l := newOUOpsLDAPper(nil, ouAdapter{})
	_, err := l.GetOU(context.Background(), "sales", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestGetOU_EmptyName(t *testing.T) {
	t.Parallel()

	l := newOUOpsLDAPper(&mocks.MockLDAPConn{}, ouAdapter{})
	_, err := l.GetOU(context.Background(), "", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	// lookupKind is "ou" — the error message must say so.
	assert.Contains(t, err.Error(), "ou")
}

func TestGetOU_EmptyBaseDN(t *testing.T) {
	t.Parallel()

	l := newOUOpsLDAPper(&mocks.MockLDAPConn{}, ouAdapter{})
	_, err := l.GetOU(context.Background(), "sales", "")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestGetOU_NotFound(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	l := newOUOpsLDAPper(conn, ouAdapter{})

	_, err := l.GetOU(context.Background(), "ghost", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFoundOrNotVisible)
	assert.Contains(t, err.Error(), "ou",
		"lookupKind must be propagated into the error message")
	assert.Contains(t, err.Error(), "ghost")
}

func TestGetOU_Ambiguous(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("ou=sales,dc=a", nil),
				newLDAPEntry("ou=sales,dc=b", nil),
			}}, nil
		},
	}
	l := newOUOpsLDAPper(conn, ouAdapter{})

	_, err := l.GetOU(context.Background(), "sales", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAmbiguousResult)
}

func TestGetOU_Success(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("ou=sales,dc=x", map[string][]string{
					"ou":          {"sales"},
					"description": {"Sales department"},
				}),
			}}, nil
		},
	}
	adapter := ouAdapter{ouAttrs: []string{"ou", "description"}}
	l := newOUOpsLDAPper(conn, adapter)

	ou, err := l.GetOU(context.Background(), "sales", "dc=x")

	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Equal(t, "ou=sales,dc=x", ou.DN)
	assert.Equal(t, []string{"sales"}, ou.Attributes["ou"])
	assert.Equal(t, []string{"Sales department"}, ou.Attributes["description"])
}

func TestGetOU_UsesAdapterAttrsAndFilter(t *testing.T) {
	t.Parallel()

	var gotAttrs []string
	var gotFilter string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			gotAttrs = req.Attributes
			gotFilter = req.Filter
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("ou=sales,dc=x", nil),
			}}, nil
		},
	}
	adapter := ouAdapter{
		ouAttrs:  []string{"ou", "objectClass", "description", "managedBy"},
		ouFilter: "(&(objectClass=organizationalUnit)(ou=%s))",
	}
	l := newOUOpsLDAPper(conn, adapter)

	_, err := l.GetOU(context.Background(), "sales", "dc=x")
	require.NoError(t, err)

	assert.Equal(t, []string{"ou", "objectClass", "description", "managedBy"}, gotAttrs)
	assert.Equal(t, "(&(objectClass=organizationalUnit)(ou=sales))", gotFilter)
}

func TestGetOU_EscapesFilterValue(t *testing.T) {
	t.Parallel()

	var gotFilter string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			gotFilter = req.Filter
			return &ldap.SearchResult{}, nil
		},
	}
	l := newOUOpsLDAPper(conn, ouAdapter{})

	// Special characters in the OU name must be escaped before substitution.
	_, _ = l.GetOU(context.Background(), "a*b(c)", "dc=x")

	assert.Contains(t, gotFilter, `a\2ab\28c\29`)
}

func TestGetOU_SearchErrorClassified(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newOUOpsLDAPper(conn, ouAdapter{})

	_, err := l.GetOU(context.Background(), "sales", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.Contains(t, err.Error(), "ou search",
		"wrapping prefix must name the operation for diagnostics")
}
