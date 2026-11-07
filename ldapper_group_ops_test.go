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

// groupAdapter extends fakeAdapter with the group-specific bits used by
// getGroupLocked. Only the methods actually exercised are meaningful; the
// rest return harmless zero values via fakeAdapter.
type groupAdapter struct {
	fakeAdapter
	groupAttrs  []string
	groupFilter string
}

func (a groupAdapter) GroupAttrs() []string {
	if a.groupAttrs != nil {
		return a.groupAttrs
	}
	return []string{"cn"}
}

func (a groupAdapter) SearchGroupFilterTemplate() string {
	if a.groupFilter != "" {
		return a.groupFilter
	}
	return "(cn=%s)"
}

func newGroupOpsLDAPper(conn *mocks.MockLDAPConn, adapter groupAdapter) *LDAPper {
	l := &LDAPper{
		catalogAdapter: adapter,
		searchLimits:   DefaultSearchLimits(),
	}
	if conn != nil {
		l.connection = conn
	}
	return l
}

// ================== GetGroup ==================

func TestGetGroup_NoConnection(t *testing.T) {
	t.Parallel()

	l := newGroupOpsLDAPper(nil, groupAdapter{})
	_, err := l.GetGroup(context.Background(), "admins", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestGetGroup_EmptyCN(t *testing.T) {
	t.Parallel()

	l := newGroupOpsLDAPper(&mocks.MockLDAPConn{}, groupAdapter{})
	_, err := l.GetGroup(context.Background(), "", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	// lookupKind is "group" — the error message must say so, not "user".
	assert.Contains(t, err.Error(), "group")
}

func TestGetGroup_EmptyBaseDN(t *testing.T) {
	t.Parallel()

	l := newGroupOpsLDAPper(&mocks.MockLDAPConn{}, groupAdapter{})
	_, err := l.GetGroup(context.Background(), "admins", "")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestGetGroup_NotFound(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	l := newGroupOpsLDAPper(conn, groupAdapter{})

	_, err := l.GetGroup(context.Background(), "ghost", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFoundOrNotVisible)
	assert.Contains(t, err.Error(), "group",
		"lookupKind must be propagated into the error message")
	assert.Contains(t, err.Error(), "ghost")
}

func TestGetGroup_Ambiguous(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=a,dc=x", nil),
				newLDAPEntry("cn=b,dc=x", nil),
			}}, nil
		},
	}
	l := newGroupOpsLDAPper(conn, groupAdapter{})

	_, err := l.GetGroup(context.Background(), "dup", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAmbiguousResult)
}

func TestGetGroup_Success(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=admins,dc=x", map[string][]string{
					"cn":     {"admins"},
					"member": {"cn=alice,dc=x", "cn=bob,dc=x"},
				}),
			}}, nil
		},
	}
	adapter := groupAdapter{groupAttrs: []string{"cn", "member"}}
	l := newGroupOpsLDAPper(conn, adapter)

	group, err := l.GetGroup(context.Background(), "admins", "dc=x")

	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "cn=admins,dc=x", group.DN)
	assert.Equal(t, []string{"admins"}, group.Attributes["cn"])
	assert.Equal(t, []string{"cn=alice,dc=x", "cn=bob,dc=x"}, group.Attributes["member"])
}

func TestGetGroup_UsesAdapterAttrsAndFilter(t *testing.T) {
	t.Parallel()

	var gotAttrs []string
	var gotFilter string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			gotAttrs = req.Attributes
			gotFilter = req.Filter
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=admins,dc=x", nil),
			}}, nil
		},
	}
	adapter := groupAdapter{
		groupAttrs:  []string{"cn", "member", "memberOf", "objectGUID"},
		groupFilter: "(&(objectCategory=group)(cn=%s))",
	}
	l := newGroupOpsLDAPper(conn, adapter)

	_, err := l.GetGroup(context.Background(), "admins", "dc=x")
	require.NoError(t, err)

	assert.Equal(t, []string{"cn", "member", "memberOf", "objectGUID"}, gotAttrs)
	assert.Equal(t, "(&(objectCategory=group)(cn=admins))", gotFilter)
}

func TestGetGroup_EscapesFilterValue(t *testing.T) {
	t.Parallel()

	var gotFilter string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			gotFilter = req.Filter
			return &ldap.SearchResult{}, nil
		},
	}
	l := newGroupOpsLDAPper(conn, groupAdapter{})

	// Special characters in the CN must be escaped before substitution.
	_, _ = l.GetGroup(context.Background(), "a*b(c)", "dc=x")

	assert.Contains(t, gotFilter, `a\2ab\28c\29`)
}

func TestGetGroup_SearchErrorClassified(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newGroupOpsLDAPper(conn, groupAdapter{})

	_, err := l.GetGroup(context.Background(), "admins", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.Contains(t, err.Error(), "group search",
		"wrapping prefix must name the operation for diagnostics")
}
