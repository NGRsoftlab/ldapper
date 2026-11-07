// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/mocks"
	"github.com/NGRsoftlab/ldapper/types"
)

// userOpsAdapter extends fakeAdapter with the group/OU filter bits used by
// getUserGroupsLocked and getOUUsersLocked. fakeAdapter covers only the
// auth-path essentials; embedding keeps the shared scaffolding DRY.
type userOpsAdapter struct {
	fakeAdapter
	groupsFilter   string
	groupsArgs     []any
	ouObjectFilter string
}

func (a userOpsAdapter) SearchUserGroupsFilterTemplate() string {
	if a.groupsFilter != "" {
		return a.groupsFilter
	}
	return "(member=%[1]s)"
}

func (a userOpsAdapter) SearchUserGroupsFilterTemplateArgs(_ types.LDAPUser) []any {
	return a.groupsArgs
}

func (a userOpsAdapter) UserObjectFilter() string {
	if a.ouObjectFilter != "" {
		return a.ouObjectFilter
	}
	return "(objectClass=user)"
}

// userOpsAdapterWithResolver is userOpsAdapter PLUS PrimaryGroupResolver.
// The distinct type (rather than a nil-checked field) matters: whether the
// adapter satisfies interfaces.PrimaryGroupResolver is a compile-time
// property, and getUserGroupsLocked relies on a type assertion.
type userOpsAdapterWithResolver struct {
	userOpsAdapter
	resolveFn func(ctx context.Context, user types.LDAPUser, conn interfaces.LDAPConn) (string, error)
}

func (a userOpsAdapterWithResolver) ResolvePrimaryGroupDN(
	ctx context.Context, user types.LDAPUser, conn interfaces.LDAPConn,
) (string, error) {
	return a.resolveFn(ctx, user, conn)
}

// newUserOpsLDAPper builds an LDAPper with a userOpsAdapter and no auth.
func newUserOpsLDAPper(conn *mocks.MockLDAPConn, adapter interfaces.CatalogAdapter) *LDAPper {
	limits := DefaultSearchLimits()
	// These tests exercise grouping/dedup, not paging. Mocks return
	// single-page responses without a paging control; RequirePaging
	// would reject them as partial. Paging behaviour is covered in
	// ldapper_search_test.go.
	limits.RequirePaging = false

	l := &LDAPper{
		catalogAdapter: adapter,
		searchLimits:   limits,
	}
	if conn != nil {
		l.connection = conn
	}
	return l
}

// byFilter returns a SearchFunc that dispatches based on req.Filter. This
// is how the user lookup (via searchSingleEntryLocked) and the groups
// lookup (via searchPaged) are told apart inside a single mock: their
// filters are constructed from different adapter templates and are
// expected to differ in tests. Any unexpected filter panics so a broken
// test fails loudly rather than silently returning empty results.
func byFilter(t *testing.T, matchers map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error)) func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
	t.Helper()
	return func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		for substr, fn := range matchers {
			if contains(req.Filter, substr) {
				return fn(req)
			}
		}
		t.Fatalf("unexpected search filter: %q", req.Filter)
		return nil, nil
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ================== GetUser ==================

func TestGetUser_Success(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=alice,dc=x", map[string][]string{
					"cn":   {"alice"},
					"mail": {"alice@example.com"},
				}),
			}}, nil
		},
	}
	adapter := userOpsAdapter{fakeAdapter: fakeAdapter{userAttrs: []string{"cn", "mail"}}}
	l := newUserOpsLDAPper(conn, adapter)

	user, err := l.GetUser(context.Background(), "alice", "dc=x")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "cn=alice,dc=x", user.DN)
	assert.Equal(t, []string{"alice"}, user.Attributes["cn"])
	assert.Equal(t, []string{"alice@example.com"}, user.Attributes["mail"])
}

func TestGetUser_NotFound(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	_, err := l.GetUser(context.Background(), "ghost", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFoundOrNotVisible)
}

func TestGetUser_EmptyUsername(t *testing.T) {
	t.Parallel()

	l := newUserOpsLDAPper(&mocks.MockLDAPConn{}, userOpsAdapter{})
	_, err := l.GetUser(context.Background(), "", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestGetUser_UsesAdapterUserAttrs(t *testing.T) {
	t.Parallel()

	var gotAttrs []string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			gotAttrs = req.Attributes
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=x,dc=x", nil),
			}}, nil
		},
	}
	adapter := userOpsAdapter{fakeAdapter: fakeAdapter{
		userAttrs: []string{"cn", "mail", "telephoneNumber"},
	}}
	l := newUserOpsLDAPper(conn, adapter)

	_, err := l.GetUser(context.Background(), "alice", "dc=x")
	require.NoError(t, err)
	assert.Equal(t, []string{"cn", "mail", "telephoneNumber"}, gotAttrs)
}

// ================== GetUserGroups ==================

func TestGetUserGroups_UserNotFound(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	_, err := l.GetUserGroups(context.Background(), "ghost", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFoundOrNotVisible)
}

func TestGetUserGroups_EmptyGroupsReturnsNonNilSlice(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", nil),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{}, nil
			},
		}),
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	groups, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.NoError(t, err)
	assert.NotNil(t, groups, "empty result must be a non-nil slice, not nil")
	assert.Empty(t, groups)
}

func TestGetUserGroups_DeduplicatesDNs(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", nil),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				// Two entries with the same DN and one distinct.
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=g1,dc=x", nil),
					newLDAPEntry("cn=g1,dc=x", nil),
					newLDAPEntry("cn=g2,dc=x", nil),
				}}, nil
			},
		}),
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	groups, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"cn=g1,dc=x", "cn=g2,dc=x"}, groups)
}

func TestGetUserGroups_SearchErrorClassified(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", nil),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
			},
		}),
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	_, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestGetUserGroups_NoResolver_SkipsPrimaryGroup(t *testing.T) {
	t.Parallel()

	// Adapter does NOT implement PrimaryGroupResolver: the type assertion
	// in getUserGroupsLocked must silently skip the primary-group step.
	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", nil),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=g1,dc=x", nil),
				}}, nil
			},
		}),
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	groups, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.NoError(t, err)
	assert.Equal(t, []string{"cn=g1,dc=x"}, groups)
}

func TestGetUserGroups_ResolverAppendsPrimaryGroup(t *testing.T) {
	t.Parallel()

	var resolverGotConn interfaces.LDAPConn
	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", map[string][]string{
						"primaryGroupID": {"513"},
					}),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=g1,dc=x", nil),
				}}, nil
			},
		}),
	}
	adapter := userOpsAdapterWithResolver{
		userOpsAdapter: userOpsAdapter{
			// primaryGroupID must be requested by UserAttrs, otherwise
			// attrsToMap filters it out and the resolver sees an empty
			// value even though the LDAP entry carried it.
			fakeAdapter: fakeAdapter{userAttrs: []string{"cn", "primaryGroupID"}},
		},
		resolveFn: func(_ context.Context, user types.LDAPUser, c interfaces.LDAPConn) (string, error) {
			resolverGotConn = c
			assert.Equal(t, "cn=alice,dc=x", user.DN)
			assert.Equal(t, "513", user.GetAttributeValue("primaryGroupID"))
			return "cn=primary,dc=x", nil
		},
	}
	l := newUserOpsLDAPper(conn, adapter)

	groups, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.NoError(t, err)
	assert.Same(t, conn, resolverGotConn,
		"resolver must receive ldapper.connection, not a copy")
	assert.ElementsMatch(t,
		[]string{"cn=g1,dc=x", "cn=primary,dc=x"},
		groups)
}

func TestGetUserGroups_ResolverEmptyDN_NoAppend(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", nil),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=g1,dc=x", nil),
				}}, nil
			},
		}),
	}
	adapter := userOpsAdapterWithResolver{
		userOpsAdapter: userOpsAdapter{},
		resolveFn: func(context.Context, types.LDAPUser, interfaces.LDAPConn) (string, error) {
			return "", nil // no primary group set
		},
	}
	l := newUserOpsLDAPper(conn, adapter)

	groups, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.NoError(t, err)
	assert.Equal(t, []string{"cn=g1,dc=x"}, groups,
		"empty resolver result must not add an empty string")
}

func TestGetUserGroups_ResolverPrimaryGroupAlreadyPresent_NoDuplicate(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", nil),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				// The primary group is already in the group list.
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=g1,dc=x", nil),
					newLDAPEntry("cn=primary,dc=x", nil),
				}}, nil
			},
		}),
	}
	adapter := userOpsAdapterWithResolver{
		userOpsAdapter: userOpsAdapter{},
		resolveFn: func(context.Context, types.LDAPUser, interfaces.LDAPConn) (string, error) {
			return "cn=primary,dc=x", nil
		},
	}
	l := newUserOpsLDAPper(conn, adapter)

	groups, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"cn=g1,dc=x", "cn=primary,dc=x"}, groups)
	assert.Len(t, groups, 2, "primary group must not be appended twice")
}

func TestGetUserGroups_ResolverError_Propagated(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("domainDNS not found")
	conn := &mocks.MockLDAPConn{
		SearchFunc: byFilter(t, map[string]func(*ldap.SearchRequest) (*ldap.SearchResult, error){
			"(uid=alice)": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=alice,dc=x", nil),
				}}, nil
			},
			"(member=": func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{}, nil
			},
		}),
	}
	adapter := userOpsAdapterWithResolver{
		userOpsAdapter: userOpsAdapter{},
		resolveFn: func(context.Context, types.LDAPUser, interfaces.LDAPConn) (string, error) {
			return "", wantErr
		},
	}
	l := newUserOpsLDAPper(conn, adapter)

	_, err := l.GetUserGroups(context.Background(), "alice", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.Contains(t, err.Error(), "resolve primary group")
}

// ================== GetOUUsers ==================

func TestGetOUUsers_NoConnection(t *testing.T) {
	t.Parallel()

	l := newUserOpsLDAPper(nil, userOpsAdapter{})
	_, err := l.GetOUUsers(context.Background(), "ou=sales,dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestGetOUUsers_EmptyOUDN(t *testing.T) {
	t.Parallel()

	l := newUserOpsLDAPper(&mocks.MockLDAPConn{}, userOpsAdapter{})
	_, err := l.GetOUUsers(context.Background(), "")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestGetOUUsers_Success(t *testing.T) {
	t.Parallel()

	var gotFilter string
	var gotAttrs []string
	var gotBaseDN string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			gotFilter = req.Filter
			gotAttrs = req.Attributes
			gotBaseDN = req.BaseDN
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=u1,ou=sales,dc=x", map[string][]string{"cn": {"u1"}}),
				newLDAPEntry("cn=u2,ou=sales,dc=x", map[string][]string{"cn": {"u2"}}),
			}}, nil
		},
	}
	adapter := userOpsAdapter{
		fakeAdapter:    fakeAdapter{userAttrs: []string{"cn", "mail"}},
		ouObjectFilter: "(&(objectClass=user)(objectCategory=person))",
	}
	l := newUserOpsLDAPper(conn, adapter)

	users, err := l.GetOUUsers(context.Background(), "ou=sales,dc=x")

	require.NoError(t, err)
	require.Len(t, users, 2)
	assert.Equal(t, "cn=u1,ou=sales,dc=x", users[0].DN)
	assert.Equal(t, "cn=u2,ou=sales,dc=x", users[1].DN)
	assert.Equal(t, "(&(objectClass=user)(objectCategory=person))", gotFilter)
	assert.Equal(t, []string{"cn", "mail"}, gotAttrs)
	assert.Equal(t, "ou=sales,dc=x", gotBaseDN)
}

func TestGetOUUsers_EmptyResultIsNonNil(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	users, err := l.GetOUUsers(context.Background(), "ou=empty,dc=x")

	require.NoError(t, err)
	assert.NotNil(t, users, "empty result must be non-nil for consistency with code")
	assert.Empty(t, users)
}

func TestGetOUUsers_SearchErrorClassified(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newUserOpsLDAPper(conn, userOpsAdapter{})

	_, err := l.GetOUUsers(context.Background(), "ou=sales,dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
}
