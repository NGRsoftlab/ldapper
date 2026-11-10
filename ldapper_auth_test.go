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
	"github.com/NGRsoftlab/ldapper/types"
)

// fakeAdapter is a minimal CatalogAdapter for auth tests. Only the methods
// used by bindConnLocked / getUserLocked are meaningfully
// implemented; the rest return harmless zero values.
type fakeAdapter struct {
	bindIdentityFn func(login, baseDN string) (string, error)
	userAttrs      []string
	userFilterTmpl string
}

func (a fakeAdapter) BindIdentity(login, baseDN string) (string, error) {
	if a.bindIdentityFn != nil {
		return a.bindIdentityFn(login, baseDN)
	}
	return "uid=" + login + "," + baseDN, nil
}

func (a fakeAdapter) SearchUserFilterTemplate() string {
	if a.userFilterTmpl != "" {
		return a.userFilterTmpl
	}
	return "(uid=%s)"
}

func (a fakeAdapter) UserAttrs() []string {
	if a.userAttrs != nil {
		return a.userAttrs
	}
	return []string{"cn"}
}

func (a fakeAdapter) GetNormalizedUserInfo(types.LDAPUser) *types.UserNormalizedInfo {
	return nil
}
func (a fakeAdapter) GetNormalizedOUInfoFromEntry(ldap.Entry) *types.OUNormalizedInfo {
	return nil
}
func (a fakeAdapter) UserObjectFilter() string                                { return "" }
func (a fakeAdapter) GroupObjectFilter() string                               { return "" }
func (a fakeAdapter) OUObjectFilter() string                                  { return "" }
func (a fakeAdapter) SearchUserGroupsFilterTemplate() string                  { return "" }
func (a fakeAdapter) SearchUserGroupsFilterTemplateArgs(types.LDAPUser) []any { return nil }
func (a fakeAdapter) SearchOUFilterTemplate() string                          { return "" }
func (a fakeAdapter) SearchGroupFilterTemplate() string                       { return "" }
func (a fakeAdapter) OUAttrs() []string                                       { return nil }
func (a fakeAdapter) GroupAttrs() []string                                    { return nil }

// newAuthTestLDAPper builds an LDAPper wired for auth tests. Auth state is
// NOT set here — tests that need it call markAuthenticated themselves.
func newAuthTestLDAPper(conn *mocks.MockLDAPConn) *LDAPper {
	l := &LDAPper{
		catalogAdapter: fakeAdapter{},
		searchLimits:   DefaultSearchLimits(),
	}
	if conn != nil {
		l.connection = conn
	}
	return l
}

// markAuthenticated sets the cached service-bind state used by
// requireAuthLocked and CheckUserCredentials.
func markAuthenticated(l *LDAPper, user, password, dn string) {
	l.isAuthenticated = true
	l.bindUser = user
	l.bindPassword = password
	l.bindDN = dn
}

// ================== invalidateAuthLocked ==================

func TestInvalidateAuthLocked_ClearsCredentialsPreservesDN(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	markAuthenticated(l, "u", "p", "dc=example")

	l.invalidateAuthLocked()

	assert.False(t, l.isAuthenticated)
	assert.Empty(t, l.bindUser)
	assert.Empty(t, l.bindPassword)
	assert.Equal(t, "dc=example", l.bindDN,
		"bindDN is caller-supplied scope, not a credential; must survive invalidation")
}

// ================== restoreServiceBindLocked ==================

func TestRestoreServiceBindLocked_Success(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		BindFunc: func(u, p string) error {
			assert.Equal(t, "svc", u)
			assert.Equal(t, "svc-pass", p)
			return nil
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	err := l.restoreServiceBindLocked(context.Background())
	require.NoError(t, err)
	assert.Same(t, conn, l.connection, "connection must survive successful rebind")
	assert.True(t, l.isAuthenticated)
}

func TestRestoreServiceBindLocked_FailureInvalidatesState(t *testing.T) {
	t.Parallel()

	closed := false
	conn := &mocks.MockLDAPConn{
		BindFunc: func(string, string) error {
			return ldap.NewError(ldap.LDAPResultInvalidCredentials,
				errors.New("password=svc-pass"))
		},
		CloseFunc: func() error { closed = true; return nil },
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	err := l.restoreServiceBindLocked(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.NotContains(t, err.Error(), "svc-pass",
		"service password must never leak into the returned error")
	assert.True(t, closed, "failed rebind must close the connection")
	assert.Nil(t, l.connection)
	assert.False(t, l.isAuthenticated)
	assert.Empty(t, l.bindUser)
	assert.Empty(t, l.bindPassword)
	assert.Equal(t, "dc=x", l.bindDN)
}

func TestRestoreServiceBindLocked_ConnectionAlreadyNil(t *testing.T) {
	t.Parallel()

	l := newAuthTestLDAPper(nil)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	// withCtx returns ErrClosed for a nil connection; restoreServiceBindLocked
	// surfaces that as ErrNotAuthenticated (a caller-fixable state).
	err := l.restoreServiceBindLocked(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotAuthenticated)
	assert.False(t, l.isAuthenticated)
}

// ================== BindConn ==================

func TestBindConn_NoConnection(t *testing.T) {
	t.Parallel()

	l := newAuthTestLDAPper(nil)
	err := l.BindConn(context.Background(), "alice", "pass", "dc=x")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestBindConn_EmptyCredentials(t *testing.T) {
	t.Parallel()

	l := newAuthTestLDAPper(&mocks.MockLDAPConn{})
	err := l.BindConn(context.Background(), "", "pass", "dc=x")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)

	err = l.BindConn(context.Background(), "alice", "", "dc=x")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestBindConn_EmptyBaseDN(t *testing.T) {
	t.Parallel()

	l := newAuthTestLDAPper(&mocks.MockLDAPConn{})
	err := l.BindConn(context.Background(), "alice", "pass", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestBindConn_BindIdentityError(t *testing.T) {
	t.Parallel()

	l := newAuthTestLDAPper(&mocks.MockLDAPConn{})
	l.catalogAdapter = fakeAdapter{
		bindIdentityFn: func(string, string) (string, error) {
			return "", errors.New("cannot map login")
		},
	}

	err := l.BindConn(context.Background(), "alice", "pass", "dc=x")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "cannot map login")
}

func TestBindConn_BindFailure_MasksAndCloses(t *testing.T) {
	t.Parallel()

	closed := false
	conn := &mocks.MockLDAPConn{
		BindFunc: func(string, string) error {
			return ldap.NewError(ldap.LDAPResultInvalidCredentials,
				errors.New("password=secret"))
		},
		CloseFunc: func() error { closed = true; return nil },
	}
	l := newAuthTestLDAPper(conn)

	err := l.BindConn(context.Background(), "alice", "secret", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.NotContains(t, err.Error(), "secret",
		"submitted credentials must not echo back through the error")
	assert.True(t, closed)
	assert.Nil(t, l.connection)
	assert.False(t, l.isAuthenticated)
	assert.Empty(t, l.bindUser)
	assert.Empty(t, l.bindPassword)
}

func TestBindConn_BaseDNProbeFailure_ClosesAndInvalidates(t *testing.T) {
	t.Parallel()

	closed := false
	conn := &mocks.MockLDAPConn{
		BindFunc: func(string, string) error { return nil },
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable,
				errors.New("server down"))
		},
		CloseFunc: func() error { closed = true; return nil },
	}
	l := newAuthTestLDAPper(conn)

	err := l.BindConn(context.Background(), "alice", "pass", "dc=x")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.True(t, closed)
	assert.Nil(t, l.connection)
	assert.False(t, l.isAuthenticated)
}

func TestBindConn_BaseDNNotFound_ClosesAndInvalidates(t *testing.T) {
	t.Parallel()

	closed := false
	conn := &mocks.MockLDAPConn{
		BindFunc: func(string, string) error { return nil },
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil // base does not exist / hidden
		},
		CloseFunc: func() error { closed = true; return nil },
	}
	l := newAuthTestLDAPper(conn)

	err := l.BindConn(context.Background(), "alice", "pass", "dc=ghost")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFoundOrNotVisible)
	assert.True(t, closed)
	assert.Nil(t, l.connection)
	assert.False(t, l.isAuthenticated)
}

func TestBindConn_CachesBindPrincipalFromBindIdentity(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		BindFunc: func(u, p string) error {
			// Bind MUST use the value returned by BindIdentity, not the login.
			assert.Equal(t, "uid=alice,ou=people,dc=x", u)
			assert.Equal(t, "alice-pass", p)
			return nil
		},
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			assert.Equal(t, "dc=x", req.BaseDN)
			assert.Equal(t, ldap.ScopeBaseObject, req.Scope)
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("dc=x", nil),
			}}, nil
		},
	}
	l := newAuthTestLDAPper(conn)
	l.catalogAdapter = fakeAdapter{
		bindIdentityFn: func(login, baseDN string) (string, error) {
			return "uid=" + login + ",ou=people," + baseDN, nil
		},
	}

	err := l.BindConn(context.Background(), "alice", "alice-pass", "dc=x")

	require.NoError(t, err)
	assert.True(t, l.isAuthenticated)
	assert.Equal(t, "uid=alice,ou=people,dc=x", l.bindUser)
	assert.Equal(t, "alice-pass", l.bindPassword)
	assert.Equal(t, "dc=x", l.bindDN)
}

// ================== CheckUserCredentials ==================

func TestCheckUserCredentials_RequiresAuth(t *testing.T) {
	t.Parallel()

	t.Run("no connection", func(t *testing.T) {
		t.Parallel()
		l := newAuthTestLDAPper(nil)
		_, err := l.CheckUserCredentials(context.Background(), "alice", "pass")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClosed)
	})

	t.Run("connection but not authenticated", func(t *testing.T) {
		t.Parallel()
		l := newAuthTestLDAPper(&mocks.MockLDAPConn{})
		_, err := l.CheckUserCredentials(context.Background(), "alice", "pass")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotAuthenticated)
	})

	t.Run("closed client", func(t *testing.T) {
		t.Parallel()
		l := newAuthTestLDAPper(&mocks.MockLDAPConn{})
		l.closed = true
		markAuthenticated(l, "svc", "svc-pass", "dc=x")

		_, err := l.CheckUserCredentials(context.Background(), "alice", "pass")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrClosed)
	})
}

func TestCheckUserCredentials_EmptyCredentials(t *testing.T) {
	t.Parallel()

	l := newAuthTestLDAPper(&mocks.MockLDAPConn{})
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	_, err := l.CheckUserCredentials(context.Background(), "", "pass")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)

	_, err = l.CheckUserCredentials(context.Background(), "alice", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestCheckUserCredentials_UserNotFound_MaskedAsInvalidCredentials(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			// Zero entries — the object may be absent or ACL-hidden.
			return &ldap.SearchResult{}, nil
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	_, err := l.CheckUserCredentials(context.Background(), "ghost", "pass")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials,
		"ErrNotFoundOrNotVisible must be masked: user existence must not leak")
	assert.NotErrorIs(t, err, ErrNotFoundOrNotVisible)
}

func TestCheckUserCredentials_LookupErrorOtherThanNotFound_Propagates(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	_, err := l.CheckUserCredentials(context.Background(), "alice", "pass")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.NotErrorIs(t, err, ErrInvalidCredentials,
		"infrastructure errors must NOT be masked as credential rejection")
}

func TestCheckUserCredentials_UserBindFails_RestoreSucceeds(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=alice,dc=x", nil),
			}}, nil
		},
		BindFunc: func(u, p string) error {
			if u == "svc" && p == "svc-pass" {
				return nil // service rebind ok
			}
			return ldap.NewError(ldap.LDAPResultInvalidCredentials,
				errors.New("wrong password"))
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	_, err := l.CheckUserCredentials(context.Background(), "alice", "wrong-pass")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.True(t, l.isAuthenticated,
		"service session restored; state must remain authenticated")
	assert.Same(t, conn, l.connection)
}

func TestCheckUserCredentials_RestoreFails_BindOk(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=alice,dc=x", nil),
			}}, nil
		},
		BindFunc: func(u, p string) error {
			if u == "cn=alice,dc=x" {
				return nil // user bind ok
			}
			return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	_, err := l.CheckUserCredentials(context.Background(), "alice", "alice-pass")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotAuthenticated)
	assert.Contains(t, err.Error(), "failed to restore service bind")
	assert.False(t, l.isAuthenticated, "restore failure must invalidate auth state")
}

func TestCheckUserCredentials_BothFail_ReportsCredentialFailure(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=alice,dc=x", nil),
			}}, nil
		},
		BindFunc: func(u, p string) error {
			// Both binds fail with different codes.
			if u == "cn=alice,dc=x" {
				return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("bad"))
			}
			return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	_, err := l.CheckUserCredentials(context.Background(), "alice", "wrong")

	require.Error(t, err)
	// The credential failure is primary; the restore failure is secondary.
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.NotErrorIs(t, err, ErrUnavailable,
		"secondary failure must not become the primary sentinel")
	assert.Contains(t, err.Error(), "additionally")
}

func TestCheckUserCredentials_UserBindContextCancelled_NotMasked(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=alice,dc=x", nil),
			}}, nil
		},
		BindFunc: func(string, string) error {
			cancel() // trigger the withCtx watchdog
			return errors.New("bind aborted by cancellation")
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	_, err := l.CheckUserCredentials(ctx, "alice", "alice-pass")

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled,
		"cancellation must not be masked as a credential rejection")
	assert.NotErrorIs(t, err, ErrInvalidCredentials)
}

func TestCheckUserCredentials_Success(t *testing.T) {
	t.Parallel()

	var binds []string
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=alice,dc=x", map[string][]string{"cn": {"alice"}}),
			}}, nil
		},
		BindFunc: func(u, p string) error {
			binds = append(binds, u)
			return nil
		},
	}
	l := newAuthTestLDAPper(conn)
	markAuthenticated(l, "svc", "svc-pass", "dc=x")

	user, err := l.CheckUserCredentials(context.Background(), "alice", "alice-pass")

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "cn=alice,dc=x", user.DN)
	assert.Equal(t, []string{"cn=alice,dc=x", "svc"}, binds,
		"user bind first, then service rebind")
	assert.True(t, l.isAuthenticated)
}
