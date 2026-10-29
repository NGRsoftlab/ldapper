// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// ---------- NewConnection ----------

func TestNewConnection_NilTLSConfig(t *testing.T) {
	cases := []struct {
		name    string
		useSSL  bool
		skipTLS bool
	}{
		{"no ssl, no skip tls", false, false},
		{"ssl", true, false},
		{"ssl and skip tls", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := NewConnection("localhost", 389, tc.useSSL, tc.skipTLS, nil, new(MockCatalogAdapter))
			assert.Nil(t, conn)
			assert.EqualError(t, err, "nil tls config passed")
		})
	}
}

func TestNewConnection_NilCatalogAdapter(t *testing.T) {
	conn, err := NewConnection("localhost", 389, false, true, &tls.Config{}, nil)
	assert.Nil(t, conn)
	assert.EqualError(t, err, "nil catalog adapter passed")
}

func TestNewConnection_DialError(t *testing.T) {
	// Port 1 is expected to be closed — DialURL must fail with a dial error.
	conn, err := NewConnection("127.0.0.1", 1, false, true, nil, new(MockCatalogAdapter))
	assert.Nil(t, conn)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsuccessful dial")
}

func TestNewConnection_UsesLDAPURITemplate(t *testing.T) {
	// The ldap:// URI is built from the constants in constants.go.
	// A closed port produces a dial error whose message contains the URI.
	conn, err := NewConnection("example.invalid", 389, false, true, nil, new(MockCatalogAdapter))
	assert.Nil(t, conn)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsuccessful dial",
		"ldapURITemplate must be used to build the dial URL")
}

func TestNewConnection_UsesLDAPSURITemplate(t *testing.T) {
	// The ldaps:// URI is built from the constants in constants.go.
	conn, err := NewConnection("example.invalid", 636, true, false, &tls.Config{}, new(MockCatalogAdapter))
	assert.Nil(t, conn)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsuccessful dial",
		"ldapsURITemplate must be used to build the dial URL")
}

// ---------- NewAuthenticatedConnection ----------

func TestNewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "pass"},
		{"empty password", "user", ""},
		{"both empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, user, err := NewAuthenticatedConnection(
				tc.username, tc.password, "dc=example,dc=com",
				"localhost", 389, false, true, &tls.Config{}, new(MockCatalogAdapter),
			)
			assert.Nil(t, conn)
			assert.Nil(t, user)
			assert.EqualError(t, err, "empty username/password passed")
		})
	}
}

func TestNewAuthenticatedConnection_NewConnectionError(t *testing.T) {
	conn, user, err := NewAuthenticatedConnection(
		"user", "pass", "dc=example,dc=com",
		"localhost", 636, true, false, nil, new(MockCatalogAdapter),
	)
	assert.Nil(t, conn)
	assert.Nil(t, user)
	assert.EqualError(t, err, "nil tls config passed")
}

// ---------- AuthenticateConn ----------

func TestAuthenticateConn_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", map[string][]string{"cn": {"John Doe"}}),
	}}, nil).Once()
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "secret").Return(nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "uid=jdoe,dc=example,dc=com", user.DN)
	// Authentication state must be recorded for later rebinds.
	assert.True(t, conn.isAuthenticated)
	assert.Equal(t, "uid=jdoe,dc=example,dc=com", conn.bindUser)
	assert.Equal(t, "secret", conn.bindPassword)
}

func TestAuthenticateConn_NilConnection(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	conn := &LDAPConnection{catalogAdapter: adapter}

	user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
	adapter.AssertNotCalled(t, "SearchUserFilterTemplate")
}

func TestAuthenticateConn_GetUserError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.AuthenticateConn("nobody", "secret", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "user does not exist")
	connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
	assert.False(t, conn.isAuthenticated)
}

func TestAuthenticateConn_BindError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "wrong").
		Return(errors.New("invalid credentials")).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.AuthenticateConn("jdoe", "wrong", "dc=example,dc=com")

	assert.NotNil(t, user, "user is returned even on bind failure")
	assert.EqualError(t, err, "unsuccessful bind with passed bind credentials")
	assert.NotContains(t, err.Error(), "invalid credentials",
		"the original bind error must not leak into the returned error")
	// Auth state must NOT be updated on failure.
	assert.False(t, conn.isAuthenticated)
	assert.Empty(t, conn.bindUser)
	assert.Empty(t, conn.bindPassword)
}

// ---------- AuthenticatedUser ----------

func TestAuthenticatedUser_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	// 1st bind: verify the end user's credentials.
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "user-pass").Return(nil).Once()
	// 2nd bind: rebind back onto the read-access service account.
	connMock.On("Bind", "cn=svc,dc=example,dc=com", "svc-pass").Return(nil).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "cn=svc,dc=example,dc=com",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticatedUser("jdoe", "user-pass", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "uid=jdoe,dc=example,dc=com", user.DN)
	connMock.AssertNumberOfCalls(t, "Bind", 2)
}

func TestAuthenticatedUser_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(MockCatalogAdapter)}
	user, err := conn.AuthenticatedUser("jdoe", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
}

func TestAuthenticatedUser_NotAuthenticated(t *testing.T) {
	connMock := new(MockLDAPConn)
	conn := &LDAPConnection{
		catalogAdapter:  new(MockCatalogAdapter),
		connection:      connMock,
		isAuthenticated: false,
	}

	user, err := conn.AuthenticatedUser("jdoe", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not authenticated")
	connMock.AssertNotCalled(t, "Search", mock.Anything)
	connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
}

func TestAuthenticatedUser_GetUserError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "cn=svc,dc=example,dc=com",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticatedUser("nobody", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "user does not exist")
	connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
}

func TestAuthenticatedUser_UserBindError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "wrong").
		Return(errors.New("invalid credentials")).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "cn=svc,dc=example,dc=com",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticatedUser("jdoe", "wrong", "dc=example,dc=com")

	assert.NotNil(t, user)
	assert.EqualError(t, err, "unsuccessful bind with passed user credentials")
	// Only one bind attempted — the rebind must not happen.
	connMock.AssertNumberOfCalls(t, "Bind", 1)
}

func TestAuthenticatedUser_RebindError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "user-pass").Return(nil).Once()
	connMock.On("Bind", "cn=svc,dc=example,dc=com", "svc-pass").
		Return(errors.New("service account locked")).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "cn=svc,dc=example,dc=com",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticatedUser("jdoe", "user-pass", "dc=example,dc=com")

	assert.NotNil(t, user)
	assert.EqualError(t, err, "unsuccessful rebind with bind-config credentials")
	connMock.AssertNumberOfCalls(t, "Bind", 2)
}

// ---------- Close ----------

func TestClose_Success(t *testing.T) {
	connMock := new(MockLDAPConn)
	connMock.On("Close").Return(nil).Once()

	conn := &LDAPConnection{connection: connMock}
	conn.Close()

	assert.Nil(t, conn.connection, "connection must be nil after a successful Close")
	connMock.AssertExpectations(t)
}

func TestClose_NilConnection(t *testing.T) {
	conn := &LDAPConnection{}
	assert.NotPanics(t, func() { conn.Close() })
}

func TestClose_ErrorStillNilsConnection(t *testing.T) {
	// Current implementation nils out conn.connection BEFORE checking the error,
	// so even a failed Close leaves conn.connection == nil.
	connMock := new(MockLDAPConn)
	connMock.On("Close").Return(errors.New("close failed")).Once()

	conn := &LDAPConnection{connection: connMock}
	conn.Close()

	assert.Nil(t, conn.connection,
		"current behavior: connection is nil-ed out regardless of the Close error")
	connMock.AssertExpectations(t)
}

// ---------- CustomSearch ----------

func TestCustomSearch_Success(t *testing.T) {
	request := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"dn"}, nil,
	)
	expected := &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "dc=example,dc=com"}}}

	connMock := new(MockLDAPConn)
	connMock.On("Search", request).Return(expected, nil).Once()

	conn := &LDAPConnection{connection: connMock}
	result, err := conn.CustomSearch(request)

	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	connMock.AssertExpectations(t)
}

func TestCustomSearch_NilConnection(t *testing.T) {
	conn := &LDAPConnection{}
	result, err := conn.CustomSearch(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil,
	))

	assert.Nil(t, result)
	assert.EqualError(t, err, "connection not initialized")
}

func TestCustomSearch_ReturnsRawError(t *testing.T) {
	originalErr := errors.New("raw ldap error")
	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(nil, originalErr).Once()

	conn := &LDAPConnection{connection: connMock}
	_, err := conn.CustomSearch(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil,
	))

	assert.ErrorIs(t, err, originalErr, "CustomSearch must not wrap the error")
	connMock.AssertExpectations(t)
}

// ---------- GetUser ----------

func TestGetUser_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", map[string][]string{
			"cn":   {"John Doe"},
			"mail": {"jdoe@example.com"},
		}),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("jdoe", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "uid=jdoe,dc=example,dc=com", user.DN)
	assert.Equal(t, []string{"John Doe"}, user.Attributes["cn"])
	assert.Equal(t, []string{"jdoe@example.com"}, user.Attributes["mail"])
}

func TestGetUser_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(MockCatalogAdapter)}
	user, err := conn.GetUser("jdoe", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
}

func TestGetUser_NoUser(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("nobody", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "user does not exist")
}

func TestGetUser_TooManyEntries(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=u1,dc=example,dc=com", nil),
		newLDAPEntry("uid=u2,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("dup", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "too many entries returned")
}

func TestGetUser_SearchError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(nil, errors.New("search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("jdoe", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "unsuccessful user search: search failed")
}

func TestGetUser_VerifiesSearchRequest(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == "(uid=jdoe)" &&
			req.Scope == ldap.ScopeWholeSubtree &&
			req.TimeLimit == defaultSearchTimeLimit &&
			len(req.Attributes) == 2
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetUser("jdoe", "dc=example,dc=com")
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}

// ---------- GetUserGroups ----------

func TestGetUserGroups_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("cn=admins,dc=example,dc=com", map[string][]string{"cn": {"admins"}}),
		newLDAPEntry("cn=users,dc=example,dc=com", map[string][]string{"cn": {"users"}}),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"admins", "users"}, groups)
	connMock.AssertNumberOfCalls(t, "Search", 2)
}

func TestGetUserGroups_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(MockCatalogAdapter)}
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.Nil(t, groups)
	assert.EqualError(t, err, "connection not initialized")
}

func TestGetUserGroups_EmptyGroups(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, groups)
	assert.Empty(t, groups)
}

func TestGetUserGroups_GetUserError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("nobody", "dc=example,dc=com")

	assert.Nil(t, groups)
	assert.EqualError(t, err, "user does not exist")
	connMock.AssertNumberOfCalls(t, "Search", 1)
	adapter.AssertNotCalled(t, "SearchUserGroupsFilterTemplate")
}

func TestGetUserGroups_SearchGroupsError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("groups lookup failed")).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.Nil(t, groups)
	assert.EqualError(t, err, "unsuccessful user groups search: groups lookup failed")
}

func TestGetUserGroups_VerifiesGroupFilterRequest(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == "(&(objectClass=group)(member=uid=jdoe,dc=example,dc=com))" &&
			req.Scope == ldap.ScopeWholeSubtree &&
			req.TimeLimit == defaultSearchTimeLimit &&
			len(req.Attributes) == 1 && req.Attributes[0] == "cn"
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}

// ---------- GetOUUsers ----------

func TestGetOUUsers_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("cn=u1,ou=people,dc=example,dc=com", map[string][]string{
			"cn":   {"User One"},
			"mail": {"u1@example.com"},
		}),
		newLDAPEntry("cn=u2,ou=people,dc=example,dc=com", map[string][]string{
			"cn":   {"User Two"},
			"mail": {"u2@example.com"},
		}),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	users, err := conn.GetOUUsers("ou=people,dc=example,dc=com")

	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "cn=u1,ou=people,dc=example,dc=com", users[0].DN)
	assert.Equal(t, "cn=u2,ou=people,dc=example,dc=com", users[1].DN)
}

func TestGetOUUsers_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(MockCatalogAdapter)}
	users, err := conn.GetOUUsers("ou=people,dc=example,dc=com")

	assert.Nil(t, users)
	assert.EqualError(t, err, "connection not initialized")
}

func TestGetOUUsers_EmptyOU(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	users, err := conn.GetOUUsers("ou=empty,dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, users)
	assert.Empty(t, users)
}

func TestGetOUUsers_SearchError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("ou search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	users, err := conn.GetOUUsers("ou=people,dc=example,dc=com")

	assert.Nil(t, users)
	assert.EqualError(t, err, "unsuccessful ou users search: ou search failed")
}

func TestGetOUUsers_VerifiesSearchRequest(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=people,dc=example,dc=com" &&
			req.Filter == "(objectClass=user)" &&
			req.Scope == ldap.ScopeWholeSubtree &&
			req.TimeLimit == defaultSearchTimeLimit &&
			len(req.Attributes) == 2
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetOUUsers("ou=people,dc=example,dc=com")
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}

// ---------- GetCatalogTree ----------

func TestGetCatalogTree_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	// OUInfoFromEntry is called once per entry: first for the root OU,
	// then for the sub OU returned by GetSubOUs.
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=root,dc=example,dc=com", Name: "root", Children: make([]*OUInfo, 0),
	}).Once()
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=sub,ou=root,dc=example,dc=com", Name: "sub", Children: make([]*OUInfo, 0),
	}).Once()

	connMock := new(MockLDAPConn)
	// 1st Search: GetRootOUs — single level under baseDn.
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" && req.Scope == ldap.ScopeSingleLevel
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root,dc=example,dc=com", nil),
	}}, nil).Once()
	// 2nd Search: GetSubOUs for "ou=root".
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com" && req.Scope == ldap.ScopeSingleLevel
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=sub,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()
	// Further recursion for "ou=sub" depends on defaultSearchDepth (=5).
	// level starts at 2, then 3, 4, 5 — recursion continues while level < 5.
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=sub,ou=root,dc=example,dc=com" && req.Scope == ldap.ScopeSingleLevel
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Maybe()

	conn := newTestConnection(adapter, connMock)
	tree, err := conn.GetCatalogTree("dc=example,dc=com")

	assert.NoError(t, err)
	assert.Len(t, tree.Tree, 1)
	assert.Equal(t, "ou=root,dc=example,dc=com", tree.Tree[0].DN)
}

func TestGetCatalogTree_RootSearchError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("root search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	tree, err := conn.GetCatalogTree("dc=example,dc=com")

	assert.ErrorContains(t, err, "unsuccessful ou search")
	assert.NotNil(t, tree.Tree)
	assert.Empty(t, tree.Tree)
}

func TestGetCatalogTree_EmptyRoot(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	tree, err := conn.GetCatalogTree("dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, tree.Tree)
	assert.Empty(t, tree.Tree)
}

// ---------- GetRootOUs ----------

func TestGetRootOUs_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=root,dc=example,dc=com", Name: "root", Children: make([]*OUInfo, 0),
	}).Once()

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Scope == ldap.ScopeSingleLevel &&
			req.Filter == "(objectClass=organizationalUnit)" &&
			req.TimeLimit == defaultSearchTimeLimit
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	ous, err := conn.GetRootOUs("dc=example,dc=com")

	assert.NoError(t, err)
	assert.Len(t, ous, 1)
	assert.Equal(t, "ou=root,dc=example,dc=com", ous[0].DN)
}

func TestGetRootOUs_SearchError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	ous, err := conn.GetRootOUs("dc=example,dc=com")

	assert.NotNil(t, ous)
	assert.Empty(t, ous)
	assert.EqualError(t, err, "unsuccessful ou search: search failed")
}

// ---------- GetSubOUs ----------

func TestGetSubOUs_Success(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=sub,ou=root,dc=example,dc=com", Name: "sub", Children: make([]*OUInfo, 0),
	}).Once()

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=sub,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, "ou=sub,ou=root,dc=example,dc=com", subs[0].DN)
}

func TestGetSubOUs_FiltersOutSelf(t *testing.T) {
	// The method drops entries whose DN equals the search base.
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=root,dc=example,dc=com", Children: make([]*OUInfo, 0),
	}).Once()

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Empty(t, subs, "entry with DN equal to the search base must be filtered out")
}

func TestGetSubOUs_FiltersOutUnrelated(t *testing.T) {
	// The method drops entries whose DN does not end with ","+group.
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=other,dc=another,dc=com", Children: make([]*OUInfo, 0),
	}).Once()

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=other,dc=another,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Empty(t, subs, "entry whose DN does not end with \",\"+group must be filtered out")
}

func TestGetSubOUs_DoesNotMatchPrefixSubstring(t *testing.T) {
	// Regression guard: the old implementation used strings.Contains, which
	// would incorrectly match "ou=root2,dc=example,dc=com" against "ou=root".
	// The current implementation uses strings.HasSuffix(dn, ","+group), so
	// such an entry must be filtered out.
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=root2,dc=example,dc=com", Children: make([]*OUInfo, 0),
	}).Once()

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root2,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Empty(t, subs,
		"\"ou=root2,...\" must not be treated as a child of \"ou=root,...\"")
}

func TestGetSubOUs_SearchError(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("sub search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NotNil(t, subs)
	assert.Empty(t, subs)
	assert.EqualError(t, err, "unsuccessful sub ou search: sub search failed")
}

func TestGetSubOUs_VerifiesSearchRequest(t *testing.T) {
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com" &&
			req.Scope == ldap.ScopeSingleLevel &&
			req.Filter == "(objectClass=organizationalUnit)" &&
			req.TimeLimit == defaultSearchTimeLimit
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}

// ---------- GetRecursiveOUSearchResult ----------

func TestGetRecursiveOUSearchResult_AtMaxDepth(t *testing.T) {
	// When level == defaultSearchDepth, the recursion condition
	// (level < defaultSearchDepth) is false, so a single GetSubOUs call
	// is made and its results are attached as Children without further recursion.
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=child,ou=root,dc=example,dc=com", Children: make([]*OUInfo, 0),
	}).Once()

	connMock := new(MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=child,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	root := []*OUInfo{{DN: "ou=root,dc=example,dc=com", Children: make([]*OUInfo, 0)}}

	conn.GetRecursiveOUSearchResult(&root, defaultSearchDepth)

	assert.Len(t, root[0].Children, 1)
	assert.Equal(t, "ou=child,ou=root,dc=example,dc=com", root[0].Children[0].DN)
	// Exactly one search — no deeper recursion at max depth.
	connMock.AssertNumberOfCalls(t, "Search", 1)
}

func TestGetRecursiveOUSearchResult_EmptyPrevLevel(t *testing.T) {
	// An empty previous level must not cause any LDAP calls.
	adapter := new(MockCatalogAdapter)
	connMock := new(MockLDAPConn)

	conn := newTestConnection(adapter, connMock)
	level := make([]*OUInfo, 0)

	conn.GetRecursiveOUSearchResult(&level, 1)

	connMock.AssertNotCalled(t, "Search", mock.Anything)
}

func TestGetRecursiveOUSearchResult_RecursesBelowMaxDepth(t *testing.T) {
	// level (1) < defaultSearchDepth (5) → GetSubOUs runs, and the result
	// is recursively processed (a second search follows for the child).
	adapter := new(MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	// First call: child of root.
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=child,ou=root,dc=example,dc=com", Children: make([]*OUInfo, 0),
	}).Once()
	// Second call (from the recursive call): grandchild of root.
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&OUInfo{
		DN: "ou=grand,ou=child,ou=root,dc=example,dc=com", Children: make([]*OUInfo, 0),
	}).Maybe()

	connMock := new(MockLDAPConn)
	// Search for the child under root.
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com"
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=child,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()
	// Search for the grandchild under the child (recursive call).
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=child,ou=root,dc=example,dc=com"
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Maybe()

	conn := newTestConnection(adapter, connMock)
	root := []*OUInfo{{DN: "ou=root,dc=example,dc=com", Children: make([]*OUInfo, 0)}}

	conn.GetRecursiveOUSearchResult(&root, 1)

	assert.Len(t, root[0].Children, 1)
	assert.Equal(t, "ou=child,ou=root,dc=example,dc=com", root[0].Children[0].DN)
	connMock.AssertCalled(t, "Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com"
	}))
}
