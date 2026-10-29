// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/NGRsoftlab/ldapper/mocks"
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
			conn, err := NewConnection("localhost", 389, tc.useSSL, tc.skipTLS, nil, new(mocks.MockCatalogAdapter))
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
	conn, err := NewConnection("127.0.0.1", 1, false, true, nil, new(mocks.MockCatalogAdapter))
	assert.Nil(t, conn)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsuccessful dial")
}

func TestNewConnection_UsesLDAPURITemplate(t *testing.T) {
	// The ldap:// URI is built from the constants in constants.go.
	// A closed port produces a dial error whose message contains the URI.
	conn, err := NewConnection("example.invalid", 389, false, true, nil, new(mocks.MockCatalogAdapter))
	assert.Nil(t, conn)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsuccessful dial",
		"ldapURITemplate must be used to build the dial URL")
}

func TestNewConnection_UsesLDAPSURITemplate(t *testing.T) {
	// The ldaps:// URI is built from the constants in constants.go.
	conn, err := NewConnection("example.invalid", 636, true, false, &tls.Config{}, new(mocks.MockCatalogAdapter))
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
				"localhost", 389, false, true, &tls.Config{}, new(mocks.MockCatalogAdapter),
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
		"localhost", 636, true, false, nil, new(mocks.MockCatalogAdapter),
	)
	assert.Nil(t, conn)
	assert.Nil(t, user)
	assert.EqualError(t, err, "nil tls config passed")
}

// ---------- AuthenticateConn ----------

func TestAuthenticateConn_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
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
	adapter := new(mocks.MockCatalogAdapter)
	conn := &LDAPConnection{catalogAdapter: adapter}

	user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
	adapter.AssertNotCalled(t, "SearchUserFilterTemplate")
}

func TestAuthenticateConn_GetUserError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
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
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
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
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
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
	conn := &LDAPConnection{catalogAdapter: new(mocks.MockCatalogAdapter)}
	user, err := conn.AuthenticatedUser("jdoe", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
}

func TestAuthenticatedUser_NotAuthenticated(t *testing.T) {
	connMock := new(mocks.MockLDAPConn)
	conn := &LDAPConnection{
		catalogAdapter:  new(mocks.MockCatalogAdapter),
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
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
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
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
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
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
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
	connMock := new(mocks.MockLDAPConn)
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
	connMock := new(mocks.MockLDAPConn)
	connMock.On("Close").Return(errors.New("close failed")).Once()

	conn := &LDAPConnection{connection: connMock}
	conn.Close()

	assert.Nil(t, conn.connection,
		"current behavior: connection is nil-ed out regardless of the Close error")
	connMock.AssertExpectations(t)
}
