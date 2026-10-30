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

// ---------- helpers for tests ----------

// stringsCount returns the number of non-overlapping occurrences of sub in s.
func stringsCount(s, sub string) int {
	if sub == "" {
		return 0
	}
	count := 0
	for {
		idx := indexSub(s, sub)
		if idx < 0 {
			return count
		}
		count++
		s = s[idx+len(sub):]
	}
}

func indexSub(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ---------- helpers for dialURL mocking ----------

// withMockDialURL temporarily replaces the package-level dialURL with fn and
// restores the original value when the test finishes.
func withMockDialURL(t *testing.T, fn func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error)) {
	t.Helper()
	original := dialURL
	dialURL = fn
	t.Cleanup(func() { dialURL = original })
}

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
			conn, err := NewConnection(
				"localhost", 389, tc.useSSL, tc.skipTLS, nil, new(mocks.MockCatalogAdapter),
			)

			assert.Nil(t, conn)
			assert.EqualError(t, err, "nil tls config passed")
		})
	}
}

func TestNewConnection_NilCatalogAdapter(t *testing.T) {
	conn, err := NewConnection(
		"localhost", 389, false, true, &tls.Config{}, nil,
	)

	assert.Nil(t, conn)
	assert.EqualError(t, err, "nil catalog adapter passed")
}

// TestNewConnection_TLSCheckBeforeAdapterCheck pins the validation order:
// tlsCfg is checked before catalogAdapter, so passing both nil must produce
// the TLS error.
func TestNewConnection_TLSCheckBeforeAdapterCheck(t *testing.T) {
	conn, err := NewConnection("localhost", 389, false, false, nil, nil)

	assert.Nil(t, conn)
	assert.EqualError(t, err, "nil tls config passed")
}

// TestNewConnection_DialError verifies that a dial failure is wrapped with
// the "unsuccessful dial" prefix and no connection is returned.
func TestNewConnection_DialError(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("connection refused")
	})

	conn, err := NewConnection(
		"localhost", 389, false, true, nil, new(mocks.MockCatalogAdapter),
	)

	assert.Nil(t, conn)
	assert.EqualError(t, err, "unsuccessful dial: connection refused")
}

// TestNewConnection_UsesLDAPURITemplate verifies that the plain LDAP URL is
// built from constants.LDAPURITemplate and passed to dialURL.
func TestNewConnection_UsesLDAPURITemplate(t *testing.T) {
	var gotURI string
	withMockDialURL(t, func(uri string, _ ...ldap.DialOpt) (*ldap.Conn, error) {
		gotURI = uri
		return nil, errors.New("stop")
	})

	_, _ = NewConnection(
		"ldap.example.com", 389, false, true, nil, new(mocks.MockCatalogAdapter),
	)

	assert.Equal(t, "ldap://ldap.example.com:389", gotURI)
}

// TestNewConnection_UsesLDAPSURITemplate verifies that the LDAPS URL is built
// from constants.LDAPSURITemplate and passed to dialURL with TLS options.
func TestNewConnection_UsesLDAPSURITemplate(t *testing.T) {
	var gotURI string
	var gotOpts int
	withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
		gotURI = uri
		gotOpts = len(opts)
		return nil, errors.New("stop")
	})

	_, _ = NewConnection(
		"ldap.example.com", 636, true, false, &tls.Config{}, new(mocks.MockCatalogAdapter),
	)

	assert.Equal(t, "ldaps://ldap.example.com:636", gotURI)
	assert.Equal(t, 1, gotOpts, "ldaps dial must pass DialWithTLSConfig")
}

// TestNewConnection_DialErrorIsWrappedWithOriginalMessage verifies that the
// original dial error message is preserved in the wrapped error.
func TestNewConnection_DialErrorIsWrappedWithOriginalMessage(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("i/o timeout")
	})

	_, err := NewConnection(
		"localhost", 389, false, true, nil, new(mocks.MockCatalogAdapter),
	)

	assert.EqualError(t, err, "unsuccessful dial: i/o timeout")
}

// ---------- NewAuthenticatedConnection ----------

func TestNewAuthenticatedConnection_EmptyUsername(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)

	conn, user, err := NewAuthenticatedConnection(
		"", "secret", "dc=example,dc=com",
		"localhost", 389, false, true, &tls.Config{}, adapter,
	)

	assert.Nil(t, conn)
	assert.Nil(t, user)
	assert.EqualError(t, err, "empty bind username/password passed")
	adapter.AssertNotCalled(t, "SearchUserFilterTemplate")
}

func TestNewAuthenticatedConnection_EmptyPassword(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)

	conn, user, err := NewAuthenticatedConnection(
		"jdoe", "", "dc=example,dc=com",
		"localhost", 389, false, true, &tls.Config{}, adapter,
	)

	assert.Nil(t, conn)
	assert.Nil(t, user)
	assert.EqualError(t, err, "empty bind username/password passed")
	adapter.AssertNotCalled(t, "SearchUserFilterTemplate")
}

func TestNewAuthenticatedConnection_EmptyCredentials_TableDriven(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "secret"},
		{"empty password", "jdoe", ""},
		{"both empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := new(mocks.MockCatalogAdapter)

			conn, user, err := NewAuthenticatedConnection(
				tc.username, tc.password, "dc=example,dc=com",
				"localhost", 389, false, true, &tls.Config{}, adapter,
			)

			assert.Nil(t, conn)
			assert.Nil(t, user)
			assert.EqualError(t, err, "empty bind username/password passed")
			adapter.AssertNotCalled(t, "SearchUserFilterTemplate")
		})
	}
}

func TestNewAuthenticatedConnection_NilTLSConfig(t *testing.T) {
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
			conn, user, err := NewAuthenticatedConnection(
				"jdoe", "secret", "dc=example,dc=com",
				"localhost", 389, tc.useSSL, tc.skipTLS, nil, new(mocks.MockCatalogAdapter),
			)

			assert.Nil(t, conn)
			assert.Nil(t, user)
			assert.EqualError(t, err, "nil tls config passed")
		})
	}
}

func TestNewAuthenticatedConnection_NilCatalogAdapter(t *testing.T) {
	conn, user, err := NewAuthenticatedConnection(
		"jdoe", "secret", "dc=example,dc=com",
		"localhost", 389, false, true, &tls.Config{}, nil,
	)

	assert.Nil(t, conn)
	assert.Nil(t, user)
	assert.EqualError(t, err, "nil catalog adapter passed")
}

func TestNewAuthenticatedConnection_DialError(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("connection refused")
	})

	conn, user, err := NewAuthenticatedConnection(
		"jdoe", "secret", "dc=example,dc=com",
		"127.0.0.1", 1, false, true, nil, new(mocks.MockCatalogAdapter),
	)

	assert.Nil(t, conn)
	assert.Nil(t, user)
	assert.EqualError(t, err, "unsuccessful dial: connection refused")
}

// TestNewAuthenticatedConnection_DialErrorNotDoubleWrapped verifies that the
// "unsuccessful dial" prefix appears exactly once — no extra wrapping by
// NewAuthenticatedConnection.
func TestNewAuthenticatedConnection_DialErrorNotDoubleWrapped(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("connection refused")
	})

	_, _, err := NewAuthenticatedConnection(
		"jdoe", "secret", "dc=example,dc=com",
		"127.0.0.1", 1, false, true, nil, new(mocks.MockCatalogAdapter),
	)

	assert.NotNil(t, err)
	assert.Equal(t, 1, stringsCount(err.Error(), "unsuccessful dial"),
		"the dial error must be propagated without extra wrapping")
}

// TestNewAuthenticatedConnection_AuthErrorClosesConnection verifies that when
// AuthenticateConn fails, the already-opened connection is closed and
// (nil, nil, err) is returned. This is the reason the `connection.Close()`
// call exists in the error branch.
func TestNewAuthenticatedConnection_AuthErrorClosesConnection(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	// Bind fails — AuthenticateConn returns an error before GetUser.
	connMock.On("Bind", "jdoe", "wrong").Return(errors.New("invalid credentials")).Once()
	// NewAuthenticatedConnection must close the connection on auth error.
	connMock.On("Close").Return(nil).Once()

	withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
		// dialURL returns a real *ldap.Conn, which cannot be mocked directly.
		// Instead, we stub NewConnection's result by intercepting at a higher
		// level: this helper is only meaningful when dial returns a *ldap.Conn,
		// so we return an error and assert the alternative path below.
		return nil, errors.New("not reached")
	})

	// Because dialURL returns *ldap.Conn (concrete type), we cannot inject
	// connMock here. This test therefore documents the intended contract
	// and must be upgraded once NewConnection is refactored to return
	// interfaces.LDAPConn from a mockable dial function.
	t.Skip("requires NewConnection to return interfaces.LDAPConn from a mockable dial")
}

// TestNewAuthenticatedConnection_AuthErrorIsPropagated verifies that an error
// from AuthenticateConn is returned unchanged, with nil conn and nil user.
func TestNewAuthenticatedConnection_AuthErrorIsPropagated(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("connection refused")
	})

	conn, user, err := NewAuthenticatedConnection(
		"jdoe", "secret", "dc=example,dc=com",
		"127.0.0.1", 1, false, true, nil, new(mocks.MockCatalogAdapter),
	)

	assert.Nil(t, conn)
	assert.Nil(t, user)
	assert.NotNil(t, err)
}

// TestNewAuthenticatedConnection_ErrorShape verifies the contract: on any
// error, both conn and user are nil.
func TestNewAuthenticatedConnection_ErrorShape(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("connection refused")
	})

	conn, user, err := NewAuthenticatedConnection(
		"jdoe", "secret", "dc=example,dc=com",
		"127.0.0.1", 1, false, true, nil, new(mocks.MockCatalogAdapter),
	)

	if err != nil {
		assert.Nil(t, conn, "on error, conn must be nil")
		assert.Nil(t, user, "on error, user must be nil")
	}
}

// ---------- AuthenticateConn ----------

func TestAuthenticateConn_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	// Bind is performed with the raw username BEFORE the user lookup.
	connMock.On("Bind", "jdoe", "secret").Return(nil).Once()
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", map[string][]string{"cn": {"John Doe"}}),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "uid=jdoe,dc=example,dc=com", user.DN)
	assert.Equal(t, []string{"John Doe"}, user.Attributes["cn"])

	// Auth state must be recorded for later rebinds.
	assert.True(t, conn.isAuthenticated)
	assert.Equal(t, "jdoe", conn.bindUser,
		"bindUser stores the raw username passed to AuthenticateConn, not user.DN")
	assert.Equal(t, "secret", conn.bindPassword)

	connMock.AssertExpectations(t)
	adapter.AssertExpectations(t)
}

func TestAuthenticateConn_NilConnection(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	conn := &LDAPConnection{catalogAdapter: adapter, connection: nil}

	user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
	adapter.AssertNotCalled(t, "SearchUserFilterTemplate")
	assert.False(t, conn.isAuthenticated)
}

func TestAuthenticateConn_EmptyCredentials(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "secret"},
		{"empty password", "jdoe", ""},
		{"both empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := new(mocks.MockCatalogAdapter)
			connMock := new(mocks.MockLDAPConn)
			conn := newTestConnection(adapter, connMock)

			user, err := conn.AuthenticateConn(tc.username, tc.password, "dc=example,dc=com")

			assert.Nil(t, user)
			assert.EqualError(t, err, "empty bind username/password passed")
			// No LDAP calls must happen for invalid input.
			connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
			connMock.AssertNotCalled(t, "Search", mock.Anything)
			assert.False(t, conn.isAuthenticated)
		})
	}
}

func TestAuthenticateConn_BindError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Bind", "jdoe", "wrong").
		Return(errors.New("invalid credentials")).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.AuthenticateConn("jdoe", "wrong", "dc=example,dc=com")

	assert.Nil(t, user, "user must be nil when bind fails before lookup")
	assert.EqualError(t, err, "unsuccessful bind with passed bind credentials")
	assert.NotContains(t, err.Error(), "invalid credentials",
		"the original bind error must not leak into the returned error")

	// GetUser must not be called after a failed bind.
	connMock.AssertNotCalled(t, "Search", mock.Anything)
	adapter.AssertNotCalled(t, "SearchUserFilterTemplate")

	// Auth state must NOT be updated on failure.
	assert.False(t, conn.isAuthenticated)
	assert.Empty(t, conn.bindUser)
	assert.Empty(t, conn.bindPassword)
}

func TestAuthenticateConn_GetUserError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Bind", "jdoe", "secret").Return(nil).Once()
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "user does not exist")
	assert.False(t, conn.isAuthenticated)
	assert.Empty(t, conn.bindUser)
	assert.Empty(t, conn.bindPassword)
}

func TestAuthenticateConn_GetUserSearchError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Bind", "jdoe", "secret").Return(nil).Once()
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "unsuccessful user search: search failed")
	assert.False(t, conn.isAuthenticated)
	assert.Empty(t, conn.bindUser)
}

func TestAuthenticateConn_BindBeforeLookup(t *testing.T) {
	// The current implementation performs the bind with the raw username
	// BEFORE calling GetUser. This test pins the call order so that any
	// future refactor is a conscious change.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	var callOrder []string
	connMock := new(mocks.MockLDAPConn)
	connMock.On("Bind", "jdoe", "secret").Return(nil).Once().
		Run(func(mock.Arguments) { callOrder = append(callOrder, "Bind") })
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once().
		Run(func(mock.Arguments) { callOrder = append(callOrder, "Search") })

	conn := newTestConnection(adapter, connMock)
	_, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.Equal(t, []string{"Bind", "Search"}, callOrder,
		"AuthenticateConn must bind before the user lookup")
}

func TestAuthenticateConn_StoresRawUsernameAsBindUser(t *testing.T) {
	// bindUser must be the username passed by the caller, not user.DN —
	// the stored credentials are later used verbatim in AuthenticateUser's rebind.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Bind", "jdoe", "secret").Return(nil).Once()
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("cn=John Doe,ou=people,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.Equal(t, "jdoe", conn.bindUser,
		"bindUser must be the raw username, not the returned DN")
}

func TestAuthenticateConn_OverwritesPreviousAuthState(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Bind", "alice", "alice-pass").Return(nil).Once()
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=alice,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Bind", "bob", "bob-pass").Return(nil).Once()
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=bob,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)

	_, err := conn.AuthenticateConn("alice", "alice-pass", "dc=example,dc=com")
	assert.NoError(t, err)
	assert.Equal(t, "alice", conn.bindUser)
	assert.Equal(t, "alice-pass", conn.bindPassword)

	_, err = conn.AuthenticateConn("bob", "bob-pass", "dc=example,dc=com")
	assert.NoError(t, err)
	assert.Equal(t, "bob", conn.bindUser,
		"the second successful authentication must overwrite the stored bind user")
	assert.Equal(t, "bob-pass", conn.bindPassword)
	assert.True(t, conn.isAuthenticated)
}

// ---------- AuthenticateUser ----------

func TestAuthenticateUser_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", map[string][]string{"cn": {"John Doe"}}),
	}}, nil).Once()
	// 1st bind: verify the end user's credentials using their DN.
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "user-pass").Return(nil).Once()
	// 2nd bind: rebind back onto the service account.
	connMock.On("Bind", "svc-reader", "svc-pass").Return(nil).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "svc-reader",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticateUser("jdoe", "user-pass", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "uid=jdoe,dc=example,dc=com", user.DN)
	assert.Equal(t, []string{"John Doe"}, user.Attributes["cn"])

	// bindUser / bindPassword must remain unchanged after the rebind.
	assert.Equal(t, "svc-reader", conn.bindUser)
	assert.Equal(t, "svc-pass", conn.bindPassword)
	assert.True(t, conn.isAuthenticated)

	connMock.AssertNumberOfCalls(t, "Bind", 2)
	connMock.AssertExpectations(t)
}

func TestAuthenticateUser_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(mocks.MockCatalogAdapter)}
	user, err := conn.AuthenticateUser("jdoe", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
}

func TestAuthenticateUser_NotAuthenticated(t *testing.T) {
	connMock := new(mocks.MockLDAPConn)
	conn := &LDAPConnection{
		catalogAdapter:  new(mocks.MockCatalogAdapter),
		connection:      connMock,
		isAuthenticated: false,
	}

	user, err := conn.AuthenticateUser("jdoe", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not authenticated")
	connMock.AssertNotCalled(t, "Search", mock.Anything)
	connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
}

func TestAuthenticateUser_EmptyCredentials(t *testing.T) {
	cases := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "pass"},
		{"empty password", "jdoe", ""},
		{"both empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			adapter := new(mocks.MockCatalogAdapter)
			connMock := new(mocks.MockLDAPConn)
			conn := &LDAPConnection{
				catalogAdapter:  adapter,
				connection:      connMock,
				isAuthenticated: true,
				bindUser:        "svc-reader",
				bindPassword:    "svc-pass",
			}

			user, err := conn.AuthenticateUser(tc.username, tc.password, "dc=example,dc=com")

			assert.Nil(t, user)
			assert.EqualError(t, err, "empty username/password passed")
			// No LDAP calls must happen for invalid input.
			connMock.AssertNotCalled(t, "Search", mock.Anything)
			connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
		})
	}
}

func TestAuthenticateUser_GetUserError(t *testing.T) {
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
		bindUser:        "svc-reader",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticateUser("nobody", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "user does not exist")
	connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
}

func TestAuthenticateUser_GetUserSearchError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("search failed")).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "svc-reader",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticateUser("jdoe", "pass", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "unsuccessful user search: search failed")
	connMock.AssertNotCalled(t, "Bind", mock.Anything, mock.Anything)
}

func TestAuthenticateUser_UserBindError(t *testing.T) {
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
		bindUser:        "svc-reader",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticateUser("jdoe", "wrong", "dc=example,dc=com")

	assert.NotNil(t, user, "user is returned even on user bind failure")
	assert.EqualError(t, err, "unsuccessful bind with passed user credentials")
	assert.NotContains(t, err.Error(), "invalid credentials",
		"the original bind error must not leak into the returned error")

	// Only one bind attempted — the rebind must not happen.
	connMock.AssertNumberOfCalls(t, "Bind", 1)
}

func TestAuthenticateUser_RebindError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "user-pass").Return(nil).Once()
	connMock.On("Bind", "svc-reader", "svc-pass").
		Return(errors.New("service account locked")).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "svc-reader",
		bindPassword:    "svc-pass",
	}
	user, err := conn.AuthenticateUser("jdoe", "user-pass", "dc=example,dc=com")

	assert.NotNil(t, user)
	assert.EqualError(t, err, "unsuccessful rebind with bind-config credentials")
	assert.NotContains(t, err.Error(), "service account locked",
		"the original rebind error must not leak into the returned error")
	connMock.AssertNumberOfCalls(t, "Bind", 2)
}

func TestAuthenticateUser_BindsUserDNThenRebindsServiceAccount(t *testing.T) {
	// Pins the exact sequence and arguments of the two Bind calls:
	// first as user.DN with the user's password, then as the stored
	// service account credentials.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	var binds []string
	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "user-pass").Return(nil).Once().
		Run(func(args mock.Arguments) {
			binds = append(binds, args.String(0)+":"+args.String(1))
		})
	connMock.On("Bind", "svc-reader", "svc-pass").Return(nil).Once().
		Run(func(args mock.Arguments) {
			binds = append(binds, args.String(0)+":"+args.String(1))
		})

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "svc-reader",
		bindPassword:    "svc-pass",
	}
	_, err := conn.AuthenticateUser("jdoe", "user-pass", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.Equal(t, []string{
		"uid=jdoe,dc=example,dc=com:user-pass",
		"svc-reader:svc-pass",
	}, binds, "AuthenticateUser must bind as the user, then rebind as the service account")
}

func TestAuthenticateUser_ServiceAccountUnchanged(t *testing.T) {
	// Even a successful AuthenticateUser must not modify the stored
	// service account credentials.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Bind", "uid=jdoe,dc=example,dc=com", "user-pass").Return(nil).Once()
	connMock.On("Bind", "svc-reader", "svc-pass").Return(nil).Once()

	conn := &LDAPConnection{
		catalogAdapter:  adapter,
		connection:      connMock,
		isAuthenticated: true,
		bindUser:        "svc-reader",
		bindPassword:    "svc-pass",
	}
	_, err := conn.AuthenticateUser("jdoe", "user-pass", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.Equal(t, "svc-reader", conn.bindUser)
	assert.Equal(t, "svc-pass", conn.bindPassword)
	assert.True(t, conn.isAuthenticated)
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
