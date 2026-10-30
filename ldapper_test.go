// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/mocks"
)

// ---------- dialHost ----------

func TestDialHost_URLForms(t *testing.T) {
	tests := []struct {
		name string
		host string
		port uint
		ssl  bool
		skip bool
		cfg  *tls.Config
		want string
	}{
		{"plain skip tls", "h", 389, false, true, nil, "ldap://h:389"},
		{"ssl", "h", 636, true, false, &tls.Config{}, "ldaps://h:636"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			withMockDialURL(t, func(uri string, _ ...ldap.DialOpt) (*ldap.Conn, error) {
				got = uri
				return &ldap.Conn{}, nil
			})
			if _, err := dialHost(tc.host, tc.port, tc.ssl, tc.skip, tc.cfg); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDialHost_DialError(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("dial fail")
	})
	_, err := dialHost("h", 389, false, true, nil)
	if err == nil || !strings.Contains(err.Error(), "unsuccessful dial") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------- connect ----------

func TestConnect_AllHostsFail(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("fail")
	})
	conn := &LDAPper{hosts: []string{"h1", "h2"}}
	err := conn.connect()
	if err == nil || !strings.Contains(err.Error(), "unsuccessful dial to any host") {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.connection != nil {
		t.Error("connection must remain nil")
	}
}

func TestConnect_Failover(t *testing.T) {
	attempt := 0
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		attempt++
		if attempt == 1 {
			return nil, errors.New("fail")
		}
		return &ldap.Conn{}, nil
	})

	conn := newDialableLDAPper([]string{"h1", "h2"})

	if err := conn.connect(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.currentHost != "h2" {
		t.Errorf("expected h2, got %s", conn.currentHost)
	}
	if attempt != 2 {
		t.Errorf("expected 2 attempts, got %d", attempt)
	}
}

// ---------- NewConnection ----------

func TestNewConnection_Validation(t *testing.T) {
	tooMany := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range tooMany {
		tooMany[i] = "h"
	}

	tests := []struct {
		name    string
		hosts   []string
		ssl     bool
		skip    bool
		cfg     *tls.Config
		adapter bool
		errPart string
	}{
		{"empty hosts", nil, false, true, nil, true, "empty hosts"},
		{"too many hosts", tooMany, false, true, nil, true, "too many hosts"},
		{"nil tls for starttls", []string{"h"}, false, false, nil, true, "nil tls config"},
		{"nil tls for ssl", []string{"h"}, true, false, nil, true, "nil tls config"},
		{"nil adapter", []string{"h"}, false, true, nil, false, "nil catalog adapter"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// NB: declare as the interface type, not *testCatalogAdapter,
			// otherwise assigning nil leaves a typed-nil that != nil.
			var adapter interfaces.CatalogAdapter
			if tc.adapter {
				adapter = &testCatalogAdapter{}
			}

			_, err := NewConnection(tc.hosts, 389, tc.ssl, tc.skip, tc.cfg, adapter)
			if err == nil || !strings.Contains(err.Error(), tc.errPart) {
				t.Fatalf("expected %q, got: %v", tc.errPart, err)
			}
		})
	}
}

func TestNewConnection_DialFails(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("fail")
	})
	_, err := NewConnection([]string{"h"}, 389, false, true, nil, &testCatalogAdapter{})
	if err == nil || !strings.Contains(err.Error(), "unsuccessful dial to any host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNewConnection_Success covers defaults (limits from constants) and
// option application in a single call to avoid duplicate dial plumbing.
func TestNewConnection_Success(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return &ldap.Conn{}, nil
	})

	conn, err := NewConnection([]string{"h"}, 389, false, true, nil, &testCatalogAdapter{},
		WithSearchLimits(50, 15))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.currentHost != "h" {
		t.Errorf("unexpected currentHost: %s", conn.currentHost)
	}
	if conn.searchLimits != (SearchLimits{50, 15}) {
		t.Errorf("option not applied: %+v", conn.searchLimits)
	}
}

func TestNewConnection_DefaultsFromConstants(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return &ldap.Conn{}, nil
	})
	conn, err := NewConnection([]string{"h"}, 389, false, true, nil, &testCatalogAdapter{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := SearchLimits{constants.DefaultSearchSizeLimit, constants.DefaultSearchTimeLimit}
	if conn.searchLimits != want {
		t.Errorf("got %+v, want %+v", conn.searchLimits, want)
	}
}

// ---------- NewAuthenticatedConnection ----------

func TestNewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	for _, tc := range []struct{ user, pass string }{{"", "p"}, {"u", ""}} {
		_, _, err := NewAuthenticatedConnection(tc.user, tc.pass, "dc=x",
			[]string{"h"}, 389, false, true, nil, &testCatalogAdapter{})
		if err == nil || !strings.Contains(err.Error(), "empty bind username/password") {
			t.Errorf("user=%q pass=%q: unexpected error: %v", tc.user, tc.pass, err)
		}
	}
}

func TestNewAuthenticatedConnection_NewConnectionErrorPropagates(t *testing.T) {
	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("fail")
	})
	_, _, err := NewAuthenticatedConnection("u", "p", "dc=x",
		[]string{"h"}, 389, false, true, nil, &testCatalogAdapter{})
	if err == nil {
		t.Fatal("expected error to propagate")
	}
}

// NB: success path requires a real LDAP server (Bind/Search on *ldap.Conn).

// ---------- AuthenticateConn ----------

func TestAuthenticateConn_NilConnection(t *testing.T) {
	_, err := (&LDAPper{}).AuthenticateConn("u", "p", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "connection not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{})
	_, err := conn.AuthenticateConn("", "p", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "empty bind username/password") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthenticateConn_BindError(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		BindFunc: func(string, string) error { return errors.New("bind fail") },
	})
	_, err := conn.AuthenticateConn("u", "p", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "unsuccessful bind with passed bind credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthenticateConn_Success(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)", userAttrs: []string{"cn"}},
		&mocks.MockLDAPConn{
			BindFunc: func(string, string) error { return nil },
			SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=user,dc=x", nil),
				}}, nil
			},
		},
	)

	user, err := conn.AuthenticateConn("user", "pass", "dc=x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || user.DN != "cn=user,dc=x" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if !conn.isAuthenticated || conn.bindUser != "user" || conn.bindPassword != "pass" {
		t.Errorf("auth state not stored: auth=%v user=%q pass=%q",
			conn.isAuthenticated, conn.bindUser, conn.bindPassword)
	}
}

// ---------- AuthenticateUser ----------

func TestAuthenticateUser_NilConnection(t *testing.T) {
	_, err := (&LDAPper{}).AuthenticateUser("u", "p", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "connection not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthenticateUser_NotAuthenticated(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{})
	_, err := conn.AuthenticateUser("u", "p", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "connection not authenticated") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthenticateUser_GetUserError(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)"},
		&mocks.MockLDAPConn{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("search fail")
		}},
	)
	conn.isAuthenticated = true
	_, err := conn.AuthenticateUser("u", "p", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "unsuccessful user search") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthenticateUser_BindErrors(t *testing.T) {
	tests := []struct {
		name    string
		userErr error
		errPart string
	}{
		{"user bind", errors.New("fail"), "unsuccessful bind with passed user credentials"},
		{"rebind", nil, "unsuccessful rebind with bind-config credentials"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			call := 0
			mockConn := &mocks.MockLDAPConn{
				BindFunc: func(string, string) error {
					call++
					if call == 1 {
						return tc.userErr
					}
					return errors.New("rebind fail")
				},
				SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
					return &ldap.SearchResult{Entries: []*ldap.Entry{
						newLDAPEntry("cn=user,dc=x", nil),
					}}, nil
				},
			}
			conn := newTestConnection(
				&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)", userAttrs: []string{"cn"}},
				mockConn,
			)
			conn.isAuthenticated = true
			conn.bindUser = "svc"
			conn.bindPassword = "svcpass"

			user, err := conn.AuthenticateUser("user", "pass", "dc=x")
			if err == nil || !strings.Contains(err.Error(), tc.errPart) {
				t.Fatalf("expected %q, got: %v", tc.errPart, err)
			}
			// Contract: user is returned alongside the error.
			if user == nil {
				t.Error("user must be returned even on bind errors")
			}
		})
	}
}

func TestAuthenticateUser_Success_BindSequence(t *testing.T) {
	var binds []string
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)", userAttrs: []string{"cn"}},
		&mocks.MockLDAPConn{
			BindFunc: func(u, p string) error {
				binds = append(binds, u+":"+p)
				return nil
			},
			SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=user,dc=x", nil),
				}}, nil
			},
		},
	)
	conn.isAuthenticated = true
	conn.bindUser = "svc"
	conn.bindPassword = "svcpass"

	if _, err := conn.AuthenticateUser("user", "pass", "dc=x"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Contract: first the target user, then the service (bind-config) user.
	want := []string{"cn=user,dc=x:pass", "svc:svcpass"}
	if len(binds) != len(want) || binds[0] != want[0] || binds[1] != want[1] {
		t.Fatalf("unexpected bind sequence: %v", binds)
	}
}

// ---------- IsAlive ----------

func TestIsAlive(t *testing.T) {
	tests := []struct {
		name  string
		conn  *mocks.MockLDAPConn
		alive bool
	}{
		{
			name:  "nil underlying connection",
			conn:  nil,
			alive: false,
		},
		{
			name:  "closing",
			conn:  &mocks.MockLDAPConn{IsClosingFunc: func() bool { return true }},
			alive: false,
		},
		{
			name: "search error",
			conn: &mocks.MockLDAPConn{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, errors.New("fail")
			}},
			alive: false,
		},
		{
			name:  "ok",
			conn:  &mocks.MockLDAPConn{},
			alive: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &LDAPper{}
			if tc.conn != nil {
				conn.connection = tc.conn
			}
			if got := conn.IsAlive(); got != tc.alive {
				t.Fatalf("got %v, want %v", got, tc.alive)
			}
		})
	}
}

// ---------- Reconnect ----------

func TestReconnect_ConnectError(t *testing.T) {
	closed := false
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		CloseFunc: func() error { closed = true; return nil },
	})
	conn.hosts = []string{"h"}
	conn.skipTLS = true

	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("dial fail")
	})

	if err := conn.Reconnect(); err == nil {
		t.Fatal("expected error")
	}
	if !closed {
		t.Error("old connection must be closed")
	}
	if conn.connection != nil {
		t.Error("connection must be nil after failed reconnect")
	}
}

func TestReconnect_Success(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		CloseFunc: func() error { return errors.New("close fail") }, // must be ignored
	})
	conn.hosts = []string{"h"}
	conn.skipTLS = true

	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return &ldap.Conn{}, nil
	})

	if err := conn.Reconnect(); err != nil {
		t.Fatalf("close error must be ignored, got: %v", err)
	}
	if conn.currentHost != "h" {
		t.Errorf("unexpected currentHost: %s", conn.currentHost)
	}
}

// NB: authenticated rebind success requires a real LDAP server; this test
// covers the failure branch.
func TestReconnect_AuthenticatedRebindFails(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{})
	conn.hosts = []string{"h"}
	conn.skipTLS = true
	conn.isAuthenticated = true
	conn.bindUser = "svc"
	conn.bindPassword = "pwd"

	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return &ldap.Conn{}, nil
	})

	err := conn.Reconnect()
	if err == nil || !strings.Contains(err.Error(), "unsuccessful rebind after reconnect") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------- EnsureAlive ----------

func TestEnsureAlive_Alive(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{})
	if err := conn.EnsureAlive(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureAlive_DeadReconnectSucceeds(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		IsClosingFunc: func() bool { return true },
	})
	conn.hosts = []string{"h"}
	conn.skipTLS = true

	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return &ldap.Conn{}, nil
	})

	if err := conn.EnsureAlive(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureAlive_DeadReconnectFails(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		IsClosingFunc: func() bool { return true },
	})
	conn.hosts = []string{"h"}
	conn.skipTLS = true

	withMockDialURL(t, func(string, ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("dial fail")
	})

	if err := conn.EnsureAlive(); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- Close ----------

func TestClose(t *testing.T) {
	tests := []struct {
		name    string
		conn    *mocks.MockLDAPConn
		closeOK bool
	}{
		{"nil connection", nil, true},
		{"success", &mocks.MockLDAPConn{}, true},
		{"error is swallowed", &mocks.MockLDAPConn{
			CloseFunc: func() error { return errors.New("close fail") },
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &LDAPper{}
			if tc.conn != nil {
				conn.connection = tc.conn
			}
			conn.Close() // must not panic
			if conn.connection != nil {
				t.Error("connection must be nil after Close")
			}
		})
	}
}
