// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/mocks"
)

// ---------- stateful auth mock ----------

// authConn is a stateful LDAPConn mock that tracks Bind and Search call
// counts independently. Necessary because AuthenticateConn performs exactly
// one Bind (service user) followed by one Search (lookup), while
// CheckUserCredentials performs one Search then two Binds (user → rebind).
//
// The callbacks receive the zero-based call index so a test can distinguish
// the user's bind from the service rebind.
type authConn struct {
	mock        *mocks.MockLDAPConn
	bindCalls   int
	searchCalls int
}

func newAuthConn(
	searchFn func(callIdx int, req *ldap.SearchRequest) (*ldap.SearchResult, error),
	bindFn func(callIdx int, u, p string) error,
) *authConn {
	ac := &authConn{}
	ac.mock = &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			idx := ac.searchCalls
			ac.searchCalls++
			if searchFn == nil {
				return &ldap.SearchResult{}, nil
			}
			return searchFn(idx, req)
		},
		BindFunc: func(u, p string) error {
			idx := ac.bindCalls
			ac.bindCalls++
			if bindFn == nil {
				return nil
			}
			return bindFn(idx, u, p)
		},
	}
	return ac
}

// simpleUserAdapter is the minimal adapter needed for user lookup paths.
func simpleUserAdapter() *fakeAdapter {
	return &fakeAdapter{
		userFilterTemplate: "(uid=%s)",
		userAttrs:          []string{"uid", "cn"},
	}
}

// ---------- AuthenticateConn ----------

// TestAuthenticateConn covers the service-bind path: validation, bind,
// lookup and caching of credentials. This is the "happy-path service login"
// tested through every failure mode.
func TestAuthenticateConn(t *testing.T) {
	const (
		user   = "svc-reader"
		pass   = "s3cr3t"
		baseDN = "dc=example,dc=com"
	)

	userEntry := newLDAPEntry(
		"cn=svc-reader,ou=ServiceAccounts,dc=example,dc=com",
		map[string][]string{"uid": {"svc-reader"}, "cn": {"svc-reader"}},
	)

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: simpleUserAdapter()}
		_, err := l.AuthenticateConn(user, pass, baseDN)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty username", func(t *testing.T) {
		ac := newAuthConn(nil, nil)
		l := &LDAPper{connection: ac.mock, catalogAdapter: simpleUserAdapter()}
		_, err := l.AuthenticateConn("", pass, baseDN)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
		if ac.bindCalls != 0 || ac.searchCalls != 0 {
			t.Fatalf("no bind/search expected, got bind=%d search=%d", ac.bindCalls, ac.searchCalls)
		}
	})

	t.Run("empty password", func(t *testing.T) {
		ac := newAuthConn(nil, nil)
		l := &LDAPper{connection: ac.mock, catalogAdapter: simpleUserAdapter()}
		_, err := l.AuthenticateConn(user, "", baseDN)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("empty baseDN rejected before bind", func(t *testing.T) {
		ac := newAuthConn(nil, nil)
		l := &LDAPper{connection: ac.mock, catalogAdapter: simpleUserAdapter()}
		_, err := l.AuthenticateConn(user, pass, "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
		if ac.bindCalls != 0 {
			t.Fatalf("bind must not happen on invalid baseDN, got %d calls", ac.bindCalls)
		}
	})

	t.Run("bind failure classified, no lookup issued", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("bad password")}
		ac := newAuthConn(nil, func(_ int, u, p string) error { return raw })
		l := &LDAPper{connection: ac.mock, catalogAdapter: simpleUserAdapter()}

		_, err := l.AuthenticateConn(user, pass, baseDN)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("errors.Is(%v, ErrInvalidCredentials) = false", err)
		}
		if ac.searchCalls != 0 {
			t.Fatalf("lookup must not happen after bind failure, got %d search calls", ac.searchCalls)
		}
		// Sensitive bind path must not leak the raw server text.
		if strings.Contains(err.Error(), "bad password") {
			t.Fatalf("bind error leaked raw text: %v", err)
		}
	})

	t.Run("user not found after successful bind", func(t *testing.T) {
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{}, nil // zero entries
			},
			nil, // bind succeeds
		)
		l := &LDAPper{
			connection:      ac.mock,
			catalogAdapter:  simpleUserAdapter(),
			isAuthenticated: true, // pre-authenticated (this is the A01 scenario)
			bindUser:        "svc-reader",
			bindPassword:    "svc-pass",
			bindDN:          "dc=example,dc=com",
		}

		_, err := l.AuthenticateConn(user, pass, baseDN)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
		if l.isAuthenticated {
			t.Fatalf("isAuthenticated must be false after failed post-bind lookup")
		}
		if l.bindUser != "" || l.bindPassword != "" {
			t.Fatalf("bind credentials must be cleared: user=%q pass=%q", l.bindUser, l.bindPassword)
		}
	})

	t.Run("success caches credentials and returns user", func(t *testing.T) {
		var bindUser, bindPass string
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			func(_ int, u, p string) error {
				bindUser, bindPass = u, p
				return nil
			},
		)
		l := &LDAPper{connection: ac.mock, catalogAdapter: simpleUserAdapter()}

		got, err := l.AuthenticateConn(user, pass, baseDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.DN != userEntry.DN {
			t.Fatalf("user = %+v, want DN %q", got, userEntry.DN)
		}
		if got.GetAttributeValue("uid") != "svc-reader" {
			t.Fatalf("uid = %q", got.GetAttributeValue("uid"))
		}

		// Bind was made with the supplied credentials.
		if bindUser != user || bindPass != pass {
			t.Fatalf("bind creds = %q/%q, want %q/%q", bindUser, bindPass, user, pass)
		}

		// Connection state cached.
		if !l.isAuthenticated {
			t.Fatalf("isAuthenticated = false, want true")
		}
		if l.bindUser != user || l.bindPassword != pass || l.bindDN != baseDN {
			t.Fatalf("cached creds = %q/%q/%q", l.bindUser, l.bindPassword, l.bindDN)
		}
	})

	t.Run("failed bind on authenticated conn invalidates state", func(t *testing.T) {
		// Simulate a pre-authenticated connection (previous AuthenticateConn
		// succeeded) that is now asked to bind again with wrong credentials.
		raw := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("bad pw")}
		ac := newAuthConn(nil, func(_ int, u, p string) error { return raw })
		l := &LDAPper{
			connection:      ac.mock,
			catalogAdapter:  simpleUserAdapter(),
			isAuthenticated: true,
			bindUser:        "svc-reader",
			bindPassword:    "svc-pass",
			bindDN:          "dc=example,dc=com",
		}

		_, err := l.AuthenticateConn("alice", "wrong", baseDN)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("errors.Is(%v, ErrInvalidCredentials) = false", err)
		}

		// Cached auth state must be cleared: the live LDAP session is anonymous
		// (RFC 4513 §4) and must not be advertised as a service session.
		if l.isAuthenticated {
			t.Fatalf("isAuthenticated = true after failed bind on authenticated conn")
		}
		if l.bindUser != "" || l.bindPassword != "" {
			t.Fatalf("bind credentials must be cleared: user=%q pass=%q", l.bindUser, l.bindPassword)
		}
		if l.bindDN != "dc=example,dc=com" {
			t.Fatalf("bindDN must be preserved: %q", l.bindDN)
		}

		// CheckUserCredentials on the now-invalidated connection must report
		// ErrNotAuthenticated, not attempt to Search/Bind anonymously.
		ac.searchCalls = 0
		ac.bindCalls = 0
		_, err = l.CheckUserCredentials("alice", "whatever")
		if !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("errors.Is(%v, ErrNotAuthenticated) = false", err)
		}
		if ac.searchCalls != 0 || ac.bindCalls != 0 {
			t.Fatalf("no I/O must be issued after invalidation: search=%d bind=%d",
				ac.searchCalls, ac.bindCalls)
		}
	})

	t.Run("successful bind populates cached credentials", func(t *testing.T) {
		userEntry := newLDAPEntry(
			"cn=svc-reader,dc=example,dc=com",
			map[string][]string{"uid": {"svc-reader"}},
		)
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			nil,
		)
		l := &LDAPper{connection: ac.mock, catalogAdapter: simpleUserAdapter()}

		_, err := l.AuthenticateConn("svc-reader", "svc-pass", baseDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !l.isAuthenticated {
			t.Fatalf("isAuthenticated = false after successful bind")
		}
		if l.bindUser != "svc-reader" || l.bindPassword != "svc-pass" || l.bindDN != baseDN {
			t.Fatalf("cached creds = %q/%q/%q", l.bindUser, l.bindPassword, l.bindDN)
		}
	})

	t.Run("user not found after successful bind", func(t *testing.T) {
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{}, nil // zero entries
			},
			nil, // bind succeeds
		)
		l := &LDAPper{
			connection:      ac.mock,
			catalogAdapter:  simpleUserAdapter(),
			isAuthenticated: true,
			bindUser:        "svc-reader",
			bindPassword:    "svc-pass",
			bindDN:          "dc=example,dc=com",
		}

		_, err := l.AuthenticateConn(user, pass, baseDN)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
		if l.isAuthenticated {
			t.Fatalf("isAuthenticated must be false after failed post-bind lookup")
		}
		if l.bindUser != "" || l.bindPassword != "" {
			t.Fatalf("bind credentials must be cleared: user=%q pass=%q", l.bindUser, l.bindPassword)
		}

		// NEW: the connection itself must be closed — otherwise subsequent
		// operations would run under the unverified `username` identity.
		if l.connection != nil {
			t.Fatalf("connection must be closed after failed post-bind lookup")
		}

		// NEW: subsequent operations must report ErrClosed, not attempt a Search.
		ac.searchCalls = 0
		ac.bindCalls = 0
		_, err = l.GetUser("alice", baseDN)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
		if ac.searchCalls != 0 || ac.bindCalls != 0 {
			t.Fatalf("no I/O must be issued after post-bind lookup failure: search=%d bind=%d",
				ac.searchCalls, ac.bindCalls)
		}
	})
}

// ---------- CheckUserCredentials ----------

// TestCheckUserCredentials covers the user-verification path. Unlike
// AuthenticateConn, this method must:
//   - never mask user existence to distinguish "user missing" from
//     "wrong password" differently — both surface as ErrInvalidCredentials;
//   - always restore the service bind, even when the user's bind fails;
//   - never return a user object alongside an auth error.
func TestCheckUserCredentials(t *testing.T) {
	const (
		svcUser = "svc-reader"
		svcPass = "svc-pass"
		baseDN  = "dc=example,dc=com"
	)

	userEntry := newLDAPEntry(
		"cn=Alice,ou=Users,dc=example,dc=com",
		map[string][]string{"uid": {"alice"}, "cn": {"Alice"}},
	)

	// newAuthLDAPper returns an LDAPper pre-loaded with the auth state
	// expected by CheckUserCredentials.
	newAuthLDAPper := func(ac *authConn) *LDAPper {
		return &LDAPper{
			connection:      ac.mock,
			catalogAdapter:  simpleUserAdapter(),
			isAuthenticated: true,
			bindUser:        svcUser,
			bindPassword:    svcPass,
			bindDN:          baseDN,
		}
	}

	t.Run("unauthenticated connection rejected", func(t *testing.T) {
		ac := newAuthConn(nil, nil)
		l := &LDAPper{connection: ac.mock, catalogAdapter: simpleUserAdapter()}
		// isAuthenticated defaults to false.
		_, err := l.CheckUserCredentials("alice", "any")
		if !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("errors.Is(%v, ErrNotAuthenticated) = false", err)
		}
		if ac.searchCalls != 0 || ac.bindCalls != 0 {
			t.Fatalf("no I/O expected, got search=%d bind=%d", ac.searchCalls, ac.bindCalls)
		}
	})

	t.Run("empty username", func(t *testing.T) {
		ac := newAuthConn(nil, nil)
		l := newAuthLDAPper(ac)
		_, err := l.CheckUserCredentials("", "p")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("empty password", func(t *testing.T) {
		ac := newAuthConn(nil, nil)
		l := newAuthLDAPper(ac)
		_, err := l.CheckUserCredentials("alice", "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("user not found surfaces as ErrInvalidCredentials", func(t *testing.T) {
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{}, nil // user missing
			},
			nil,
		)
		l := newAuthLDAPper(ac)

		user, err := l.CheckUserCredentials("ghost", "any")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("errors.Is(%v, ErrInvalidCredentials) = false", err)
		}
		if errors.Is(err, ErrNotFound) {
			t.Fatalf("user enumeration leak: ErrNotFound must be masked")
		}
		if user != nil {
			t.Fatalf("user must be nil on auth failure, got %+v", user)
		}
		// No bind should have been attempted.
		if ac.bindCalls != 0 {
			t.Fatalf("bind must not happen when the user is not found, got %d", ac.bindCalls)
		}
		// Service session stays healthy: no rebind needed, isAuthenticated true.
		if !l.isAuthenticated {
			t.Fatalf("isAuthenticated must remain true")
		}
	})

	t.Run("user bind fails with invalid credentials; service rebind ok", func(t *testing.T) {
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			func(idx int, u, p string) error {
				// Call 0: user bind → invalid creds.
				// Call 1: service rebind → ok.
				if idx == 0 {
					return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("bad pw")}
				}
				return nil
			},
		)
		l := newAuthLDAPper(ac)

		user, err := l.CheckUserCredentials("alice", "wrong")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("errors.Is(%v, ErrInvalidCredentials) = false", err)
		}
		if user != nil {
			t.Fatalf("user must be nil on bind failure (no mis-use invitation), got %+v", user)
		}
		if !l.isAuthenticated {
			t.Fatalf("service session must survive a user bind failure")
		}
	})

	t.Run("user bind fails with insufficient access", func(t *testing.T) {
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			func(idx int, u, p string) error {
				if idx == 0 {
					return &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("denied")}
				}
				return nil
			},
		)
		l := newAuthLDAPper(ac)

		_, err := l.CheckUserCredentials("alice", "x")
		if !errors.Is(err, ErrInsufficientAccess) {
			t.Fatalf("errors.Is(%v, ErrInsufficientAccess) = false", err)
		}
	})

	t.Run("successful user bind, service rebind succeeds", func(t *testing.T) {
		var userBindCreds, svcBindCreds [2]string
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			func(idx int, u, p string) error {
				if idx == 0 {
					userBindCreds = [2]string{u, p}
				} else {
					svcBindCreds = [2]string{u, p}
				}
				return nil
			},
		)
		l := newAuthLDAPper(ac)

		user, err := l.CheckUserCredentials("alice", "alice-pass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if user == nil || user.DN != userEntry.DN {
			t.Fatalf("user = %+v, want DN %q", user, userEntry.DN)
		}
		// First bind used the user's DN and supplied password.
		if userBindCreds[0] != userEntry.DN || userBindCreds[1] != "alice-pass" {
			t.Fatalf("user bind creds = %v", userBindCreds)
		}
		// Rebind restored the service credentials.
		if svcBindCreds[0] != svcUser || svcBindCreds[1] != svcPass {
			t.Fatalf("service rebind creds = %v", svcBindCreds)
		}
		if !l.isAuthenticated {
			t.Fatalf("isAuthenticated must remain true after clean rebind")
		}
	})

	t.Run("user bind ok, service rebind fails: ErrNotAuthenticated", func(t *testing.T) {
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			func(idx int, u, p string) error {
				if idx == 0 {
					return nil // user bind OK
				}
				return &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("server down")}
			},
		)
		l := newAuthLDAPper(ac)

		user, err := l.CheckUserCredentials("alice", "alice-pass")
		if !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("errors.Is(%v, ErrNotAuthenticated) = false", err)
		}
		if user != nil {
			t.Fatalf("user must be nil when service session is lost, got %+v", user)
		}
		if l.isAuthenticated {
			t.Fatalf("isAuthenticated must be cleared after rebind failure")
		}
	})

	t.Run("both binds fail: primary error preserved, no secret leak", func(t *testing.T) {
		const secret = "alice-secret-pw"
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			func(idx int, u, p string) error {
				// Both binds fail with invalid creds; error text may echo the
				// submitted password — must not leak through classify*.
				return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("bind failed for " + p)}
			},
		)
		l := newAuthLDAPper(ac)

		_, err := l.CheckUserCredentials("alice", secret)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("errors.Is(%v, ErrInvalidCredentials) = false", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("password leaked through wrapped error: %v", err)
		}
		if l.isAuthenticated {
			t.Fatalf("isAuthenticated must be cleared when rebind fails")
		}
	})

	t.Run("service rebind fails: connection closed", func(t *testing.T) {
		ac := newAuthConn(
			func(_ int, _ *ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{userEntry}}, nil
			},
			func(idx int, u, p string) error {
				if idx == 0 {
					return nil // user bind OK
				}
				return &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("down")}
			},
		)
		l := newAuthLDAPper(ac)

		_, err := l.CheckUserCredentials("alice", "alice-pass")
		if !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("errors.Is(%v, ErrNotAuthenticated) = false", err)
		}
		if l.connection != nil {
			t.Fatalf("connection must be closed after rebind failure")
		}
		// Subsequent operation must fail with ErrClosed.
		if _, err := l.GetUser("alice", baseDN); !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})
}
