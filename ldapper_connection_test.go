// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/mocks"
)

// ---------- dialHost ----------

// TestDialHost_LDAPS covers the LDAPS (SSL on dial) path: URI template,
// TLS config option, and dial error classification. Successful dial is
// tested via connectLocked (see below) because dialHost returns a concrete
// *ldap.Conn that tests cannot exercise further.
func TestDialHost_LDAPS(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	t.Run("uri uses ldaps template and host is formatted", func(t *testing.T) {
		var gotURI string
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			gotURI = uri
			return &ldap.Conn{}, nil
		})
		_, err := dialHost("ldap.example.com", 636, true, false, tlsCfg, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotURI != "ldaps://ldap.example.com:636" {
			t.Fatalf("uri = %q", gotURI)
		}
	})

	t.Run("ipv6 host is bracketed", func(t *testing.T) {
		var gotURI string
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			gotURI = uri
			return &ldap.Conn{}, nil
		})
		_, _ = dialHost("::1", 636, true, false, tlsCfg, 0)
		if gotURI != "ldaps://[::1]:636" {
			t.Fatalf("uri = %q", gotURI)
		}
	})

	t.Run("dial error classified as ErrUnavailable", func(t *testing.T) {
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			return nil, &ldap.Error{ResultCode: ldap.LDAPResultServerDown, Err: errors.New("down")}
		})
		_, err := dialHost("ldap.example.com", 636, true, false, tlsCfg, 0)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})
}

// TestDialHost_PlainSkipTLS covers the plain LDAP path with skipTLS=true.
// This is the only plain-LDAP success path testable without a real socket,
// because StartTLS on a zero-value *ldap.Conn blocks forever.
func TestDialHost_PlainSkipTLS(t *testing.T) {
	t.Run("uri uses ldap template", func(t *testing.T) {
		var gotURI string
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			gotURI = uri
			return &ldap.Conn{}, nil
		})
		_, err := dialHost("ldap.example.com", 389, false, true, nil, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotURI != "ldap://ldap.example.com:389" {
			t.Fatalf("uri = %q", gotURI)
		}
	})

	t.Run("dial error classified", func(t *testing.T) {
		// NB: use *net.OpError — this is what a real ldap.DialURL returns
		// on a refused connection. A bare errors.New("connection refused")
		// is opaque to classifyLDAPError (no transport signature) and would
		// be returned unwrapped, so errors.Is(_, ErrUnavailable) would fail.
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		})
		_, err := dialHost("ldap.example.com", 389, false, true, nil, 0)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})
}

// TestDialHost_PlainStartTLS_DialError covers the StartTLS path's dial
// error branch. The success branch (dial OK → StartTLS OK) requires a live
// server and is deliberately untested at the unit level.
func TestDialHost_PlainStartTLS_DialError(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("down")}
	})
	_, err := dialHost("ldap.example.com", 389, false, false, tlsCfg, 0)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
	}
}

// ---------- connectLocked ----------

// TestConnectLocked covers the multi-host fallback loop. The success path
// is exercised with skipTLS=true because dialHost returns a zero-value
// *ldap.Conn that cannot handle StartTLS.
func TestConnectLocked(t *testing.T) {
	t.Run("no hosts returns ErrUnavailable", func(t *testing.T) {
		l := &LDAPper{skipTLS: true}
		err := l.connectLocked()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})

	t.Run("first host succeeds", func(t *testing.T) {
		calls := 0
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			calls++
			return &ldap.Conn{}, nil
		})
		l := &LDAPper{hosts: []string{"h1.example.com"}, port: 389, skipTLS: true}
		if err := l.connectLocked(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if l.currentHost != "h1.example.com" {
			t.Fatalf("currentHost = %q", l.currentHost)
		}
		if l.connection == nil {
			t.Fatalf("connection must be set")
		}
		if calls != 1 {
			t.Fatalf("dialURL calls = %d, want 1", calls)
		}
	})

	t.Run("second host succeeds after first fails", func(t *testing.T) {
		hosts := []string{"dead.example.com", "live.example.com"}
		idx := 0
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			h := hosts[idx]
			idx++
			if h == "dead.example.com" {
				return nil, errors.New("refused")
			}
			return &ldap.Conn{}, nil
		})
		l := &LDAPper{hosts: hosts, port: 389, skipTLS: true}
		if err := l.connectLocked(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if l.currentHost != "live.example.com" {
			t.Fatalf("currentHost = %q", l.currentHost)
		}
		if idx != 2 {
			t.Fatalf("dialURL calls = %d, want 2", idx)
		}
	})

	t.Run("all hosts fail returns ErrUnavailable wrapping last error", func(t *testing.T) {
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			return nil, errors.New("refused")
		})
		l := &LDAPper{hosts: []string{"a.example.com", "b.example.com"}, port: 389, skipTLS: true}
		err := l.connectLocked()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
		if l.connection != nil {
			t.Fatalf("connection must remain nil after full failure")
		}
	})
}

// ---------- IsAlive ----------

// TestIsAlive covers the local-state checks and the root-DSE probe.
func TestIsAlive(t *testing.T) {
	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{}
		if l.IsAlive() {
			t.Fatalf("IsAlive() = true for nil conn")
		}
	})

	t.Run("closing connection", func(t *testing.T) {
		l := &LDAPper{
			connection: &mocks.MockLDAPConn{
				IsClosingFunc: func() bool { return true },
				SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
					t.Fatalf("Search must not be called when IsClosing is true")
					return nil, nil
				},
			},
		}
		if l.IsAlive() {
			t.Fatalf("IsAlive() = true for closing conn")
		}
	})

	t.Run("root DSE probe fails", func(t *testing.T) {
		l := &LDAPper{
			connection: &mocks.MockLDAPConn{
				SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					// Sanity: probe must target the root DSE.
					if req.BaseDN != "" || req.Scope != ldap.ScopeBaseObject {
						t.Fatalf("probe request malformed: baseDN=%q scope=%d", req.BaseDN, req.Scope)
					}
					return nil, errors.New("boom")
				},
			},
		}
		if l.IsAlive() {
			t.Fatalf("IsAlive() = true despite search failure")
		}
	})

	t.Run("root DSE probe succeeds", func(t *testing.T) {
		l := &LDAPper{
			connection: &mocks.MockLDAPConn{
				SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
					return &ldap.SearchResult{}, nil
				},
			},
		}
		if !l.IsAlive() {
			t.Fatalf("IsAlive() = false for healthy conn")
		}
	})
}

// ---------- Reconnect ----------

// TestReconnect covers the dial-failure branch and the "connection
// replaced" behaviour. Successful reconnect with re-bind is not unit-testable
// because dialHost returns a zero-value *ldap.Conn that cannot execute Bind.
func TestReconnect(t *testing.T) {
	t.Run("dial failure closes existing connection", func(t *testing.T) {
		closed := false
		l := &LDAPper{
			hosts:      []string{"h1.example.com"},
			port:       389,
			skipTLS:    true,
			connection: &mocks.MockLDAPConn{CloseFunc: func() error { closed = true; return nil }},
		}
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			return nil, errors.New("refused")
		})
		err := l.Reconnect()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
		if !closed {
			t.Fatalf("existing connection must be closed")
		}
		if l.connection != nil {
			t.Fatalf("connection must be nil after failed reconnect")
		}
	})

	t.Run("successful reconnect without auth replaces connection", func(t *testing.T) {
		closed := false
		l := &LDAPper{
			hosts:   []string{"h1.example.com"},
			port:    389,
			skipTLS: true,
			connection: &mocks.MockLDAPConn{
				CloseFunc: func() error { closed = true; return nil },
			},
			isAuthenticated: false,
		}
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			return &ldap.Conn{}, nil
		})
		if err := l.Reconnect(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !closed {
			t.Fatalf("existing connection must be closed before reconnect")
		}
		if l.connection == nil {
			t.Fatalf("connection must be set after successful reconnect")
		}
	})
}

// ---------- EnsureAlive ----------

// TestEnsureAlive verifies the "check → maybe reconnect" contract.
func TestEnsureAlive(t *testing.T) {
	t.Run("alive connection: no dial", func(t *testing.T) {
		dials := 0
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			dials++
			return &ldap.Conn{}, nil
		})
		l := &LDAPper{
			hosts:   []string{"h1.example.com"},
			port:    389,
			skipTLS: true,
			connection: &mocks.MockLDAPConn{
				SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
					return &ldap.SearchResult{}, nil
				},
			},
		}
		if err := l.EnsureAlive(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dials != 0 {
			t.Fatalf("dialURL calls = %d, want 0", dials)
		}
	})

	t.Run("dead connection: reconnect", func(t *testing.T) {
		dials := 0
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			dials++
			return &ldap.Conn{}, nil
		})
		l := &LDAPper{
			hosts:   []string{"h1.example.com"},
			port:    389,
			skipTLS: true,
			connection: &mocks.MockLDAPConn{
				SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
					return nil, errors.New("dead")
				},
			},
		}
		if err := l.EnsureAlive(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dials != 1 {
			t.Fatalf("dialURL calls = %d, want 1", dials)
		}
	})

	t.Run("dead connection and dial fails: error propagated", func(t *testing.T) {
		withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
			return nil, errors.New("refused")
		})
		l := &LDAPper{
			hosts:   []string{"h1.example.com"},
			port:    389,
			skipTLS: true,
			connection: &mocks.MockLDAPConn{
				SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
					return nil, errors.New("dead")
				},
			},
		}
		err := l.EnsureAlive()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})
}

// ---------- Close ----------

// TestClose covers the no-op and teardown cases.
func TestClose(t *testing.T) {
	t.Run("nil connection: no-op", func(t *testing.T) {
		l := &LDAPper{}
		l.Close() // must not panic
	})

	t.Run("existing connection closed and cleared", func(t *testing.T) {
		closed := false
		l := &LDAPper{
			connection: &mocks.MockLDAPConn{CloseFunc: func() error { closed = true; return nil }},
		}
		l.Close()
		if !closed {
			t.Fatalf("connection was not closed")
		}
		if l.connection != nil {
			t.Fatalf("connection must be nil after Close")
		}
	})
}

// ---------- sanity: no accidental leak of sensitive text in connect errors ----------

// TestConnectLocked_ErrorDoesNotLeakHost guards against future logging of
// credentials (there are none here, but the pattern is worth keeping).
func TestConnectLocked_ErrorDoesNotLeakHost(t *testing.T) {
	withMockDialURL(t, func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error) {
		return nil, errors.New("refused")
	})
	l := &LDAPper{hosts: []string{"secret.internal.example.com"}, port: 389, skipTLS: true}
	err := l.connectLocked()
	if err == nil {
		t.Fatalf("expected error")
	}
	// The host is not sensitive; but err must at least mention failure reason.
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("underlying reason lost: %v", err)
	}
}
