// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/mocks"
)

// NB: tests that swap the package-level dialConn seam MUST NOT use
// t.Parallel(): the swap is process-wide and parallel tests would stomp
// on each other. All such tests are marked "no t.Parallel" inline.

// withDialConn swaps the package-level dialConn for the duration of the
// test and restores it afterwards via t.Cleanup.
func withDialConn(t *testing.T, fn DialFunc) {
	t.Helper()
	old := dialConn
	dialConn = fn
	t.Cleanup(func() { dialConn = old })
}

// ================== withCtx ==================

func TestWithCtx_CtxAlreadyCancelled(t *testing.T) {
	t.Parallel()

	fnCalled := false
	l := &LDAPper{connection: &mocks.MockLDAPConn{}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := l.withCtx(ctx, 0, func() error {
		fnCalled = true
		return nil
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, fnCalled, "fn must not be invoked when ctx is already cancelled")
}

func TestWithCtx_NilConnection(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	err := l.withCtx(context.Background(), 0, func() error { return nil })

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestWithCtx_SuccessPassesThrough(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{}
	l := &LDAPper{connection: conn}

	err := l.withCtx(context.Background(), 0, func() error { return nil })
	assert.NoError(t, err)
	// Connection is preserved on success.
	assert.Same(t, conn, l.connection)
}

func TestWithCtx_ErrorPassesThrough(t *testing.T) {
	t.Parallel()

	want := errors.New("op failed")
	conn := &mocks.MockLDAPConn{}
	l := &LDAPper{connection: conn}

	err := l.withCtx(context.Background(), 0, func() error { return want })

	assert.Equal(t, want, err)
	assert.Same(t, conn, l.connection, "no cancellation: conn must be preserved")
}

func TestWithCtx_AppliesAndResetsTimeout(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var timeouts []time.Duration
	conn := &mocks.MockLDAPConn{
		SetTimeoutFunc: func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			timeouts = append(timeouts, d)
		},
	}
	l := &LDAPper{connection: conn}

	err := l.withCtx(context.Background(), 5*time.Second, func() error { return nil })
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []time.Duration{5 * time.Second, 0}, timeouts,
		"SetTimeout must be called with the effective timeout, then reset to 0")
}

func TestWithCtx_NoTimeoutNoSetTimeoutCalls(t *testing.T) {
	t.Parallel()

	calls := 0
	conn := &mocks.MockLDAPConn{
		SetTimeoutFunc: func(time.Duration) { calls++ },
	}
	l := &LDAPper{connection: conn}

	_ = l.withCtx(context.Background(), 0, func() error { return nil })
	assert.Zero(t, calls, "SetTimeout must not be called when effTimeout == 0")
}

func TestWithCtx_CtxDeadlineCapsTimeout(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var timeouts []time.Duration
	conn := &mocks.MockLDAPConn{
		SetTimeoutFunc: func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			timeouts = append(timeouts, d)
		},
	}
	l := &LDAPper{connection: conn}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_ = l.withCtx(ctx, 10*time.Second, func() error { return nil })

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, timeouts, 2)
	assert.Greater(t, timeouts[0], time.Duration(0))
	assert.LessOrEqual(t, timeouts[0], time.Second,
		"effective timeout must be capped by ctx deadline, got %v", timeouts[0])
	assert.Equal(t, time.Duration(0), timeouts[1])
}

func TestWithCtx_DeadlineAlreadyExpired(t *testing.T) {
	t.Parallel()

	fnCalled := false
	l := &LDAPper{connection: &mocks.MockLDAPConn{}}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := l.withCtx(ctx, 5*time.Second, func() error {
		fnCalled = true
		return nil
	})

	// ctx.Err() fires before fn — the operation is not attempted at all.
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, fnCalled)
}

func TestWithCtx_CancelDuringOp_ClosesConnection(t *testing.T) {
	t.Parallel()

	connClosed := make(chan struct{})
	conn := &mocks.MockLDAPConn{
		CloseFunc: func() error { close(connClosed); return nil },
	}
	l := &LDAPper{
		connection:      conn,
		isAuthenticated: true,
		bindUser:        "u",
		bindPassword:    "p",
		bindDN:          "dc=x",
	}

	ctx, cancel := context.WithCancel(context.Background())

	err := l.withCtx(ctx, 0, func() error {
		cancel()             // trigger the watchdog
		<-connClosed         // block until the watchdog closes the conn
		return net.ErrClosed // realistic: op fails once the conn is closed
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, err, net.ErrClosed)

	// Connection invalidated, auth state cleared, bind DN preserved.
	assert.Nil(t, l.connection)
	assert.False(t, l.isAuthenticated)
	assert.Empty(t, l.bindUser)
	assert.Empty(t, l.bindPassword)
	assert.Equal(t, "dc=x", l.bindDN,
		"bindDN is a caller-supplied scope, not a credential, and must be preserved")
}

// ================== withCtxResult ==================

func TestWithCtxResult_CtxAlreadyCancelled(t *testing.T) {
	t.Parallel()

	fnCalled := false
	l := &LDAPper{connection: &mocks.MockLDAPConn{}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := l.withCtxResult(ctx, 0, func() (*ldap.SearchResult, error) {
		fnCalled = true
		return nil, nil
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, fnCalled)
}

func TestWithCtxResult_NilConnection(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	_, err := l.withCtxResult(context.Background(), 0, func() (*ldap.SearchResult, error) {
		return nil, nil
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestWithCtxResult_SuccessReturnsResult(t *testing.T) {
	t.Parallel()

	want := &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "cn=x"}}}
	l := &LDAPper{connection: &mocks.MockLDAPConn{}}

	got, err := l.withCtxResult(context.Background(), 0, func() (*ldap.SearchResult, error) {
		return want, nil
	})

	require.NoError(t, err)
	assert.Same(t, want, got)
}

func TestWithCtxResult_ErrorPropagates(t *testing.T) {
	t.Parallel()

	want := errors.New("search failed")
	l := &LDAPper{connection: &mocks.MockLDAPConn{}}

	_, err := l.withCtxResult(context.Background(), 0, func() (*ldap.SearchResult, error) {
		return nil, want
	})

	assert.Equal(t, want, err)
}

func TestWithCtxResult_CancelDuringOp_ClosesConnection(t *testing.T) {
	t.Parallel()

	connClosed := make(chan struct{})
	conn := &mocks.MockLDAPConn{
		CloseFunc: func() error { close(connClosed); return nil },
	}
	l := &LDAPper{connection: conn, isAuthenticated: true, bindUser: "u", bindPassword: "p"}

	ctx, cancel := context.WithCancel(context.Background())

	_, err := l.withCtxResult(ctx, 0, func() (*ldap.SearchResult, error) {
		cancel()
		<-connClosed
		return nil, net.ErrClosed
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, err, net.ErrClosed)
	assert.Nil(t, l.connection)
	assert.False(t, l.isAuthenticated)
}

// ================== Close ==================

func TestClose_NilConnection(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	l.Close()

	assert.True(t, l.closed)
}

func TestClose_ClosesConnectionAndInvalidatesAuth(t *testing.T) {
	t.Parallel()

	closed := false
	conn := &mocks.MockLDAPConn{CloseFunc: func() error { closed = true; return nil }}
	l := &LDAPper{
		connection:      conn,
		isAuthenticated: true,
		bindUser:        "u",
		bindPassword:    "p",
	}

	l.Close()

	assert.True(t, closed)
	assert.True(t, l.closed)
	assert.Nil(t, l.connection)
	assert.False(t, l.isAuthenticated)
	assert.Empty(t, l.bindUser)
	assert.Empty(t, l.bindPassword)
}

func TestClose_Idempotent(t *testing.T) {
	t.Parallel()

	calls := 0
	conn := &mocks.MockLDAPConn{CloseFunc: func() error { calls++; return nil }}
	l := &LDAPper{connection: conn}

	l.Close()
	l.Close()
	l.Close()

	assert.Equal(t, 1, calls, "second and subsequent Close must be a no-op")
}

// ================== isAliveLocked / IsAlive ==================

func TestIsAlive_NilConnection(t *testing.T) {
	t.Parallel()

	l := &LDAPper{}
	assert.False(t, l.IsAlive(context.Background()))
}

func TestIsAlive_ClosingConnection(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{IsClosingFunc: func() bool { return true }}
	l := &LDAPper{connection: conn}

	assert.False(t, l.IsAlive(context.Background()))
}

func TestIsAlive_ProbeSucceeds(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			assert.Equal(t, "", req.BaseDN, "probe must target the root DSE")
			return &ldap.SearchResult{}, nil
		},
	}
	l := &LDAPper{connection: conn}

	assert.True(t, l.IsAlive(context.Background()))
}

func TestIsAlive_ProbeFails(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("network error")
		},
	}
	l := &LDAPper{connection: conn}

	assert.False(t, l.IsAlive(context.Background()))
}

func TestIsAlive_UsesHardcodedProbeLimits(t *testing.T) {
	t.Parallel()

	// The probe deliberately ignores user-configured searchLimits so that
	// a large TimeLimit cannot make EnsureAlive block on a slow server.
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			assert.Equal(t, 1, req.SizeLimit, "size limit is hardcoded to 1")
			assert.Equal(t, 1, req.TimeLimit, "time limit is hardcoded to 1")
			return &ldap.SearchResult{}, nil
		},
	}
	l := &LDAPper{
		connection:   conn,
		searchLimits: SearchLimits{SizeLimit: 999, TimeLimit: 99},
	}

	assert.True(t, l.IsAlive(context.Background()))
}

// ================== EnsureAlive ==================

func TestEnsureAlive_ClosedClient(t *testing.T) {
	t.Parallel()

	l := &LDAPper{closed: true}
	err := l.EnsureAlive(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestEnsureAlive_AlreadyAlive(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}
	l := &LDAPper{connection: conn}

	err := l.EnsureAlive(context.Background())
	require.NoError(t, err)
	assert.Same(t, conn, l.connection, "no reconnect when connection is alive")
}

func TestEnsureAlive_ReconnectOnFailure(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	deadConn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("dead")
		},
		CloseFunc: func() error { return nil },
	}

	fakeConn := &ldap.Conn{}
	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return fakeConn, nil
	})

	l := &LDAPper{
		connection: deadConn,
		hosts:      []string{"h1"},
		port:       389,
	}

	err := l.EnsureAlive(context.Background())
	require.NoError(t, err)
	assert.Same(t, fakeConn, l.connection, "connection replaced on reconnect")
}

// ================== Reconnect / reconnectLocked ==================

func TestReconnect_ClosedClient(t *testing.T) {
	t.Parallel()

	l := &LDAPper{closed: true}
	err := l.Reconnect(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
	assert.Contains(t, err.Error(), "closed")
}

func TestReconnectLocked_NotAuthenticated(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	fakeConn := &ldap.Conn{}
	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return fakeConn, nil
	})

	l := &LDAPper{
		hosts:           []string{"h1"},
		port:            389,
		isAuthenticated: false,
	}

	err := l.reconnectLocked(context.Background())
	require.NoError(t, err)
	assert.Same(t, fakeConn, l.connection)
}

func TestReconnectLocked_DialFails(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return nil, errors.New("dial failed")
	})

	l := &LDAPper{
		hosts:           []string{"h1"},
		port:            389,
		isAuthenticated: true,
		bindUser:        "u",
		bindPassword:    "p",
	}

	err := l.reconnectLocked(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	// Old connection must be cleared; a failed reconnect leaves no stale conn.
	assert.Nil(t, l.connection)
}

func TestReconnectLocked_ClosesOldConnection(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	oldClosed := false
	oldConn := &mocks.MockLDAPConn{CloseFunc: func() error { oldClosed = true; return nil }}

	fakeConn := &ldap.Conn{}
	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return fakeConn, nil
	})

	l := &LDAPper{
		connection: oldConn,
		hosts:      []string{"h1"},
		port:       389,
	}

	err := l.reconnectLocked(context.Background())
	require.NoError(t, err)
	assert.True(t, oldClosed, "old connection must be closed before publishing new one")
}

// ================== connectLocked ==================

func TestConnectLocked_StoresConnectionAndHost(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	fakeConn := &ldap.Conn{}
	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return fakeConn, nil
	})

	l := &LDAPper{hosts: []string{"h1"}, port: 389}
	require.NoError(t, l.connectLocked(context.Background()))
	assert.Same(t, fakeConn, l.connection)
	assert.Equal(t, "h1", l.currentHost)
}

func TestConnectLocked_DialFails(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return nil, errors.New("fail")
	})

	l := &LDAPper{hosts: []string{"h1"}, port: 389}
	err := l.connectLocked(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.Nil(t, l.connection)
}

// ================== dialAnyLocked ==================

func TestDialAnyLocked_NoHosts(t *testing.T) {
	t.Parallel()

	// No dialConn swap needed: the loop body never runs.
	l := &LDAPper{hosts: nil}

	conn, host, err := l.dialAnyLocked(context.Background())
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Empty(t, host)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.Contains(t, err.Error(), "no hosts")
}

func TestDialAnyLocked_FirstSuccessWins(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	fakeConn := &ldap.Conn{}
	var tried []string
	withDialConn(t, func(_ context.Context, host string, _ uint, _, _ bool, _ *tls.Config, _ time.Duration) (*ldap.Conn, error) {
		tried = append(tried, host)
		return fakeConn, nil
	})

	l := &LDAPper{hosts: []string{"h1", "h2", "h3"}, port: 389}

	conn, host, err := l.dialAnyLocked(context.Background())
	require.NoError(t, err)
	assert.Same(t, fakeConn, conn)
	assert.Equal(t, "h1", host)
	assert.Equal(t, []string{"h1"}, tried, "must stop at the first successful dial")
}

func TestDialAnyLocked_FallsThroughToSecond(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	fakeConn := &ldap.Conn{}
	var tried []string
	withDialConn(t, func(_ context.Context, host string, _ uint, _, _ bool, _ *tls.Config, _ time.Duration) (*ldap.Conn, error) {
		tried = append(tried, host)
		if host == "h1" {
			return nil, errors.New("fail")
		}
		return fakeConn, nil
	})

	l := &LDAPper{hosts: []string{"h1", "h2"}, port: 389}

	conn, host, err := l.dialAnyLocked(context.Background())
	require.NoError(t, err)
	assert.Same(t, fakeConn, conn)
	assert.Equal(t, "h2", host)
	assert.Equal(t, []string{"h1", "h2"}, tried)
}

func TestDialAnyLocked_AllHostsFail(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	lastErr := errors.New("last failure")
	withDialConn(t, func(_ context.Context, host string, _ uint, _, _ bool, _ *tls.Config, _ time.Duration) (*ldap.Conn, error) {
		if host == "h2" {
			return nil, lastErr
		}
		return nil, errors.New("first failure")
	})

	l := &LDAPper{hosts: []string{"h1", "h2"}, port: 389}

	conn, host, err := l.dialAnyLocked(context.Background())
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Empty(t, host)
	assert.ErrorIs(t, err, ErrUnavailable)
	assert.ErrorIs(t, err, lastErr, "last error must be in the chain for diagnostics")
}
