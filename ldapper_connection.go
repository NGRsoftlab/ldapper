// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
)

// DialFunc is a seam for tests.
type DialFunc func(ctx context.Context, host string, port uint,
	useSSL, skipTLS bool, tlsCfg *tls.Config, timeout time.Duration) (*ldap.Conn, error)

var dialConn DialFunc = dialHost

// withCtx runs fn with:
//   - an effective deadline = min(opTimeout, ctx.Deadline - now);
//   - a watchdog that closes the underlying connection if ctx is cancelled
//     before fn returns (go-ldap has no context-aware Bind/StartTLS).
//
// If the watchdog fires, the connection is published as unusable:
// subsequent operations return ErrClosed until Reconnect/EnsureAlive.
// Caller must hold opMu.
func (ldapper *LDAPper) withCtx(ctx context.Context, opTimeout time.Duration, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if ldapper.connection == nil {
		return fmt.Errorf("%w: connection not initialized", ErrClosed)
	}

	conn := ldapper.connection

	effTimeout := opTimeout
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		if effTimeout <= 0 || remaining < effTimeout {
			effTimeout = remaining
		}
	}

	if effTimeout > 0 {
		conn.SetTimeout(effTimeout)
	}

	var (
		cancelled atomic.Bool
		stopWatch chan struct{}
		watchDone chan struct{}
	)
	if ctx.Done() != nil {
		stopWatch = make(chan struct{})
		watchDone = make(chan struct{})
		go func() {
			defer close(watchDone)
			select {
			case <-ctx.Done():
				cancelled.Store(true)
				_ = conn.Close() // unblocks pending read
			case <-stopWatch:
			}
		}()
	}

	err := fn()

	if stopWatch != nil {
		close(stopWatch)
		<-watchDone
	}
	if effTimeout > 0 {
		conn.SetTimeout(0)
	}

	if cancelled.Load() {
		if ldapper.connection == conn {
			ldapper.connection = nil
			ldapper.invalidateAuthLocked()
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ctx.Err(), err)
		}
	}
	return err
}

func (ldapper *LDAPper) withCtxResult(ctx context.Context, opTimeout time.Duration, fn func() (*ldap.SearchResult, error)) (*ldap.SearchResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if ldapper.connection == nil {
		return nil, fmt.Errorf("%w: connection not initialized", ErrClosed)
	}

	conn := ldapper.connection

	effTimeout := opTimeout
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		if effTimeout <= 0 || remaining < effTimeout {
			effTimeout = remaining
		}
	}

	if effTimeout > 0 {
		conn.SetTimeout(effTimeout)
	}

	var (
		cancelled atomic.Bool
		stopWatch chan struct{}
		watchDone chan struct{}
	)
	if ctx.Done() != nil {
		stopWatch = make(chan struct{})
		watchDone = make(chan struct{})
		go func() {
			defer close(watchDone)
			select {
			case <-ctx.Done():
				cancelled.Store(true)
				_ = conn.Close() // unblocks pending read
			case <-stopWatch:
			}
		}()
	}

	res, err := fn()

	if stopWatch != nil {
		close(stopWatch)
		<-watchDone
	}
	if effTimeout > 0 {
		conn.SetTimeout(0)
	}

	if cancelled.Load() {
		if ldapper.connection == conn {
			ldapper.connection = nil
			ldapper.invalidateAuthLocked()
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ctx.Err(), err)
		}
	}

	return res, err
}

// connectLocked tries every configured host and stores the first successful
// connection. Caller must hold opMu (or be inside the constructor, before
// the object is published).
func (ldapper *LDAPper) connectLocked(ctx context.Context) error {
	c, host, err := ldapper.dialAnyLocked(ctx)
	if err != nil {
		return err
	}
	ldapper.connection = c
	ldapper.currentHost = host
	return nil
}

// dialAnyLocked tries every configured host and returns the first successful
// dial. The connection is NOT published on ldapper — the caller owns
// publication. This lets reconnectLocked verify Bind (when required) before
// exposing the connection to other methods.
func (ldapper *LDAPper) dialAnyLocked(ctx context.Context) (interfaces.LDAPConn, string, error) {
	var lastErr error
	for _, host := range ldapper.hosts {
		c, err := dialConn(ctx, host, ldapper.port, ldapper.useSSL, ldapper.skipTLS,
			ldapper.tlsCfg, ldapper.dialTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		return c, host, nil
	}
	if lastErr == nil {
		return nil, "", fmt.Errorf("%w: no hosts available", ErrUnavailable)
	}
	return nil, "", fmt.Errorf("%w: unsuccessful dial to any host: %w", ErrUnavailable, lastErr)
}

// dialHost establishes a single LDAP connection to the given host.
func dialHost(ctx context.Context, host string, port uint,
	useSSL, skipTLS bool, tlsCfg *tls.Config, timeout time.Duration,
) (*ldap.Conn, error) {
	addr := net.JoinHostPort(formatHost(host), strconv.FormatUint(uint64(port), 10))
	dialer := &net.Dialer{Timeout: timeout}

	if useSSL {
		td := &tls.Dialer{Config: tlsCfg, NetDialer: dialer}
		raw, err := td.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dial: %w", classifyLDAPError(err))
		}
		conn := ldap.NewConn(raw, true)
		conn.Start()
		return conn, nil
	}

	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", classifyLDAPError(err))
	}
	conn := ldap.NewConn(raw, false)
	conn.Start()

	if skipTLS {
		return conn, nil
	}

	// StartTLS: same hybrid approach as withCtx, but the conn is not yet
	// published, so closing on cancel is safe.
	tlsTimeout := timeout
	if tlsTimeout <= 0 {
		tlsTimeout = constants.DefaultStartTLSTimeout
	}
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining <= 0 {
			_ = conn.Close()
			return nil, context.DeadlineExceeded
		}
		if remaining < tlsTimeout {
			tlsTimeout = remaining
		}
	}

	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	var cancelled atomic.Bool
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			cancelled.Store(true)
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	conn.SetTimeout(tlsTimeout)
	err = conn.StartTLS(tlsCfg)
	close(stopWatch)
	<-watchDone
	conn.SetTimeout(0)

	if cancelled.Load() {
		return nil, fmt.Errorf("%w: start tls cancelled", ctx.Err())
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("start tls: %w", classifyLDAPError(err))
	}
	return conn, nil
}

// IsAlive reports whether the underlying LDAP connection is still usable.
// Returns false after Close() — a closed client cannot be revived via
// EnsureAlive (see ErrClosed).
// It first checks the local state and then performs a lightweight round-trip
// by querying the root DSE (works for every LDAP server and does not require auth).
// NB: although RFC 4512 does not require objectClass on the root DSE,
// all mainstream servers accept it; we rely on this to keep the probe minimal.
func (ldapper *LDAPper) IsAlive(ctx context.Context) bool {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.isAliveLocked(ctx)
}

func (ldapper *LDAPper) isAliveLocked(ctx context.Context) bool {
	if ldapper.connection == nil {
		return false
	}
	if ldapper.connection.IsClosing() {
		return false
	}

	// NB: size/time limits are hardcoded to 1 — the probe is intentionally
	// independent of connection-level searchLimits so that a user-configured
	// large TimeLimit does not make EnsureAlive block on a slow server.
	req := ldap.NewSearchRequest(
		"", // root DSE
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, // size limit
		1, // time limit (seconds)
		false,
		"(objectClass=*)", // NB: hopefully, objectClass is universal for different adapters
		[]string{"namingContexts"},
		nil,
	)

	_, err := ldapper.withCtxResult(ctx, ldapper.opTimeouts.Search, func() (*ldap.SearchResult, error) {
		return ldapper.connection.Search(req)
	})

	return err == nil
}

// Reconnect closes the current connection and tries to establish a new one
// against any of the configured hosts. If the previous connection was
// authenticated, the stored bind credentials are re-applied — and if the
// rebind fails, the new connection is closed and the cached auth state is
// invalidated (subsequent operations return ErrClosed until AuthenticateConn
// is called again).
func (ldapper *LDAPper) Reconnect(ctx context.Context) error {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.reconnectLocked(ctx)
}

func (ldapper *LDAPper) reconnectLocked(ctx context.Context) error {
	if ldapper.closed {
		return fmt.Errorf("%w: client is closed", ErrClosed)
	}

	if ldapper.connection != nil {
		_ = ldapper.connection.Close()
		ldapper.connection = nil
	}

	// Dial but DO NOT publish: the new connection is not yet known to be
	// usable. Publication happens only after Bind (when required) succeeds.
	c, host, err := ldapper.dialAnyLocked(ctx)
	if err != nil {
		return err
	}

	if ldapper.isAuthenticated {
		bindTimeout := ldapper.opTimeouts.Bind
		if bindTimeout <= 0 {
			bindTimeout = constants.DefaultDialTimeout // или отдельная константа
		}
		if dl, ok := ctx.Deadline(); ok {
			remaining := time.Until(dl)
			if remaining <= 0 {
				_ = c.Close()
				ldapper.invalidateAuthLocked()
				return context.DeadlineExceeded
			}
			if remaining < bindTimeout {
				bindTimeout = remaining
			}
		}

		stopWatch := make(chan struct{})
		watchDone := make(chan struct{})
		var cancelled atomic.Bool
		if ctx.Done() != nil {
			go func() {
				defer close(watchDone)
				select {
				case <-ctx.Done():
					cancelled.Store(true)
					_ = c.Close()
				case <-stopWatch:
				}
			}()
		}

		c.SetTimeout(bindTimeout)
		err := c.Bind(ldapper.bindUser, ldapper.bindPassword)
		c.SetTimeout(0)
		if ctx.Done() != nil {
			close(stopWatch)
			<-watchDone
		}

		if cancelled.Load() || err != nil {
			_ = c.Close()
			ldapper.invalidateAuthLocked()
			if cancelled.Load() {
				return ctx.Err()
			}
			return classifySensitiveBindError(err)
		}
	}

	// Every required step succeeded — publish.
	ldapper.connection = c
	ldapper.currentHost = host
	return nil
}

// EnsureAlive checks liveness and reconnects when the connection is stale.
// Can be used by callers before performing operations on the connection.
// If ctx is cancelled during the liveness probe, the underlying connection
// is discarded and cached credentials are invalidated.
// Call EnsureAlive with a live context and re-authenticate afterwards.
func (ldapper *LDAPper) EnsureAlive(ctx context.Context) error {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if ldapper.closed {
		return fmt.Errorf("%w: client is closed", ErrClosed)
	}
	if ldapper.isAliveLocked(ctx) {
		return nil
	}
	return ldapper.reconnectLocked(ctx)
}

func (ldapper *LDAPper) Close() {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if ldapper.closed {
		return // idempotent: Close after Close is a no-op
	}
	ldapper.closed = true

	if ldapper.connection != nil {
		_ = ldapper.connection.Close()
		ldapper.connection = nil
	}
	ldapper.invalidateAuthLocked()
}
