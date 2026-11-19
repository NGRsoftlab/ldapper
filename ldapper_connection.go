// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
)

// DialFunc is a seam for tests.
type DialFunc func(ctx context.Context, host string, port uint,
	useLDAPS, skipStartTLS bool, tlsCfg *tls.Config, timeout time.Duration) (*ldap.Conn, error)

var dialConn DialFunc = dialHost

// --- watchdog primitives ---

// timeoutCloser is the subset of LDAPConn used by the watchdog and by
// runWithWatchdog. Both *ldap.Conn and mocks.MockLDAPConn satisfy it.
type timeoutCloser interface {
	SetTimeout(time.Duration)
	Close() error
}

// watchdog represents a running watchdog goroutine. Nil when ctx has no
// Done channel; stopWatchdog is a no-op in that case.
type watchdog struct {
	stop chan struct{}
	done chan struct{}
}

// startWatchdog launches a goroutine that closes conn when ctx is
// cancelled. Returns nil when ctx has no Done channel (Background/TODO).
// The caller MUST stop the watchdog via stopWatchdog (usually deferred)
// before touching conn again; otherwise a late ctx cancellation could
// close a connection the caller is already using.
func startWatchdog(ctx context.Context, conn io.Closer) *watchdog {
	if ctx.Done() == nil {
		return nil
	}
	wd := &watchdog{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go func() {
		defer close(wd.done)
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblocks pending read
		case <-wd.stop:
		}
	}()
	return wd
}

// stopWatchdog waits for the goroutine to exit. Safe with a nil receiver.
func stopWatchdog(wd *watchdog) {
	if wd == nil {
		return
	}
	close(wd.stop)
	<-wd.done
}

// runWithWatchdog is the shared execution primitive behind withCtx /
// withCtxResult / StartTLS / reconnect-bind. It:
//   - applies conn.SetTimeout(effTimeout) before fn (when effTimeout > 0)
//     and resets it to zero afterwards;
//   - starts a watchdog that closes conn on ctx cancellation;
//   - stops and waits for the watchdog in a defer, so a panic in fn cannot
//     leak the goroutine or leave a stale timeout on the connection.
//
// It does NOT inspect ctx.Err(): the caller decides whether to keep the
// connection and how to interpret the result. Keeping that decision out of
// the helper lets the same primitive be reused for connection-lifecycle
// operations (dialHost, reconnectLocked) where invalidation state differs.
func runWithWatchdog(ctx context.Context, conn timeoutCloser, effTimeout time.Duration, fn func() error) error {
	if effTimeout > 0 {
		conn.SetTimeout(effTimeout)
	}
	wd := startWatchdog(ctx, conn)
	defer func() {
		stopWatchdog(wd)
		if effTimeout > 0 {
			conn.SetTimeout(0)
		}
	}()
	return fn()
}

// --- withCtx family ---

// withCtxCore is the shared body of withCtx and withCtxResult. It runs fn
// under runWithWatchdog, then applies the cancellation policy shared by
// every operation:
//   - if ctx was cancelled mid-flight, the connection is published as
//     unusable (connection = nil, invalidateAuthLocked) and the operation
//     returns a wrapped error combining ctxErr with fn's error (if any);
//   - otherwise fn's result is passed through unchanged.
//
// Caller must hold opMu.
func withCtxCore[T any](
	ldapper *LDAPper,
	ctx context.Context,
	opTimeout time.Duration,
	fn func() (T, error),
) (T, error) {
	var zero T

	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if ldapper.connection == nil {
		return zero, fmt.Errorf("%w: connection not initialized", ErrClosed)
	}

	conn := ldapper.connection

	effTimeout := opTimeout
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return zero, context.DeadlineExceeded
		}
		if effTimeout <= 0 || remaining < effTimeout {
			effTimeout = remaining
		}
	}

	var res T
	err := runWithWatchdog(ctx, conn, effTimeout, func() error {
		var e error
		res, e = fn()
		return e
	})

	// ctx.Err() is the source of truth for "was the operation aborted":
	// the watchdog goroutine may not have run yet when fn returns, so
	// relying on a flag it sets is racy. ctx.Err() is set synchronously
	// by cancel()/deadline and cannot lag.
	if ctxErr := ctx.Err(); ctxErr != nil {
		if ldapper.connection == conn {
			// Close is idempotent; the watchdog may or may not have
			// already closed the connection depending on timing.
			_ = conn.Close()
			ldapper.connection = nil
			ldapper.invalidateAuthLocked()
		}
		if err != nil {
			return zero, fmt.Errorf("%w: %w", ctxErr, err)
		}
		// fn reported success, but ctx was cancelled. Do not let the
		// caller see a false success for an aborted operation.
		return zero, ctxErr
	}
	return res, err
}

// withCtx runs fn with the cancellation-aware timeout/watchdog discipline
// shared by all operations. Caller must hold opMu.
//
// If the watchdog fires (ctx cancelled), the connection is published as
// unusable (connection = nil, invalidateAuthLocked) so that subsequent
// operations return ErrClosed until Reconnect / EnsureAlive.
func (ldapper *LDAPper) withCtx(ctx context.Context, opTimeout time.Duration, fn func() error) error {
	_, err := withCtxCore[struct{}](ldapper, ctx, opTimeout, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

// withCtxResult is the search-result flavour of withCtx. See withCtx for
// the cancellation contract. Caller must hold opMu.
func (ldapper *LDAPper) withCtxResult(ctx context.Context, opTimeout time.Duration, fn func() (*ldap.SearchResult, error)) (*ldap.SearchResult, error) {
	return withCtxCore[*ldap.SearchResult](ldapper, ctx, opTimeout, fn)
}

// --- connection management ---

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
//
// ctx cancellation is honoured between hosts: once the caller aborts,
// remaining hosts are skipped instead of being dialed in vain.
func (ldapper *LDAPper) dialAnyLocked(ctx context.Context) (interfaces.LDAPConn, string, error) {
	var lastErr error
	for _, host := range ldapper.hosts {
		// Dialing a dead host can be slow; there is no point starting the
		// next attempt once the caller has aborted.
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		c, err := dialConn(ctx, host, ldapper.port, ldapper.useLDAPS, ldapper.skipStartTLS,
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
	useLDAPS, skipStartTLS bool, tlsCfg *tls.Config, timeout time.Duration,
) (*ldap.Conn, error) {
	addr := net.JoinHostPort(formatHost(host), strconv.FormatUint(uint64(port), 10))
	dialer := &net.Dialer{Timeout: timeout}

	if useLDAPS {
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

	if skipStartTLS {
		return conn, nil
	}

	// StartTLS: the connection is not yet published, so closing on
	// cancellation cannot affect other operations.
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

	err = runWithWatchdog(ctx, conn, tlsTimeout, func() error {
		return conn.StartTLS(tlsCfg)
	})

	// ctx.Err() is the source of truth for cancellation: the watchdog
	// goroutine may not have run yet when StartTLS returns, so a flag
	// it writes would be racy. ctx.Err() is set synchronously by
	// cancel()/deadline and cannot lag.
	if ctxErr := ctx.Err(); ctxErr != nil {
		// Close is idempotent. This also covers the case where StartTLS
		// returned success while the watchdog did not fire — without
		// this close the connection would leak.
		_ = conn.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: start tls: %w", ctxErr, err)
		}
		return nil, fmt.Errorf("%w: start tls cancelled", ctxErr)
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
// invalidated (subsequent operations return ErrClosed until BindConn
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

	// A cancelled ctx after a successful dial means the caller aborted:
	// do not publish, and skip the Bind (its watchdog would fire
	// immediately and close the fresh connection anyway).
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = c.Close()
		return ctxErr
	}

	if ldapper.isAuthenticated {
		// opTimeouts.Bind == 0 means "no client-side Bind timeout" — the
		// same contract as withCtx / withCtxResult. The dial itself is
		// still bounded by ldapper.dialTimeout (applied inside dialHost),
		// so a dead peer cannot block the reconnect indefinitely.
		bindTimeout := ldapper.opTimeouts.Bind
		if dl, ok := ctx.Deadline(); ok {
			remaining := time.Until(dl)
			if remaining <= 0 {
				_ = c.Close()
				ldapper.invalidateAuthLocked()
				return context.DeadlineExceeded
			}
			if bindTimeout <= 0 || remaining < bindTimeout {
				bindTimeout = remaining
			}
		}

		bindErr := runWithWatchdog(ctx, c, bindTimeout, func() error {
			return c.Bind(ldapper.bindUser, ldapper.bindPassword)
		})

		// ctx.Err() is authoritative, not any flag written by the
		// watchdog (that write races with fn returning). A successful
		// Bind on a cancelled context still means the caller aborted:
		// publishing the connection would run subsequent operations
		// under a principal the caller no longer wants to be bound as.
		if ctxErr := ctx.Err(); ctxErr != nil || bindErr != nil {
			_ = c.Close()
			ldapper.invalidateAuthLocked()
			if ctxErr != nil {
				return ctxErr
			}
			return classifySensitiveBindError(bindErr)
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
