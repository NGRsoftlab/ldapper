// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
)

// withTimeout runs fn with the given client-side timeout applied to the
// LDAP connection. The timeout is set before the call and reset to zero
// afterwards regardless of the result, so it cannot silently cap subsequent
// operations. If timeout <= 0, fn is called without touching the socket.
//
// Caller must hold opMu (or be inside a path where the connection is
// exclusively owned, e.g. constructor).
func (ldapper *LDAPper) withTimeout(timeout time.Duration, fn func() error) error {
	if timeout <= 0 {
		return fn()
	}
	ldapper.connection.SetTimeout(timeout)
	defer ldapper.connection.SetTimeout(0)
	return fn()
}

func (ldapper *LDAPper) withTimeoutResult(timeout time.Duration, fn func() (*ldap.SearchResult, error)) (*ldap.SearchResult, error) {
	if timeout <= 0 {
		return fn()
	}
	ldapper.connection.SetTimeout(timeout)
	defer ldapper.connection.SetTimeout(0)
	return fn()
}

// connectLocked tries every configured host and stores the first successful
// connection. Caller must hold opMu (or be inside the constructor, before
// the object is published).
func (ldapper *LDAPper) connectLocked() error {
	c, host, err := ldapper.dialAnyLocked()
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
func (ldapper *LDAPper) dialAnyLocked() (interfaces.LDAPConn, string, error) {
	var lastErr error
	for _, host := range ldapper.hosts {
		c, err := dialHost(host, ldapper.port, ldapper.useSSL, ldapper.skipTLS,
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
func dialHost(host string, port uint, useSSL, skipTLS bool, tlsCfg *tls.Config, dialTimeout time.Duration) (*ldap.Conn, error) {
	dialOpts := make([]ldap.DialOpt, 0, 2)
	if dialTimeout > 0 {
		dialOpts = append(dialOpts, ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}))
	}
	if useSSL {
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(tlsCfg))
	}

	var uri string
	if useSSL {
		uri = fmt.Sprintf(constants.LDAPSURITemplate, formatHost(host), port)
	} else {
		uri = fmt.Sprintf(constants.LDAPURITemplate, formatHost(host), port)
	}

	connection, err := dialURL(uri, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", classifyLDAPError(err))
	}

	if !useSSL && !skipTLS {
		tlsTimeout := dialTimeout

		if tlsTimeout <= 0 {
			tlsTimeout = constants.DefaultStartTLSTimeout
		}

		connection.SetTimeout(tlsTimeout)

		if err = connection.StartTLS(tlsCfg); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("start tls: %w", classifyLDAPError(err))
		}

		connection.SetTimeout(0)
	}

	return connection, nil
}

// IsAlive reports whether the underlying LDAP connection is still usable.
// It first checks the local state and then performs a lightweight round-trip
// by querying the root DSE (works for every LDAP server and does not require auth).
// NB: although RFC 4512 does not require objectClass on the root DSE,
// all mainstream servers accept it; we rely on this to keep the probe minimal.
func (ldapper *LDAPper) IsAlive() bool {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.isAliveLocked()
}

func (ldapper *LDAPper) isAliveLocked() bool {
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

	_, err := ldapper.withTimeoutResult(ldapper.opTimeouts.Search, func() (*ldap.SearchResult, error) {
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
func (ldapper *LDAPper) Reconnect() error {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.reconnectLocked()
}

func (ldapper *LDAPper) reconnectLocked() error {
	if ldapper.closed {
		return fmt.Errorf("%w: client is closed", ErrClosed)
	}

	if ldapper.connection != nil {
		_ = ldapper.connection.Close()
		ldapper.connection = nil
	}

	// Dial but DO NOT publish: the new connection is not yet known to be
	// usable. Publication happens only after Bind (when required) succeeds.
	c, host, err := ldapper.dialAnyLocked()
	if err != nil {
		return err
	}

	if ldapper.isAuthenticated {
		if bindErr := c.Bind(ldapper.bindUser, ldapper.bindPassword); bindErr != nil {
			_ = c.Close()
			ldapper.invalidateAuthLocked()
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
func (ldapper *LDAPper) EnsureAlive() error {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if ldapper.closed {
		return fmt.Errorf("%w: client is closed", ErrClosed)
	}
	if ldapper.isAliveLocked() {
		return nil
	}
	return ldapper.reconnectLocked()
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

// TODO: add ForceClose for emergency operation stops instead of ctx realisations?
