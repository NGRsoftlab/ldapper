// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
)

// connectLocked tries every configured host and stores the first successful
// connection. Caller must hold opMu (or be inside the constructor, before
// the object is published).
func (ldapper *LDAPper) connectLocked() error {
	var lastErr error

	for _, host := range ldapper.hosts {
		c, err := dialHost(host, ldapper.port, ldapper.useSSL, ldapper.skipTLS, ldapper.tlsCfg, ldapper.dialTimeout)
		if err != nil {
			lastErr = err
			continue
		}

		ldapper.connection = c
		ldapper.currentHost = host
		return nil
	}

	if lastErr == nil {
		return fmt.Errorf("%w: no hosts available", ErrUnavailable)
	}

	return fmt.Errorf("%w: unsuccessful dial to any host: %w", ErrUnavailable, lastErr)
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
		return nil, fmt.Errorf("unsuccessful dial: %w", classifyLDAPError(err))
	}

	if !useSSL && !skipTLS {
		// NB: StartTLS performs the handshake on the already-open socket,
		// so the dial timeout must be reapplied here, then reset afterwards
		// to avoid capping regular operations.
		if dialTimeout > 0 {
			connection.SetTimeout(dialTimeout)
		}
		if err = connection.StartTLS(tlsCfg); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("unsuccessful start tls: %w", classifyLDAPError(err))
		}
		if dialTimeout > 0 {
			connection.SetTimeout(0)
		}
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

	if _, err := ldapper.connection.Search(req); err != nil {
		return false
	}

	return true
}

// Reconnect closes the current connection and tries to establish a new one
// against any of the configured hosts. If the previous connection was
// authenticated, the stored bind credentials are re-applied.
func (ldapper *LDAPper) Reconnect() error {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.reconnectLocked()
}

func (ldapper *LDAPper) reconnectLocked() error {
	if ldapper.connection != nil {
		_ = ldapper.connection.Close()
		ldapper.connection = nil
	}

	if err := ldapper.connectLocked(); err != nil {
		return err
	}

	if ldapper.isAuthenticated {
		if err := ldapper.connection.Bind(ldapper.bindUser, ldapper.bindPassword); err != nil {
			// Rebind failure means the freshly-dialed connection cannot be
			// treated as a service session — invalidate cached credentials.
			ldapper.invalidateAuthLocked()
			// NB: do not wrap the raw error — it may contain credentials.
			return classifySensitiveBindError(err)
		}
	}

	return nil
}

// EnsureAlive checks liveness and reconnects when the connection is stale.
// Can be used by callers before performing operations on the connection.
func (ldapper *LDAPper) EnsureAlive() error {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if ldapper.isAliveLocked() {
		return nil
	}
	return ldapper.reconnectLocked()
}

func (ldapper *LDAPper) Close() {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if ldapper.connection == nil {
		return
	}
	_ = ldapper.connection.Close()
	ldapper.connection = nil
	ldapper.invalidateAuthLocked()
}
