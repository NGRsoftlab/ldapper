// Copyright 2020-2026 NGR Softlab
// Package ldapper provides a thin, opinionated LDAP client with pluggable
// catalog adapters (AldPro, FreeIPA, MSAD, OpenLDAP). ...
package ldapper

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

var dialURL = ldap.DialURL

type LDAPper struct {
	opMu sync.Mutex // serializes all operations touching the LDAP connection
	// and mutable state; go-ldap connections are not safe
	// for concurrent use, and multi-step operations (paged
	// search, bind+rebind) must be atomic.

	// mutable (guarded by opMu)
	connection      interfaces.LDAPConn
	isAuthenticated bool
	closed          bool // set by Close; terminal — no reconnect allowed
	bindUser        string
	bindPassword    string
	bindDN          string
	currentHost     string
	searchLimits    SearchLimits
	dialTimeout     time.Duration // 0 = no explicit timeout (Go default)
	opTimeouts      OperationTimeouts

	// immutable after construction
	catalogAdapter interfaces.CatalogAdapter
	hosts          []string
	port           uint
	useSSL         bool
	skipTLS        bool
	tlsCfg         *tls.Config
}

// NB: supports many host alternatives. Max hosts length is capped at
// constants.DefaultMaxHostsLength to reject pathological inputs (e.g.
// a caller programmatically generating a huge host list) before we
// attempt sequential dialing against each.
// NB: use WithSearchLimits(...) to override default size/time limits for all search requests.
// NB: use WithDialTimeout(...) to override default dial timeout for connect/reconnect.
// NB: skipTLS only affects plain LDAP connections: when false, StartTLS is
// performed after Dial; when true, the connection stays in cleartext.
// For LDAPS (useSSL=true) the flag has no effect.
// NB: use useSSL=false with skipTLS=true only for dev/test purposes, not production
func NewLDAPper(
	hosts []string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter interfaces.CatalogAdapter,
	opts ...Option) (*LDAPper, error) {

	if len(hosts) == 0 {
		return nil, fmt.Errorf("%w: empty hosts list", ErrInvalidArgument)
	}

	if len(hosts) > constants.DefaultMaxHostsLength {
		return nil, fmt.Errorf("%w: too many hosts (%d > %d)",
			ErrInvalidArgument, len(hosts), constants.DefaultMaxHostsLength)
	}

	for _, host := range hosts {
		if err := validateHost(host); err != nil {
			return nil, err
		}
	}

	// NewLDAPper, right after len(hosts) checks.
	if port == 0 || port > 65535 {
		return nil, fmt.Errorf("%w: invalid port %d", ErrInvalidArgument, port)
	}

	if useSSL && skipTLS {
		return nil, fmt.Errorf("%w: skipTLS has no effect with useSSL", ErrInvalidArgument)
	}

	if tlsCfg == nil && !skipTLS {
		return nil, fmt.Errorf("%w: nil tls config", ErrInvalidArgument)
	}

	if catalogAdapter == nil {
		return nil, fmt.Errorf("%w: nil catalog adapter", ErrInvalidArgument)
	}

	var clonedTLSCfg *tls.Config
	if tlsCfg != nil {
		clonedTLSCfg = tlsCfg.Clone()
	}

	ldapper := &LDAPper{
		catalogAdapter: catalogAdapter,
		hosts:          append([]string(nil), hosts...), // defensive copy
		port:           port,
		useSSL:         useSSL,
		skipTLS:        skipTLS,
		tlsCfg:         clonedTLSCfg,
		searchLimits:   DefaultSearchLimits(),
		dialTimeout:    constants.DefaultDialTimeout,
		opTimeouts:     OperationTimeouts{}, // 0/0 = disabled (backwards compatible)
	}

	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: nil option", ErrInvalidArgument)
		}
		opt(ldapper)
	}

	// NB: object is not published yet — no concurrent access is possible.
	if err := ldapper.connectLocked(); err != nil {
		return nil, err
	}

	return ldapper, nil
}

// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
// NB: hosts and TLS config are validated and copied by NewLDAPper; see its
// doc comment for the host count limit and TLS mode semantics.
// NB: use WithSearchLimits(...) to override default size/time limits for all search requests.
// NB: use WithDialTimeout(...) to override default dial timeout for connect/reconnect.
// NB: use useSSL=false with skipTLS=true only for dev/test purposes, not production
func NewAuthenticatedLDAPper(
	username, password, baseDN string,
	hosts []string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter interfaces.CatalogAdapter,
	opts ...Option) (*LDAPper, *types.LDAPUser, error) {

	if username == "" || password == "" {
		return nil, nil, fmt.Errorf("%w: empty bind username/password", ErrInvalidArgument)
	}

	ldapper, err := NewLDAPper(hosts, port, useSSL, skipTLS, tlsCfg, catalogAdapter, opts...)
	if err != nil {
		return nil, nil, err
	}

	user, err := ldapper.AuthenticateConn(username, password, baseDN)
	if err != nil {
		ldapper.Close()
		return nil, nil, err
	}

	return ldapper, user, nil
}
