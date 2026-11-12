// Package ldapper provides a thin, opinionated LDAP client with pluggable
// catalog adapters (AldPro, FreeIPA, MSAD, OpenLDAP). ...
// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
)

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
	useLDAPS       bool
	skipStartTLS   bool
	tlsCfg         *tls.Config
}

// NB: supports many host alternatives. Max hosts length is capped at
// constants.DefaultMaxHostsLength to reject pathological inputs (e.g.
// a caller programmatically generating a huge host list) before we
// attempt sequential dialing against each.
// NB: use WithSearchLimits(...) to override default size/time limits for all search requests.
// NB: use WithDialTimeout(...) to override default dial timeout for connect/reconnect.
// NB: skipStartTLS only affects plain LDAP connections: when false, StartTLS is
// performed after Dial; when true, the connection stays in cleartext.
// For LDAPS (useLDAPS=true) the flag has no effect.
// NB: use useLDAPS=false with skipStartTLS=true only for dev/test purposes, not production
func NewLDAPper(
	ctx context.Context,
	hosts []string,
	port uint,
	useLDAPS bool,
	skipStartTLS bool,
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

	if useLDAPS && skipStartTLS {
		return nil, fmt.Errorf("%w: skipStartTLS has no effect with useLDAPS", ErrInvalidArgument)
	}

	if tlsCfg == nil && !skipStartTLS {
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
		useLDAPS:       useLDAPS,
		skipStartTLS:   skipStartTLS,
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
	if err := ldapper.connectLocked(ctx); err != nil {
		return nil, err
	}

	return ldapper, nil
}

// NewAuthenticatedLDAPper dials a host and binds as `username`, then
// verifies the connection by probing `baseDN` with a base-object search.
// No post-bind user lookup is performed: any principal accepted by the
// adapter's BindIdentity is accepted as long as baseDN is reachable
// under it. No user entry is returned — call GetUser afterwards if you
// need the full entry.
//
// `username` and `baseDN` are cached for later CheckUserCredentials calls.
//
// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
// NB: hosts and TLS config are validated and copied by NewLDAPper; see its
// doc comment for the host count limit and TLS mode semantics.
// NB: use WithSearchLimits(...) to override default size/time limits for all search requests.
// NB: use WithDialTimeout(...) to override default dial timeout for connect/reconnect.
func NewAuthenticatedLDAPper(
	ctx context.Context,
	username, password, baseDN string,
	hosts []string,
	port uint,
	useLDAPS bool,
	skipStartTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter interfaces.CatalogAdapter,
	opts ...Option) (*LDAPper, error) {

	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: empty bind username/password", ErrInvalidArgument)
	}

	ldapper, err := NewLDAPper(ctx, hosts, port, useLDAPS, skipStartTLS, tlsCfg, catalogAdapter, opts...)
	if err != nil {
		return nil, err
	}

	err = ldapper.BindConn(ctx, username, password, baseDN)
	if err != nil {
		ldapper.Close()
		return nil, err
	}

	return ldapper, nil
}
