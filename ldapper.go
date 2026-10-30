// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

var dialURL = ldap.DialURL

// SearchLimits holds default LDAP search request limits.
// SizeLimit == 0 means "no size limit" (server default).
// TimeLimit == 0 means "no time limit" (server default).
type SearchLimits struct {
	SizeLimit int
	TimeLimit int
}

// Option configures optional LDAPper parameters.
type Option func(*LDAPper)

type LDAPper struct {
	catalogAdapter interfaces.CatalogAdapter
	connection     interfaces.LDAPConn

	isAuthenticated bool

	bindUser     string
	bindPassword string

	hosts       []string
	currentHost string
	port        uint

	useSSL  bool
	skipTLS bool
	tlsCfg  *tls.Config

	searchLimits SearchLimits
}

// TODO: pass controlable ctx into connection creator to break dial if smth is not ok (or break by timeout)
// NB: suports many host alternatives, max hosts lenght = constants.DefaultMaxHostsLength (need it for 1mln same hosts protection, etc.)
// NB: use WithSearchLimits(...) to override default size/time limits for all search requests.
func NewConnection(
	hosts []string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter interfaces.CatalogAdapter,
	opts ...Option) (*LDAPper, error) {

	if len(hosts) == 0 {
		return nil, errors.New("empty hosts list passed")
	}

	if len(hosts) > constants.DefaultMaxHostsLength {
		return nil, errors.New("too many hosts passed")
	}

	if tlsCfg == nil && (!skipTLS || useSSL) {
		return nil, errors.New("nil tls config passed")
	}

	if catalogAdapter == nil {
		return nil, errors.New("nil catalog adapter passed")
	}

	conn := &LDAPper{
		catalogAdapter: catalogAdapter,
		hosts:          hosts,
		port:           port,
		useSSL:         useSSL,
		skipTLS:        skipTLS,
		tlsCfg:         tlsCfg,
		searchLimits: SearchLimits{
			SizeLimit: constants.DefaultSearchSizeLimit,
			TimeLimit: constants.DefaultSearchTimeLimit,
		},
	}

	for _, opt := range opts {
		opt(conn)
	}

	if err := conn.connect(); err != nil {
		return nil, err
	}

	return conn, nil
}

// TODO: pass controlable ctx into connection creator to break dial if smth is not ok (or break by timeout)
// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
// NB: suports many host alternatives, max hosts lenght = constants.DefaultMaxHostsLength (need it for 1mln same hosts protection, etc.)
// NB: use WithSearchLimits(...) to override default size/time limits for all search requests.
func NewAuthenticatedConnection(
	username, password, baseDN string,
	hosts []string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter interfaces.CatalogAdapter,
	opts ...Option) (*LDAPper, *types.LDAPUser, error) {

	if username == "" || password == "" {
		return nil, nil, errors.New("empty bind username/password passed")
	}

	connection, err := NewConnection(hosts, port, useSSL, skipTLS, tlsCfg, catalogAdapter, opts...)
	if err != nil {
		return nil, nil, err
	}

	user, err := connection.AuthenticateConn(username, password, baseDN)
	if err != nil {
		connection.Close()
		return nil, nil, err
	}

	return connection, user, nil
}

// connect tries every configured host and stores the first successful connection.
func (conn *LDAPper) connect() error {
	var lastErr error

	for _, host := range conn.hosts {
		c, err := dialHost(host, conn.port, conn.useSSL, conn.skipTLS, conn.tlsCfg)
		if err != nil {
			lastErr = err
			continue
		}

		conn.connection = c
		conn.currentHost = host
		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("no hosts available")
	}

	return fmt.Errorf("unsuccessful dial to any host: %w", lastErr)
}

// dialHost establishes a single LDAP connection to the given host.
func dialHost(host string, port uint, useSSL, skipTLS bool, tlsCfg *tls.Config) (*ldap.Conn, error) {
	var connection *ldap.Conn
	var err error

	if !useSSL {
		connection, err = dialURL(fmt.Sprintf(constants.LDAPURITemplate, host, port))
		if err != nil {
			return nil, fmt.Errorf("unsuccessful dial: %s", err.Error())
		}

		if !skipTLS {
			if err = connection.StartTLS(tlsCfg); err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("unsuccessful start tls: %s", err.Error())
			}
		}
	} else {
		connection, err = dialURL(fmt.Sprintf(constants.LDAPSURITemplate, host, port), ldap.DialWithTLSConfig(tlsCfg))
		if err != nil {
			return nil, fmt.Errorf("unsuccessful dial: %s", err.Error())
		}
	}

	return connection, nil
}

// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
func (conn *LDAPper) AuthenticateConn(username, password, baseDN string) (*types.LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	if username == "" || password == "" {
		return nil, errors.New("empty bind username/password passed")
	}

	// bind check
	err := conn.connection.Bind(username, password)
	if err != nil {
		// NB: no err value return - it can contain sensitive data
		return nil, errors.New("unsuccessful bind with passed bind credentials")
	}

	// user is ok check
	// TODO: think if we need dn instead of username for bind user cfg
	user, err := conn.GetUser(username, baseDN)
	if err != nil {
		return nil, err
	}

	conn.isAuthenticated = true
	conn.bindUser = username
	conn.bindPassword = password

	return user, nil
}

// NB: can not be used with non-authenticated conn or with non-read-access-granted bindUser in conn cfg
func (conn *LDAPper) AuthenticateUser(username, password, baseDN string) (*types.LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	if !conn.isAuthenticated {
		return nil, errors.New("connection not authenticated")
	}

	if username == "" || password == "" {
		return nil, errors.New("empty username/password passed")
	}

	// user is ok check
	user, err := conn.GetUser(username, baseDN)
	if err != nil {
		return nil, err
	}

	// bind check
	err = conn.connection.Bind(user.DN, password)
	if err != nil {
		// NB: no err value return - it can contain sensitive data
		return user, errors.New("unsuccessful bind with passed user credentials")
	}

	// rebind onto potentially ok access granted bind user
	err = conn.connection.Bind(conn.bindUser, conn.bindPassword)
	if err != nil {
		// NB: no err value return - it can contain sensitive data
		return user, errors.New("unsuccessful rebind with bind-config credentials")
	}

	return user, nil
}

// IsAlive reports whether the underlying LDAP connection is still usable.
// It first checks the local state and then performs a lightweight round-trip
// by querying the root DSE (works for every LDAP server and does not require auth)
func (conn *LDAPper) IsAlive() bool {
	if conn.connection == nil {
		return false
	}

	if conn.connection.IsClosing() {
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

	if _, err := conn.connection.Search(req); err != nil {
		return false
	}

	return true
}

// Reconnect closes the current connection and tries to establish a new one
// against any of the configured hosts. If the previous connection was
// authenticated, the stored bind credentials are re-applied.
func (conn *LDAPper) Reconnect() error {
	if conn.connection != nil {
		_ = conn.connection.Close()
		conn.connection = nil
	}

	if err := conn.connect(); err != nil {
		return err
	}

	if conn.isAuthenticated {
		if err := conn.connection.Bind(conn.bindUser, conn.bindPassword); err != nil {
			// NB: no err value return - it can contain sensitive data
			return errors.New("unsuccessful rebind after reconnect")
		}
	}

	return nil
}

// EnsureAlive checks liveness and reconnects when the connection is stale.
// Can be used by callers before performing operations on the connection.
func (conn *LDAPper) EnsureAlive() error {
	if conn.IsAlive() {
		return nil
	}
	return conn.Reconnect()
}

func (conn *LDAPper) Close() {
	if conn.connection != nil {
		err := conn.connection.Close()
		conn.connection = nil
		if err != nil {
			return
		}
	}
}
