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

type LDAPConnection struct {
	catalogAdapter  interfaces.CatalogAdapter
	connection      interfaces.LDAPConn
	isAuthenticated bool
	bindUser        string
	bindPassword    string
}

// TODO: add many hosts support
func NewConnection(
	host string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter interfaces.CatalogAdapter) (*LDAPConnection, error) {

	var connection *ldap.Conn
	var err error

	if tlsCfg == nil && (!skipTLS || useSSL) {
		return nil, errors.New("nil tls config passed")
	}

	if catalogAdapter == nil {
		return nil, errors.New("nil catalog adapter passed")
	}

	if !useSSL {
		connection, err = ldap.DialURL(fmt.Sprintf(constants.LDAPURITemplate, host, port))
		if err != nil {
			return nil, fmt.Errorf("unsuccessful dial: %s", err.Error())
		}

		if !skipTLS {
			err = connection.StartTLS(tlsCfg)
			if err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("unsuccessful start tls: %s", err.Error())
			}
		}
	} else {
		connection, err = ldap.DialURL(fmt.Sprintf(constants.LDAPSURITemplate, host, port), ldap.DialWithTLSConfig(tlsCfg))
		if err != nil {
			return nil, fmt.Errorf("unsuccessful dial: %s", err.Error())
		}
	}

	return &LDAPConnection{
		catalogAdapter: catalogAdapter,
		connection:     connection,
	}, nil
}

// TODO: add many hosts support
// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
func NewAuthenticatedConnection(
	username, password, baseDN string,
	host string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter interfaces.CatalogAdapter) (*LDAPConnection, *types.LDAPUser, error) {

	if username == "" || password == "" {
		return nil, nil, errors.New("empty username/password passed")
	}

	connection, err := NewConnection(host, port, useSSL, skipTLS, tlsCfg, catalogAdapter)
	if err != nil {
		return nil, nil, err
	}

	user, err := connection.AuthenticateConn(username, password, baseDN)
	if err != nil {
		return nil, nil, err
	}

	return connection, user, nil
}

// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
func (conn *LDAPConnection) AuthenticateConn(username, password, baseDN string) (*types.LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
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
		return user, errors.New("unsuccessful bind with passed bind credentials")
	}

	conn.isAuthenticated = true
	conn.bindUser = user.DN
	conn.bindPassword = password

	return user, nil
}

// NB: can not be used with non-authenticated conn or with non-read-access-granted bindUser in conn cfg
func (conn *LDAPConnection) AuthenticatedUser(username, password, baseDN string) (*types.LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	if !conn.isAuthenticated {
		return nil, errors.New("connection not authenticated")
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

	// rebind onto read access granted bind user
	err = conn.connection.Bind(conn.bindUser, conn.bindPassword)
	if err != nil {
		// NB: no err value return - it can contain sensitive data
		return user, errors.New("unsuccessful rebind with bind-config credentials")
	}

	return user, nil
}

func (conn *LDAPConnection) Close() {
	if conn.connection != nil {
		err := conn.connection.Close()
		conn.connection = nil
		if err != nil {
			return
		}
	}
}
