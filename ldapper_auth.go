// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"fmt"

	"github.com/NGRsoftlab/ldapper/types"
)

// AuthenticateConn binds as the service user and caches its credentials for
// later reconnect and per-user checks. See CheckUserCredentials for verifying
// an arbitrary user without disturbing the service session.
// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
func (ldapper *LDAPper) AuthenticateConn(username, password, baseDN string) (*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.authenticateConnLocked(username, password, baseDN)
}

func (ldapper *LDAPper) authenticateConnLocked(username, password, baseDN string) (*types.LDAPUser, error) {
	if err := ldapper.requireConnLocked(); err != nil {
		return nil, err
	}

	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: empty bind username/password", ErrInvalidArgument)
	}

	if err := validateBaseDN(baseDN); err != nil {
		return nil, err
	}

	// bind check
	if err := ldapper.connection.Bind(username, password); err != nil {
		// NB: do not wrap the raw error — it may contain credentials.
		return nil, classifySensitiveBindError(err)
	}

	user, err := ldapper.getUserLocked(username, baseDN)
	if err != nil {
		return nil, err
	}

	ldapper.isAuthenticated = true
	ldapper.bindUser = username
	ldapper.bindPassword = password
	ldapper.bindDN = baseDN

	return user, nil
}

// CheckUserCredentials verifies a user's password by binding as that user and
// then restoring the service bind. Can only be used on an authenticated
// connection whose bind user has read access to the directory.
// NB: can not be used with non-authenticated conn or with non-read-access-granted bindUser in conn cfg
func (ldapper *LDAPper) CheckUserCredentials(username, password string) (user *types.LDAPUser, err error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if err := ldapper.requireAuthLocked(); err != nil {
		return nil, err
	}

	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: empty username/password", ErrInvalidArgument)
	}

	user, err = ldapper.getUserLocked(username, ldapper.bindDN)
	if err != nil {
		// NB: hide user existence — a missing user must be indistinguishable
		// from a wrong password for the caller.
		if errors.Is(err, ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	defer func() {
		// NB: rebind back with the service user; the connection is anonymous
		// until this succeeds.
		errRebind := ldapper.connection.Bind(ldapper.bindUser, ldapper.bindPassword)
		if errRebind == nil {
			return
		}
		ldapper.isAuthenticated = false

		if err == nil {
			// User bind succeeded but service session was lost.
			user = nil
			err = fmt.Errorf("%w: failed to restore service bind", ErrNotAuthenticated)
			return
		}
		// NB: keep the primary error first so errors.Is(err, ...) keeps working.
		err = fmt.Errorf("%w (additionally: failed to restore service bind: %v)",
			err, classifySensitiveBindError(errRebind))
	}()

	if err = ldapper.connection.Bind(user.DN, password); err != nil {
		// NB: do not wrap the raw error — it may contain credentials.
		return nil, classifySensitiveBindError(err)
	}

	return user, nil
}
