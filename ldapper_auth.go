// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"fmt"

	"github.com/NGRsoftlab/ldapper/types"
)

// invalidateAuthLocked clears every piece of cached authentication state.
// Caller must hold opMu.
//
// Rationale: a failed Bind (RFC 4513) transitions the LDAP session to
// anonymous; a successful Bind whose post-bind user lookup failed leaves the
// session identified as an unverified principal. In both cases the cached
// service-session state no longer describes the live connection and must be
// reset so that requireAuthLocked() rejects subsequent operations until the
// caller re-authenticates explicitly.
//
// The base DN (bindDN) is intentionally preserved: it is the caller-supplied
// search scope, not a credential, and is required if AuthenticateConn is
// invoked again on the same object.
func (ldapper *LDAPper) invalidateAuthLocked() {
	ldapper.isAuthenticated = false
	ldapper.bindUser = ""
	ldapper.bindPassword = ""
}

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

	// Bind check. On any failure the live LDAP session is no longer
	// trustworthy — RFC 4513 transitions the connection to anonymous
	// on a failed Bind. Invalidate cached auth state so requireAuthLocked()
	// protects subsequent operations instead of letting them run anonymously.
	if err := ldapper.connection.Bind(username, password); err != nil {
		// NB: do not wrap the raw error — it may contain credentials.
		ldapper.invalidateAuthLocked()
		return nil, classifySensitiveBindError(err)
	}

	user, err := ldapper.getUserLocked(username, baseDN)
	if err != nil {
		// Bind succeeded, but the post-bind lookup did not. The connection
		// is now identified as an unverified principal, and any cached state
		// from a previous AuthenticateConn describes a different session.
		// Invalidate so callers cannot silently operate under an unexpected
		// identity.
		ldapper.invalidateAuthLocked()
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
		// Rebind failed — the session is no longer the verified service one.
		// Invalidate cached credentials so subsequent operations fail closed.
		ldapper.invalidateAuthLocked()

		if err == nil {
			user = nil
			err = fmt.Errorf("%w: failed to restore service bind", ErrNotAuthenticated)
			return
		}
		err = fmt.Errorf("%w (additionally: failed to restore service bind: %v)",
			err, classifySensitiveBindError(errRebind))
	}()

	if err = ldapper.connection.Bind(user.DN, password); err != nil {
		// NB: do not wrap the raw error — it may contain credentials.
		return nil, classifySensitiveBindError(err)
	}

	return user, nil
}
