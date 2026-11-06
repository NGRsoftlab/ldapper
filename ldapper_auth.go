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

// restoreServiceBindLocked re-binds as the cached service principal. On
// failure it closes the connection and invalidates auth state so that no
// subsequent operation runs under an unverified identity. Returns nil on
// success.
func (ldapper *LDAPper) restoreServiceBindLocked() error {
	err := ldapper.withTimeout(ldapper.opTimeouts.Bind, func() error {
		return ldapper.connection.Bind(ldapper.bindUser, ldapper.bindPassword)
	})
	if err == nil {
		return nil
	}
	_ = ldapper.connection.Close()
	ldapper.connection = nil
	ldapper.invalidateAuthLocked()
	return classifySensitiveBindError(err)
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

	// Ask the adapter how to present the login as a bind principal. The
	// returned string is a DN or an accepted AD-style principal — it is
	// NOT filter-escaped (that is only for filter values).
	bindUsername, err := ldapper.catalogAdapter.BindIdentity(username, baseDN)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}

	// Bind with the adapter-supplied principal. A failed Bind invalidates
	// cached state; a failed post-bind lookup closes the connection.
	if err := ldapper.withTimeout(ldapper.opTimeouts.Bind, func() error {
		return ldapper.connection.Bind(bindUsername, password)
	}); err != nil {
		ldapper.invalidateAuthLocked()
		return nil, classifySensitiveBindError(err)
	}

	// Verify the bind principal by applying the adapter's user filter to
	// the ORIGINAL login. The adapter's SearchUserFilterTemplate must
	// accept every form it accepts in BindIdentity (see shipped adapters).
	user, err := ldapper.getUserLocked(username, baseDN)
	if err != nil {
		_ = ldapper.connection.Close()
		ldapper.connection = nil
		ldapper.invalidateAuthLocked()
		return nil, err
	}

	ldapper.isAuthenticated = true
	// Cache the *bind* principal — it is what Reconnect and the deferred
	// rebind inside CheckUserCredentials must replay.
	ldapper.bindUser = bindUsername
	ldapper.bindPassword = password
	ldapper.bindDN = baseDN

	return user, nil
}

// CheckUserCredentials verifies a user's password by binding as that user and
// then restoring the service bind. Can only be used on an authenticated
// connection whose bind user has read access to the directory.
// NB: can not be used with non-authenticated conn or with non-read-access-granted bindUser in conn cfg
func (ldapper *LDAPper) CheckUserCredentials(username, password string) (*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if err := ldapper.requireAuthLocked(); err != nil {
		return nil, err
	}
	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: empty username/password", ErrInvalidArgument)
	}

	user, err := ldapper.getUserLocked(username, ldapper.bindDN)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Hide user existence.
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	bindErr := ldapper.withTimeout(ldapper.opTimeouts.Bind, func() error {
		return ldapper.connection.Bind(user.DN, password)
	})

	// Restore service session regardless of the user-bind outcome.
	restoreErr := ldapper.restoreServiceBindLocked()

	switch {
	case bindErr != nil && restoreErr != nil:
		// Both failed. Preserve the credential failure as primary (masking),
		// note the rebind failure for diagnostics.
		return nil, fmt.Errorf("%w (additionally: %v)",
			classifySensitiveBindError(bindErr), restoreErr)
	case bindErr != nil:
		return nil, classifySensitiveBindError(bindErr)
	case restoreErr != nil:
		return nil, fmt.Errorf("%w: failed to restore service bind", ErrNotAuthenticated)
	}

	return user, nil
}
