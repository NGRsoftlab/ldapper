// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"

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
// search scope, not a credential, and is required if BindConn is
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
func (ldapper *LDAPper) restoreServiceBindLocked(ctx context.Context) error {
	err := ldapper.withCtx(ctx, ldapper.opTimeouts.Bind, func() error {
		return ldapper.connection.Bind(ldapper.bindUser, ldapper.bindPassword)
	})
	if err == nil {
		return nil
	}
	if ldapper.connection != nil {
		_ = ldapper.connection.Close()
		ldapper.connection = nil
	}
	ldapper.invalidateAuthLocked()

	if errors.Is(err, ErrClosed) {
		return ErrNotAuthenticated
	}

	return classifySensitiveBindError(err)
}

// BindConn binds as the service user and caches its credentials for
// later reconnect and per-user checks. See CheckUserCredentials for
// verifying an arbitrary user without disturbing the service session.
//
// Post-bind verification does not perform a user lookup: any principal
// accepted by BindIdentity (UPN, sAMAccountName, DN — not necessarily an
// entry matching UserObjectFilter, e.g. simpleSecurityObject service
// accounts) is accepted as long as baseDN is reachable under the bound
// identity.
//
// The returned *types.LDAPUser carries the bind principal in DN and has
// empty Attributes. For OpenLDAP/FreeIPA DN is a real DN; for MSAD/ALDPro
// it may be a UPN or sAMAccountName. Callers that need the user entry
// must call GetUser separately.
func (ldapper *LDAPper) BindConn(ctx context.Context, username, password, baseDN string) (*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.bindConnLocked(ctx, username, password, baseDN)
}

func (ldapper *LDAPper) bindConnLocked(ctx context.Context, username, password, baseDN string) (*types.LDAPUser, error) {
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
	// cached state; a failed post-bind verification closes the connection.
	if err := ldapper.withCtx(ctx, ldapper.opTimeouts.Bind, func() error {
		return ldapper.connection.Bind(bindUsername, password)
	}); err != nil {
		if ldapper.connection != nil {
			_ = ldapper.connection.Close()
			ldapper.connection = nil
		}
		ldapper.invalidateAuthLocked()
		return nil, classifySensitiveBindError(err)
	}

	// Verify the bind is usable by probing baseDN. This intentionally
	// replaces the previous post-bind user lookup: service accounts
	// (simpleSecurityObject, AD service principals) often do not match
	// UserObjectFilter, but the base DN is still readable under them.
	if err := ldapper.verifyBaseDNLocked(ctx, baseDN); err != nil {
		if ldapper.connection != nil {
			_ = ldapper.connection.Close()
			ldapper.connection = nil
		}
		ldapper.invalidateAuthLocked()
		return nil, err
	}

	ldapper.isAuthenticated = true
	// Cache the *bind* principal — it is what Reconnect and the deferred
	// rebind inside CheckUserCredentials must replay.
	ldapper.bindUser = bindUsername
	ldapper.bindPassword = password
	ldapper.bindDN = baseDN

	// The returned user carries only the bind principal; attributes are
	// empty because no lookup was issued. See the BindConn doc comment.
	return &types.LDAPUser{DN: bindUsername}, nil
}

// CheckUserCredentials verifies a user's password by binding as that user and
// then restoring the service bind. Can only be used on an authenticated
// connection whose bind user has read access to the directory.
// NB: can not be used with non-authenticated conn or with non-read-access-granted bindUser in conn cfg
func (ldapper *LDAPper) CheckUserCredentials(ctx context.Context, username, password string) (*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if err := ldapper.requireAuthLocked(); err != nil {
		return nil, err
	}
	if username == "" || password == "" {
		return nil, fmt.Errorf("%w: empty username/password", ErrInvalidArgument)
	}

	user, err := ldapper.getUserLocked(ctx, username, ldapper.bindDN)
	if err != nil {
		if errors.Is(err, ErrNotFoundOrNotVisible) {
			// Hide user existence — missing user must look like a wrong password.
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	bindErr := ldapper.withCtx(ctx, ldapper.opTimeouts.Bind, func() error {
		return ldapper.connection.Bind(user.DN, password)
	})

	// Restore service session regardless of the user-bind outcome.
	restoreErr := ldapper.restoreServiceBindLocked(ctx)

	switch {
	case bindErr != nil && restoreErr != nil:
		if errors.Is(bindErr, context.Canceled) {
			return nil, bindErr // cancel — not credential failure
		}

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

// verifyBaseDNLocked checks that baseDN exists and is readable under the
// currently bound identity. Uses ScopeBaseObject so the server resolves
// exactly one entry — a definitive "base is present and accessible".
// Caller must hold opMu.
func (ldapper *LDAPper) verifyBaseDNLocked(ctx context.Context, baseDN string) error {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, // base-object returns at most one entry; hardcoded cap
		ldapper.searchLimits.TimeLimit,
		false,
		"(objectClass=*)",
		[]string{"1.1"}, // no attributes: DN-only probe
		nil,
	)

	res, err := ldapper.withCtxResult(ctx, ldapper.opTimeouts.Search, func() (*ldap.SearchResult, error) {
		return ldapper.connection.Search(req)
	})
	if err != nil {
		return fmt.Errorf("base DN probe: %w", classifyLDAPError(err))
	}
	if len(res.Entries) == 0 {
		return fmt.Errorf("%w: base DN %q not found or not visible",
			ErrNotFoundOrNotVisible, baseDN)
	}
	return nil
}
