// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

// GetUser returns the user matching username inside baseDN.
// Returns ErrNotFoundOrNotVisible if no entry matches — the user may
// either not exist or be hidden by ACL. Never infer "user does not
// exist" from this error in security-sensitive code.
func (ldapper *LDAPper) GetUser(ctx context.Context, username, baseDN string) (*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getUserLocked(ctx, username, baseDN)
}

// getUserLocked searches for a single user by login. Caller must hold opMu.
func (ldapper *LDAPper) getUserLocked(ctx context.Context, username, baseDN string) (*types.LDAPUser, error) {
	attrs := ldapper.catalogAdapter.UserAttrs()

	entry, err := ldapper.searchSingleEntryLocked(
		ctx,
		kindUser, username, baseDN,
		ldapper.catalogAdapter.SearchUserFilterTemplate(), attrs,
	)
	if err != nil {
		return nil, err
	}

	return &types.LDAPUser{
		DN:         entry.DN,
		Attributes: attrsToMap(entry, attrs),
	}, nil
}

// GetUserGroups returns DNs of all groups the given user belongs to.
//
// For MSAD, this function resolves the user's primary group (via
// primaryGroupID) by:
//  1. finding the nearest domainDNS ancestor of the user's DN (this
//     also returns the domain's objectSid),
//  2. computing the group's SID from domain SID + primaryGroupID,
//  3. searching for a group with that objectSid.
//
// This adds up to 3 additional LDAP round-trips per call (1-2 for the
// domainDNS ancestor lookup, 1 for the primary group lookup). The domain
// SID is NOT cached — for bulk operations against the same domain,
// consider caching at the caller level.
//
// Returns ErrNotFoundOrNotVisible if the user lookup yields no entries
// (not present or not visible to the bind identity).
//
// # Timeout semantics of PrimaryGroupResolver
//
// When the adapter implements PrimaryGroupResolver (e.g. MSADAdapter),
// the resolver is invoked inside a single withCtx call that applies
// opTimeouts.Search to the entire resolver invocation. That timeout is
// applied via LDAPConn.SetTimeout, so it bounds each individual Bind /
// Search the resolver issues on the supplied connection — it does NOT
// bound the resolver's total wall-clock time. A resolver doing N
// sequential LDAP round-trips can take up to N * opTimeouts.Search.
//
// The only reliable total-limit mechanism is a deadline on ctx: use
// context.WithTimeout around the GetUserGroups call when a hard
// end-to-end bound is required. This is by design — the resolver owns
// its own multi-step logic, and a per-request timeout keeps a single
// slow server response from stalling the whole thing, without
// re-implementing a scheduler here.
func (ldapper *LDAPper) GetUserGroups(ctx context.Context, username, baseDN string) ([]string, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getUserGroupsLocked(ctx, username, baseDN)
}

// NB: return list of user groups DNs
func (ldapper *LDAPper) getUserGroupsLocked(ctx context.Context, username, baseDN string) ([]string, error) {
	user, err := ldapper.getUserLocked(ctx, username, baseDN)
	if err != nil {
		return nil, err
	}

	args := escapeFilterArgs(ldapper.catalogAdapter.SearchUserGroupsFilterTemplateArgs(*user))
	filter, err := renderFilterTemplate(kindGroup,
		ldapper.catalogAdapter.SearchUserGroupsFilterTemplate(), args)
	if err != nil {
		return nil, err
	}

	// NB: "1.1" tells the server to return only the DN; all we need here.
	entries, err := ldapper.searchPaged(
		ctx,
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false,
		filter, []string{"1.1"}, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("user groups search: %w", classifyLDAPError(err))
	}

	groups := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries)) // Deduplication map
	for _, entry := range entries {
		if _, dup := seen[entry.DN]; dup {
			continue
		}
		seen[entry.DN] = struct{}{}
		groups = append(groups, entry.DN)
	}

	// Resolve the primary group if the adapter supports it.
	//
	// Per-request timeout: withCtx applies opTimeouts.Search to the whole
	// resolver call via LDAPConn.SetTimeout, so each individual Bind /
	// Search inside the resolver is bounded by that value. See the
	// GetUserGroups doc comment for the per-request-vs-total distinction.
	if resolver, ok := ldapper.catalogAdapter.(interfaces.PrimaryGroupResolver); ok {
		var primaryGroupDN string

		resolveErr := ldapper.withCtx(ctx, ldapper.opTimeouts.Search, func() error {
			var err error
			primaryGroupDN, err = resolver.ResolvePrimaryGroupDN(ctx, *user, ldapper.connection)
			return err
		})

		if resolveErr != nil {
			return nil, fmt.Errorf("resolve primary group: %w", resolveErr)
		}

		if primaryGroupDN != "" {
			if _, exists := seen[primaryGroupDN]; !exists {
				groups = append(groups, primaryGroupDN)
			}
		}
	}

	return groups, nil
}

func (ldapper *LDAPper) GetOUUsers(ctx context.Context, ouDN string) ([]*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getOUUsersLocked(ctx, ouDN)
}

func (ldapper *LDAPper) getOUUsersLocked(ctx context.Context, ouDN string) ([]*types.LDAPUser, error) {
	if err := ldapper.requireConnLocked(); err != nil {
		return nil, err
	}

	filter := ldapper.catalogAdapter.UserObjectFilter()
	attributes := ldapper.catalogAdapter.UserAttrs()

	if err := validateBaseDN(ouDN); err != nil {
		return nil, err
	}

	entries, err := ldapper.searchPaged(
		ctx,
		ouDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false,
		filter, attributes, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("ou users search: %w", classifyLDAPError(err))
	}

	res := make([]*types.LDAPUser, 0, len(entries))
	for _, entry := range entries {
		res = append(res, &types.LDAPUser{
			DN:         entry.DN,
			Attributes: attrsToMap(entry, attributes),
		})
	}

	return res, nil
}
