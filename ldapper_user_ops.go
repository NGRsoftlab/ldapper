// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

// GetUser returns the user matching username inside baseDN.
// Returns ErrNotFoundOrNotVisible if no entry matches — the user may
// either not exist or be hidden by ACL. Never infer "user does not
// exist" from this error in security-sensitive code.
func (ldapper *LDAPper) GetUser(username, baseDN string) (*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getUserLocked(username, baseDN)
}

// getUserLocked searches for a single user by login. Caller must hold opMu.
func (ldapper *LDAPper) getUserLocked(username, baseDN string) (*types.LDAPUser, error) {
	attrs := ldapper.catalogAdapter.UserAttrs()

	entry, err := ldapper.searchSingleEntryLocked(
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
// Returns ErrNotFoundOrNotVisible if the user lookup yields no entries
// (not present or not visible to the bind identity).
func (ldapper *LDAPper) GetUserGroups(username, baseDN string) ([]string, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getUserGroupsLocked(username, baseDN)
}

// NB: return list of user groups DNs
func (ldapper *LDAPper) getUserGroupsLocked(username, baseDN string) ([]string, error) {
	user, err := ldapper.getUserLocked(username, baseDN)
	if err != nil {
		return nil, err
	}

	filter := fmt.Sprintf(
		ldapper.catalogAdapter.SearchUserGroupsFilterTemplate(),
		escapeFilterArgs(ldapper.catalogAdapter.SearchUserGroupsFilterTemplateArgs(*user))...,
	)

	// NB: "1.1" tells the server to return only the DN; all we need here.
	entries, err := ldapper.searchPaged(
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

	// Resolve the primary group if the adapter supports it
	if resolver, ok := ldapper.catalogAdapter.(interfaces.PrimaryGroupResolver); ok {
		var primaryGroupDN string

		resolveErr := ldapper.withTimeout(ldapper.opTimeouts.Search, func() error {
			var err error
			primaryGroupDN, err = resolver.ResolvePrimaryGroupDN(*user, ldapper.connection)
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

func (ldapper *LDAPper) GetOUUsers(ouDN string) ([]*types.LDAPUser, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getOUUsersLocked(ouDN)
}

func (ldapper *LDAPper) getOUUsersLocked(ouDN string) ([]*types.LDAPUser, error) {
	if err := ldapper.requireConnLocked(); err != nil {
		return nil, err
	}

	filter := ldapper.catalogAdapter.UserObjectFilter()
	attributes := ldapper.catalogAdapter.UserAttrs()

	if err := validateBaseDN(ouDN); err != nil {
		return nil, err
	}

	entries, err := ldapper.searchPaged(
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
