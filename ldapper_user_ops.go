// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

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
		return nil, fmt.Errorf("unsuccessful user groups search: %w", classifyLDAPError(err))
	}

	groups := make([]string, 0, len(entries))
	for _, entry := range entries {
		groups = append(groups, entry.DN)
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
		return nil, fmt.Errorf("unsuccessful ou users search: %w", classifyLDAPError(err))
	}

	res := make([]*types.LDAPUser, 0, len(entries))
	for _, entry := range entries {
		user := &types.LDAPUser{
			DN:         entry.DN,
			Attributes: map[string][]string{},
		}
		for _, attr := range attributes {
			user.Attributes[attr] = entry.GetAttributeValues(attr)
		}
		res = append(res, user)
	}

	return res, nil
}
