// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"github.com/NGRsoftlab/ldapper/types"
)

// GetGroup returns the group with the given cn inside baseDN.
// Returns ErrNotFoundOrNotVisible if no entry matches (the object may
// either not exist or be hidden by ACL — LDAP cannot distinguish these),
// and ErrAmbiguousResult if more than one does.
func (ldapper *LDAPper) GetGroup(cn, baseDN string) (*types.LDAPGroup, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getGroupLocked(cn, baseDN)
}

func (ldapper *LDAPper) getGroupLocked(cn, baseDN string) (*types.LDAPGroup, error) {
	attrs := ldapper.catalogAdapter.GroupAttrs()

	entry, err := ldapper.searchSingleEntryLocked(
		kindGroup, cn, baseDN,
		ldapper.catalogAdapter.SearchGroupFilterTemplate(), attrs,
	)
	if err != nil {
		return nil, err
	}

	return &types.LDAPGroup{
		DN:         entry.DN,
		Attributes: attrsToMap(entry, attrs),
	}, nil
}
