// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"

	"github.com/NGRsoftlab/ldapper/types"
)

// GetOU returns the organizational unit with the given ou name inside baseDN.
// Returns ErrNotFoundOrNotVisible if no entry matches — the object may
// either not exist or be hidden by ACL. Returns ErrAmbiguousResult if
// more than one matches.
func (ldapper *LDAPper) GetOU(ctx context.Context, ou, baseDN string) (*types.LDAPOU, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getOULocked(ctx, ou, baseDN)
}

func (ldapper *LDAPper) getOULocked(ctx context.Context, ou, baseDN string) (*types.LDAPOU, error) {
	attrs := ldapper.catalogAdapter.OUAttrs()

	entry, err := ldapper.searchSingleEntryLocked(
		ctx,
		kindOU, ou, baseDN,
		ldapper.catalogAdapter.SearchOUFilterTemplate(), attrs,
	)
	if err != nil {
		return nil, err
	}

	return &types.LDAPOU{
		DN:         entry.DN,
		Attributes: attrsToMap(entry, attrs),
	}, nil
}
