// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// CATALOG OU-TREE DISCOVERY METHODS

// GetCatalogTree fetches the whole OU subtree in a single LDAP search and
// builds the tree on the client, optionally trimming to maxDepth (0 = no limit).
// NB: returns tree with normalized ou objects
func (ldapper *LDAPper) GetCatalogTree(baseDN string, maxDepth int) (types.CatalogTree, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getCatalogTreeLocked(baseDN, maxDepth)
}

// Nodes whose direct parent is not in the fetched set (e.g., the base DN itself,
// or entries filtered out by the server) are promoted to roots of res.Tree.
func (ldapper *LDAPper) getCatalogTreeLocked(baseDN string, maxDepth int) (types.CatalogTree, error) {
	res := types.CatalogTree{Tree: make([]*types.OUNormalizedInfo, 0)}

	if err := ldapper.requireConnLocked(); err != nil {
		return res, err
	}

	dn, err := ldap.ParseDN(baseDN)
	if err != nil {
		return res, fmt.Errorf("%w: invalid DN %q: %v", ErrInvalidArgument, baseDN, err)
	}

	allEntries, err := ldapper.searchPaged(dn.String(), ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, false,
		ldapper.catalogAdapter.OUObjectFilter(),
		ldapper.catalogAdapter.OUAttrs(), nil)
	if err != nil {
		return res, fmt.Errorf("unsuccessful ou search: %w", classifyLDAPError(err))
	}

	// NB: keys are lowercased so that DN comparisons are case-insensitive,
	// matching ldap.DN.AncestorOf behavior.
	byDN := make(map[string]*types.OUNormalizedInfo, len(allEntries))
	order := make([]string, 0, len(allEntries)) // preserves server order

	for _, e := range allEntries {
		info := ldapper.catalogAdapter.GetNormalizedOUInfoFromEntry(*e)
		if info == nil || info.DN == "" {
			continue
		}
		parsed, err := ldap.ParseDN(info.DN)
		if err != nil {
			continue // malformed DN from server: skip rather than crash
		}
		if !dn.AncestorOf(parsed) {
			// Skips both the base DN itself and any entries outside baseDN.
			continue
		}
		byDN[strings.ToLower(info.DN)] = info
		order = append(order, info.DN)
	}

	for _, dnItem := range order {
		info := byDN[strings.ToLower(dnItem)]
		parentKey := strings.ToLower(parentDNOf(info.DN))
		if parent, ok := byDN[parentKey]; ok {
			parent.Children = append(parent.Children, info)
		} else {
			res.Tree = append(res.Tree, info)
		}
	}

	if maxDepth > 0 {
		res.Tree = trimDepth(res.Tree, maxDepth)
	}

	return res, nil
}

func (ldapper *LDAPper) ListSingleLevelOUs(rootDN string) ([]*types.OUNormalizedInfo, error) {
	return ldapper.GetSubOUs(rootDN, ldap.ScopeSingleLevel)
}

func (ldapper *LDAPper) GetSubOUs(parentDN string, scope int) ([]*types.OUNormalizedInfo, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.getSubOUsLocked(parentDN, scope)
}

func (ldapper *LDAPper) getSubOUsLocked(parentDN string, scope int) ([]*types.OUNormalizedInfo, error) {
	if err := ldapper.requireConnLocked(); err != nil {
		return nil, err
	}

	switch scope {
	case ldap.ScopeSingleLevel, ldap.ScopeWholeSubtree:
	case ldap.ScopeBaseObject:
		// NB: GetSubOUs returns descendants only, so ScopeBaseObject would
		// always yield an empty list. Reject it explicitly.
		return nil, fmt.Errorf("%w: ScopeBaseObject is not supported by GetSubOUs", ErrInvalidArgument)
	default:
		return nil, fmt.Errorf("%w: invalid scope %d", ErrInvalidArgument, scope)
	}

	parentParsed, err := ldap.ParseDN(parentDN)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid DN %q: %v", ErrInvalidArgument, parentDN, err)
	}

	entries, err := ldapper.searchPaged(
		parentParsed.String(), scope, ldap.NeverDerefAliases, false,
		ldapper.catalogAdapter.OUObjectFilter(),
		ldapper.catalogAdapter.OUAttrs(), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("unsuccessful sub ou search: %w", classifyLDAPError(err))
	}

	res := make([]*types.OUNormalizedInfo, 0, len(entries))
	for _, entry := range entries {
		info := ldapper.catalogAdapter.GetNormalizedOUInfoFromEntry(*entry)
		if info == nil || info.DN == parentParsed.String() {
			// Base DN itself is excluded: "sub" means descendants only.
			continue
		}
		res = append(res, info)
	}

	return res, nil
}
