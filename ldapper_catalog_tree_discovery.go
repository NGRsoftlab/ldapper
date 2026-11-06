// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// CATALOG OU-TREE DISCOVERY METHODS

// WalkCatalogTree traverses the OU subtree under baseDN in depth-first
// order, invoking fn for each node up to maxDepth levels deep. A maxDepth
// of 0 means "no limit"; maxDepth == 1 visits only the direct children of
// baseDN and is served with ScopeSingleLevel (avoiding a full subtree read).
//
// The callback receives the current depth (0 = top-level child of baseDN)
// and the node. The Children field of the passed node is always empty —
// structural information is conveyed by the DFS order and the depth value.
// Callers that need a tree should reconstruct it from the depth sequence.
//
// If fn returns a non-nil error the walk stops early and that error is
// returned to the caller.
//
// Trade-off: for maxDepth > 1 the full subtree is fetched before the walk
// begins because LDAP does not expose a server-side depth parameter. To
// bound memory for very large catalogs, set SearchLimits.MaxEntries.
func (ldapper *LDAPper) WalkCatalogTree(
	baseDN string,
	maxDepth int,
	fn func(depth int, node *types.OUNormalizedInfo) error,
) error {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()
	return ldapper.walkCatalogTreeLocked(baseDN, maxDepth, fn)
}

func (ldapper *LDAPper) walkCatalogTreeLocked(
	baseDN string,
	maxDepth int,
	fn func(depth int, node *types.OUNormalizedInfo) error,
) error {
	if fn == nil {
		return fmt.Errorf("%w: nil callback", ErrInvalidArgument)
	}
	if err := ldapper.requireConnLocked(); err != nil {
		return err
	}

	dn, err := ldap.ParseDN(baseDN)
	if err != nil {
		return fmt.Errorf("%w: invalid DN %q: %v", ErrInvalidArgument, baseDN, err)
	}

	// Fast path: single level can be served with ScopeSingleLevel, which
	// avoids reading the subtree. LDAP has no depth parameter, so for
	// maxDepth > 1 the full subtree is fetched regardless.
	if maxDepth == 1 {
		return ldapper.walkSingleLevelLocked(dn, fn)
	}

	entries, err := ldapper.searchPaged(
		dn.String(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, false,
		ldapper.catalogAdapter.OUObjectFilter(),
		ldapper.catalogAdapter.OUAttrs(), nil)
	if err != nil {
		return fmt.Errorf("ou search: %w", classifyLDAPError(err))
	}

	// Canonical keys normalize case, escaping and multi-valued RDN order,
	// so equivalent DNs link correctly. See helpers.go:canonicalDN.
	byDN := make(map[string]*types.OUNormalizedInfo, len(entries))
	order := make([]string, 0, len(entries))

	for _, e := range entries {
		info := ldapper.catalogAdapter.GetNormalizedOUInfoFromEntry(*e)
		if info == nil || info.DN == "" {
			continue
		}
		parsed, err := ldap.ParseDN(info.DN)
		if err != nil {
			continue // malformed DN from server: skip rather than crash
		}
		// AncestorOfFold matches caseIgnoreMatch for naming attributes;
		// AncestorOf would drop case-differing DNs silently.
		if !dn.AncestorOfFold(parsed) {
			continue
		}
		key := canonicalDN(info.DN)
		if _, dup := byDN[key]; dup {
			continue
		}
		byDN[key] = info
		order = append(order, key)
	}

	children := make(map[string][]string, len(byDN))
	roots := make([]string, 0, len(byDN))
	for _, key := range order {
		info := byDN[key]
		parentKey := canonicalDN(parentDNOf(info.DN))
		if _, ok := byDN[parentKey]; ok {
			children[parentKey] = append(children[parentKey], key)
		} else {
			roots = append(roots, key)
		}
	}

	var walk func(keys []string, depth int) error
	walk = func(keys []string, depth int) error {
		if maxDepth > 0 && depth >= maxDepth {
			return nil
		}
		for _, key := range keys {
			if err := fn(depth, byDN[key]); err != nil {
				return err
			}
			if err := walk(children[key], depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	return walk(roots, 0)
}

// walkSingleLevelLocked serves the maxDepth == 1 case with ScopeSingleLevel.
// The server returns only the direct children of dn, so no parent-child
// index is needed.
func (ldapper *LDAPper) walkSingleLevelLocked(
	dn *ldap.DN,
	fn func(depth int, node *types.OUNormalizedInfo) error,
) error {
	entries, err := ldapper.searchPaged(
		dn.String(), ldap.ScopeSingleLevel, ldap.NeverDerefAliases, false,
		ldapper.catalogAdapter.OUObjectFilter(),
		ldapper.catalogAdapter.OUAttrs(), nil)
	if err != nil {
		return fmt.Errorf("ou search: %w", classifyLDAPError(err))
	}

	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		info := ldapper.catalogAdapter.GetNormalizedOUInfoFromEntry(*e)
		if info == nil || info.DN == "" {
			continue
		}
		parsed, err := ldap.ParseDN(info.DN)
		if err != nil {
			continue
		}
		if !dn.AncestorOfFold(parsed) {
			continue
		}
		key := canonicalDN(info.DN)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if err := fn(0, info); err != nil {
			return err
		}
	}

	return nil
}

// GetCatalogTree builds the OU tree under baseDN, optionally truncated to
// maxDepth levels (0 = no limit; 1 = direct children of baseDN only).
//
// For maxDepth == 1 the tree is fetched with ScopeSingleLevel, avoiding a
// full subtree read. For maxDepth > 1 the full subtree is fetched first
// because LDAP has no server-side depth parameter, then reassembled into a
// tree — use SearchLimits.MaxEntries to bound memory for very large
// catalogs.
//
// Nodes whose direct parent is not in the fetched set (e.g., entries
// filtered out by the server due to ACL) are promoted to roots of the
// result.
func (ldapper *LDAPper) GetCatalogTree(baseDN string, maxDepth int) (types.CatalogTree, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	return ldapper.getCatalogTreeLocked(baseDN, maxDepth)
}

func (ldapper *LDAPper) getCatalogTreeLocked(baseDN string, maxDepth int) (types.CatalogTree, error) {
	res := types.CatalogTree{Tree: make([]*types.OUNormalizedInfo, 0)}

	// path[d] is the ancestor at depth d of the node currently being
	// visited. DFS order from walkCatalogTreeLocked guarantees that on a
	// callback at depth D, path has exactly D entries: the chain from the
	// current root down to the node's parent.
	var path []*types.OUNormalizedInfo

	err := ldapper.walkCatalogTreeLocked(baseDN, maxDepth,
		func(depth int, node *types.OUNormalizedInfo) error {
			if depth > len(path) {
				// Internal invariant: walk delivers nodes in DFS order, so
				// a node at depth D always has D ancestors already pushed.
				return fmt.Errorf(
					"catalog tree: walk delivered depth %d with %d ancestors",
					depth, len(path))
			}

			// Defensive: adapters return nodes with an empty Children
			// slice, but reset it if a custom adapter populated it — the
			// tree reconstruction owns this field.
			if len(node.Children) > 0 {
				node.Children = make([]*types.OUNormalizedInfo, 0)
			}

			// Drop ancestors from the previous subtree; only the chain up
			// to the current depth is meaningful.
			path = path[:depth]

			if depth == 0 {
				res.Tree = append(res.Tree, node)
			} else {
				parent := path[depth-1]
				parent.Children = append(parent.Children, node)
			}
			path = append(path, node)
			return nil
		})
	if err != nil {
		// Discard the partially built tree — a partial result is more
		// dangerous than an empty one for callers that trust the output.
		return types.CatalogTree{Tree: make([]*types.OUNormalizedInfo, 0)}, err
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
		return nil, fmt.Errorf("%w: ScopeBaseObject is not supported by GetSubOUs", ErrInvalidArgument)
	default:
		return nil, fmt.Errorf("%w: invalid scope %d", ErrInvalidArgument, scope)
	}

	parentParsed, err := ldap.ParseDN(parentDN)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid DN %q: %v", ErrInvalidArgument, parentDN, err)
	}
	parentKey := canonicalDN(parentDN) // canonicalDN parses internally

	entries, err := ldapper.searchPaged(
		parentParsed.String(), scope, ldap.NeverDerefAliases, false,
		ldapper.catalogAdapter.OUObjectFilter(),
		ldapper.catalogAdapter.OUAttrs(), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("sub ou search: %w", classifyLDAPError(err))
	}

	res := make([]*types.OUNormalizedInfo, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		info := ldapper.catalogAdapter.GetNormalizedOUInfoFromEntry(*entry)
		if info == nil {
			continue
		}
		key := canonicalDN(info.DN)
		if key == parentKey {
			// Base DN itself is excluded: "sub" means descendants only.
			// Canonical comparison handles case/escaping differences between
			// the caller-supplied parentDN and the server-returned DN.
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		res = append(res, info)
	}

	return res, nil
}
