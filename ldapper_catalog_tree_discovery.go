// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/types"
)

// parentDNOf returns the parent DN string, or "" for the topmost RDN.
func parentDNOf(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || parsed == nil || len(parsed.RDNs) <= 1 {
		return ""
	}
	parent := &ldap.DN{RDNs: parsed.RDNs[1:]}
	return parent.String()
}

// trimDepth returns a copy of nodes truncated to maxDepth (1 = only roots).
func trimDepth(nodes []*types.OUInfo, maxDepth int) []*types.OUInfo {
	out := make([]*types.OUInfo, 0, len(nodes))
	for _, n := range nodes {
		clone := *n
		if maxDepth <= 1 {
			clone.Children = make([]*types.OUInfo, 0)
		} else {
			clone.Children = trimDepth(n.Children, maxDepth-1)
		}
		out = append(out, &clone)
	}
	return out
}

// CATALOG OU-TREE DISCOVERY METHODS

// GetCatalogTree fetches the whole OU subtree in a single LDAP search and
// builds the tree on the client, optionally trimming to maxDepth (0 = no limit).
func (conn *LDAPper) GetCatalogTree(baseDn string, maxDepth int) (types.CatalogTree, error) {
	res := types.CatalogTree{Tree: make([]*types.OUInfo, 0)}

	filter := conn.catalogAdapter.OUObjectFilter()
	attrs := conn.catalogAdapter.OUAttrs()

	// Single subtree search + paged control (required for AD).
	pagingControl := ldap.NewControlPaging(constants.DefaultCatalogTreePageSize)
	var allEntries []*ldap.Entry

	for {
		req := conn.newSearchRequest(baseDn, ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, false, filter, attrs, []ldap.Control{pagingControl})

		result, err := conn.connection.Search(req)
		if err != nil {
			return res, fmt.Errorf("unsuccessful ou search: %w", err)
		}
		allEntries = append(allEntries, result.Entries...)

		// The server echoes the paging control back; extract the next cookie.
		ctrl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if ctrl == nil {
			break // server did not honor paging: single page, done
		}
		next, ok := ctrl.(*ldap.ControlPaging)
		if !ok {
			break // unexpected control type: stop rather than loop forever
		}
		pagingControl.SetCookie(next.Cookie)
		if len(next.Cookie) == 0 {
			break // empty cookie = last page
		}
	}

	// Convert entries once; filter to descendants of baseDn.
	baseDN, err := ldap.ParseDN(baseDn)
	if err != nil {
		return res, fmt.Errorf("invalid base DN %q: %w", baseDn, err)
	}

	byDN := make(map[string]*types.OUInfo, len(allEntries))
	order := make([]string, 0, len(allEntries)) // preserves server order
	for _, e := range allEntries {
		info := conn.catalogAdapter.OUInfoFromEntry(*e)
		if info == nil || info.DN == "" {
			continue
		}
		parsed, err := ldap.ParseDN(info.DN)
		if err != nil {
			continue // malformed DN from server: skip rather than crash
		}
		if !baseDN.AncestorOf(parsed) {
			// Skips both the base DN itself (not its own ancestor) and any
			// entries outside baseDn returned by the server.
			continue
		}
		info.Children = make([]*types.OUInfo, 0)
		byDN[info.DN] = info
		order = append(order, info.DN)
	}

	// Attach each entry to its nearest ancestor present in byDN.
	for _, dn := range order {
		info := byDN[dn]
		parentDN := parentDNOf(info.DN)
		if parent, ok := byDN[parentDN]; ok {
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

func (conn *LDAPper) GetRootOUs(rootDN string) ([]*types.OUInfo, error) {
	res := make([]*types.OUInfo, 0)

	filter := conn.catalogAdapter.OUObjectFilter()
	attributes := conn.catalogAdapter.OUAttrs()

	searchRequest := conn.newSearchRequest(rootDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, false, filter, attributes, nil)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("unsuccessful ou search: %s", err.Error())
	}

	for _, entry := range searchResult.Entries {
		res = append(res, conn.catalogAdapter.OUInfoFromEntry(*entry))
	}

	return res, nil
}

func (conn *LDAPper) GetSubOUs(group string, level int) (res []*types.OUInfo, err error) {
	res = make([]*types.OUInfo, 0)

	filter := conn.catalogAdapter.OUObjectFilter()
	attributes := conn.catalogAdapter.OUAttrs()

	searchRequest := conn.newSearchRequest(group, level, ldap.NeverDerefAliases, false, filter, attributes, nil)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("unsuccessful sub ou search: %s", err.Error())
	}

	for _, entry := range searchResult.Entries {
		info := conn.catalogAdapter.OUInfoFromEntry(*entry)

		info.Children = make([]*types.OUInfo, 0)

		if strings.HasSuffix(info.DN, ","+group) && info.DN != group {
			res = append(res, info)
		}
	}

	return res, nil
}
