// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/types"
)

// CATALOG TREE DISCOVERY METHODS

// TODO: make controlable tree search depth
// GetCatalogTree read catalog tree (with depth 2)
func (conn *LDAPConnection) GetCatalogTree(baseDn string) (types.CatalogTree, error) {
	res := types.CatalogTree{Tree: make([]*types.OUInfo, 0)}

	firstLevel, err := conn.GetRootOUs(baseDn)
	if err != nil {
		return res, err
	}

	if firstLevel != nil {
		_ = conn.GetRecursiveOUSearchResult(&firstLevel, 2)
		res.Tree = firstLevel
	}

	return res, nil
}

func (conn *LDAPConnection) GetRootOUs(rootDN string) ([]*types.OUInfo, error) {
	res := make([]*types.OUInfo, 0)

	filter := conn.catalogAdapter.OUObjectFilter()
	attributes := conn.catalogAdapter.OUAttrs()

	// TODO: think about limits (search size and timeout)
	searchRequest := ldap.NewSearchRequest(
		rootDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, constants.DefaultSearchTimeLimit, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("unsuccessful ou search: %s", err.Error())
	}

	for _, entry := range searchResult.Entries {
		res = append(res, conn.catalogAdapter.OUInfoFromEntry(*entry))
	}

	return res, nil
}

// TODO: make controlable search depth
func (conn *LDAPConnection) GetRecursiveOUSearchResult(prevLevel *[]*types.OUInfo, level int) *[]*types.OUInfo {
	nextLevel := make([]*types.OUInfo, 0)

	for k, v := range *prevLevel {
		nextLevel, _ := conn.GetSubOUs(v.DN, ldap.ScopeSingleLevel)
		if nextLevel != nil {
			if level < constants.DefaultSearchDepth {
				conn.GetRecursiveOUSearchResult(&nextLevel, level+1)
			}
			(*prevLevel)[k].Children = nextLevel
		}
	}
	return &nextLevel
}

func (conn *LDAPConnection) GetSubOUs(group string, level int) (res []*types.OUInfo, err error) {
	res = make([]*types.OUInfo, 0)

	filter := conn.catalogAdapter.OUObjectFilter()
	attributes := conn.catalogAdapter.OUAttrs()

	// TODO: think about limits (search size and timeout)
	searchRequest := ldap.NewSearchRequest(
		group,
		level, ldap.NeverDerefAliases, 0, constants.DefaultSearchTimeLimit, false,
		filter,
		attributes,
		nil,
	)

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
