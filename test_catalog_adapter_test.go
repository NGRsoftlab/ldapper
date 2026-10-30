// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// testCatalogAdapter is a lightweight test double for interfaces.CatalogAdapter.
// Static values are plain fields; only methods that need argument-dependent
// returns use function fields.

// In fact - test interface implementation

type testCatalogAdapter struct {
	userObjectFilter               string
	ouObjectFilter                 string
	searchUserFilterTemplate       string
	searchUserGroupsFilterTemplate string
	searchUserGroupsFilterArgsFunc func(types.LDAPUser) []any
	userAttrs                      []string
	ouAttrs                        []string
	ouInfoFromEntryFunc            func(ldap.Entry) *types.OUInfo
}

func (a *testCatalogAdapter) GetNormalizedUserInfo(_ types.LDAPUser) *types.UserNormalizedInfo {
	return &types.UserNormalizedInfo{}
}

func (a *testCatalogAdapter) OUInfoFromEntry(e ldap.Entry) *types.OUInfo {
	if a.ouInfoFromEntryFunc != nil {
		return a.ouInfoFromEntryFunc(e)
	}
	return &types.OUInfo{DN: e.DN, Children: []*types.OUInfo{}}
}

func (a *testCatalogAdapter) UserObjectFilter() string  { return a.userObjectFilter }
func (a *testCatalogAdapter) GroupObjectFilter() string { return "" }
func (a *testCatalogAdapter) OUObjectFilter() string    { return a.ouObjectFilter }

func (a *testCatalogAdapter) SearchUserFilterTemplate() string { return a.searchUserFilterTemplate }
func (a *testCatalogAdapter) SearchUserGroupsFilterTemplate() string {
	return a.searchUserGroupsFilterTemplate
}

func (a *testCatalogAdapter) SearchUserGroupsFilterTemplateArgs(u types.LDAPUser) []any {
	if a.searchUserGroupsFilterArgsFunc != nil {
		return a.searchUserGroupsFilterArgsFunc(u)
	}
	return nil
}

func (a *testCatalogAdapter) SearchOUFilterTemplate() string    { return "" }
func (a *testCatalogAdapter) SearchGroupFilterTemplate() string { return "" }

func (a *testCatalogAdapter) UserAttrs() []string  { return a.userAttrs }
func (a *testCatalogAdapter) OUAttrs() []string    { return a.ouAttrs }
func (a *testCatalogAdapter) GroupAttrs() []string { return nil }
