// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// fakeAdapter is a minimal, configurable CatalogAdapter for tests. Methods
// that are not exercised by a particular test return sane neutral values so
// the struct can be constructed sparsely:
//
//	a := &fakeAdapter{
//	    userFilterTemplate: "(&(objectClass=user)(uid=%s))",
//	    userAttrs:          []string{"uid", "cn"},
//	}
//
// is usually enough for a user lookup test. Fields default to empty
// strings / empty slices; callers should populate whatever the test needs.
type fakeAdapter struct {
	userFilterTemplate  string
	groupFilterTemplate string
	ouFilterTemplate    string

	userGroupsTemplate string
	userGroupsArgs     func(u types.LDAPUser) []any

	userAttrs  []string
	groupAttrs []string
	ouAttrs    []string

	userObjFilter  string
	groupObjFilter string
	ouObjFilter    string

	normalizedUser func(u types.LDAPUser) *types.UserNormalizedInfo
	normalizedOU   func(e ldap.Entry) *types.OUNormalizedInfo
}

func (f *fakeAdapter) GetNormalizedUserInfo(u types.LDAPUser) *types.UserNormalizedInfo {
	if f.normalizedUser != nil {
		return f.normalizedUser(u)
	}
	return nil
}

func (f *fakeAdapter) GetNormalizedOUInfoFromEntry(e ldap.Entry) *types.OUNormalizedInfo {
	if f.normalizedOU != nil {
		return f.normalizedOU(e)
	}
	return nil
}

func (f *fakeAdapter) UserObjectFilter() string  { return f.userObjFilter }
func (f *fakeAdapter) GroupObjectFilter() string { return f.groupObjFilter }
func (f *fakeAdapter) OUObjectFilter() string    { return f.ouObjFilter }

func (f *fakeAdapter) SearchUserFilterTemplate() string  { return f.userFilterTemplate }
func (f *fakeAdapter) SearchGroupFilterTemplate() string { return f.groupFilterTemplate }
func (f *fakeAdapter) SearchOUFilterTemplate() string    { return f.ouFilterTemplate }

func (f *fakeAdapter) SearchUserGroupsFilterTemplate() string {
	return f.userGroupsTemplate
}

func (f *fakeAdapter) SearchUserGroupsFilterTemplateArgs(u types.LDAPUser) []any {
	if f.userGroupsArgs != nil {
		return f.userGroupsArgs(u)
	}
	return nil
}

func (f *fakeAdapter) UserAttrs() []string  { return f.userAttrs }
func (f *fakeAdapter) GroupAttrs() []string { return f.groupAttrs }
func (f *fakeAdapter) OUAttrs() []string    { return f.ouAttrs }
