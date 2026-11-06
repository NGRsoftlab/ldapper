// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

type OPENLDAPAdapter struct{}

// CAST

func (a OPENLDAPAdapter) GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo {
	return &types.UserNormalizedInfo{
		DistinguishedName: ldapUser.DN,
		CommonName:        ldapUser.GetAttributeValue("cn"),
		Mobile:            ldapUser.GetAttributeValue("mobile"),
		Phone:             ldapUser.GetAttributeValue("telephoneNumber"),
		Mail:              ldapUser.GetAttributeValue("mail"),
		Department:        ldapUser.GetAttributeValue("departmentNumber"),
		Title:             ldapUser.GetAttributeValue("title"),
		Manager:           ldapUser.GetAttributeValue("manager"),
		Photo:             ldapUser.GetAttributeValue("jpegPhoto"),
		Company:           ldapUser.GetAttributeValue("o"),
		Country:           "",
		Address:           ldapUser.GetAttributeValue("postalAddress"),
		City:              "",
		Index:             "",
	}
}

func (a OPENLDAPAdapter) GetNormalizedOUInfoFromEntry(entry ldap.Entry) *types.OUNormalizedInfo {
	return &types.OUNormalizedInfo{
		DN:       entry.DN,
		Name:     ouNameFromDN(entry.DN),
		OU:       entry.GetAttributeValue("ou"),
		Children: make([]*types.OUNormalizedInfo, 0),
	}
}

// TYPE FILTERS

func (a OPENLDAPAdapter) OUObjectFilter() string {
	return "(&(objectClass=organizationalUnit))"
}

func (a OPENLDAPAdapter) GroupObjectFilter() string {
	return "(|(objectClass=groupOfNames)(objectClass=posixGroup))"
}

func (a OPENLDAPAdapter) UserObjectFilter() string {
	return "(&(objectClass=person))"
}

// SEARCH

func (a OPENLDAPAdapter) SearchUserFilterTemplate() string {
	return "(&(!(objectClass=computer))(|(uid=%[1]s)(entryDN=%[1]s)))"
}

func (a OPENLDAPAdapter) SearchUserGroupsFilterTemplate() string {
	return "(|(&(objectClass=groupOfNames)(member=%s))(&(objectClass=posixGroup)(memberUid=%s)))"
}

func (a OPENLDAPAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any {
	return []any{ldapUser.DN, ldapUser.GetAttributeValue("uid")}
}

func (a OPENLDAPAdapter) SearchOUFilterTemplate() string {
	return "(&(objectClass=organizationalUnit)(ou=%s))"
}

func (a OPENLDAPAdapter) SearchGroupFilterTemplate() string {
	return "(&(|(objectClass=groupOfNames)(objectClass=posixGroup))(cn=%s))"
}

// ATTRS

func (a OPENLDAPAdapter) UserAttrs() []string {
	return []string{
		// common (person class)
		"cn",
		"sn",

		// organizationalPerson class
		"ou",
		"title",
		"telephoneNumber",
		"postalAddress",

		// inetOrgPerson class
		"uid",
		"givenName",
		"displayName",
		"mail",
		"mobile",
		"departmentNumber",
		"employeeNumber",
		"employeeType",
		"jpegPhoto",

		// posixAccount  class
		"uidNumber",
		"gidNumber",
		"homeDirectory",

		// may be or not to be at all attrs
		"description",
		"manager",
	}
}

func (a OPENLDAPAdapter) OUAttrs() []string {
	return []string{
		"ou",
		"objectClass",
		"description",
	}
}

func (a OPENLDAPAdapter) GroupAttrs() []string {
	return []string{
		"cn",
		"member",       // NB: groupOfNames
		"uniqueMember", // NB: groupOfUniqueNames
		"gidNumber",    // NB: posixGroup

		// non-must attrs (may be empty)
		"description",

		// groupOfNames&groupOfUniqueNames
		"o",
		"ou",
		"owner",
		"businessCategory",

		// posixGroup
		"memberUid",

		// operational attr
		"memberOf", // NB: may be empty, needs research
	}
}
