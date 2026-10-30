// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

/*
NB: BE CAREFUL There are nsContainer instead of (or together with) organizationalUnit in FreeIPA (nsContainers - just one-level struct) - so smth can work incorrectly
*/

type FREEIPAAdapter struct{}

// CAST

func (a FREEIPAAdapter) GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo {
	// TODO: think what else we need in normalized user info

	return &types.UserNormalizedInfo{
		DistinguishedName: ldapUser.GetAttributeValue("dn"),
		CommonName:        ldapUser.GetAttributeValue("cn"),
		Mobile:            ldapUser.GetAttributeValue("mobile"),
		Phone:             ldapUser.GetAttributeValue("telephoneNumber"),
		Mail:              ldapUser.GetAttributeValue("mail"),
		Department:        "",
		Title:             ldapUser.GetAttributeValue("title"),
		Manager:           ldapUser.GetAttributeValue("manager"),
		Photo:             ldapUser.GetAttributeValue("jpegPhoto"),
		Company:           "",
		Country:           ldapUser.GetAttributeValue("co"),
		Address:           ldapUser.GetAttributeValue("street"),
		City:              ldapUser.GetAttributeValue("l"),
		Index:             ldapUser.GetAttributeValue("postalCode"),
	}
}

func (a FREEIPAAdapter) OUInfoFromEntry(entry ldap.Entry) *types.OUInfo {
	return &types.OUInfo{
		DN:       entry.DN,
		Name:     entry.DN,
		OU:       entry.GetAttributeValue("ou"),
		Children: make([]*types.OUInfo, 0),
	}
}

// TYPE FILTERS

func (a FREEIPAAdapter) OUObjectFilter() string {
	return "(|(objectClass=organizationalUnit)(objectClass=nsContainer))"
}

func (a FREEIPAAdapter) GroupObjectFilter() string {
	return "(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))"
}

func (a FREEIPAAdapter) UserObjectFilter() string {
	return "(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))"
}

// SEARCH

func (a FREEIPAAdapter) SearchUserFilterTemplate() string {
	return "(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(uid=%s))"
}

// NB: filter syntax need check
func (a FREEIPAAdapter) SearchUserGroupsFilterTemplate() string {
	return "(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=uid=%s))"
}

func (a FREEIPAAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any {
	return []any{ldapUser.GetAttributeValue("uid")}
}

func (a FREEIPAAdapter) SearchOUFilterTemplate() string {
	return "(&(|(objectClass=organizationalUnit)(objectClass=nsContainer))(ou=%s))"
}

func (a FREEIPAAdapter) SearchGroupFilterTemplate() string {
	return "(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(cn=%s))"
}

// ATTRS

func (a FREEIPAAdapter) UserAttrs() []string {
	return []string{
		"dn",

		"uid",
		"cn",
		"givenName",
		"sn",
		"displayName",
		"mail",
		"telephoneNumber",
		"mobile",
		"title",
		"ou",
		"o",
		"jpegPhoto",

		"nsAccountLock",

		// system&posix attrs
		"uidNumber",
		"gidNumber",
		"homeDirectory",
		"memberOf",
		"ipaUniqueID",

		// address
		"street",
		"l",
		"st",
		"postalCode",

		// may be or not to be at all attrs
		"description",
		"manager",
		"co",
	}
}

func (a FREEIPAAdapter) OUAttrs() []string {
	return []string{
		"dn",
		"ou",
		"objectClass",
		"description",
	}
}

func (a FREEIPAAdapter) GroupAttrs() []string {
	return []string{
		"cn",
		"ou",
		"description",
		"objectClass",

		"gidNumber", // NB: posixGroup
		"memberUid", // NB: posixGroup

		"member",
		"memberIndirect",
		"memberOf",

		"mepManagedBy",
		"ipaUniqueID",
		"ipaNTSecurityIdentifier",
	}
}
