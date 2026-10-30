// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

/*
NB: BE CAREFUL There are rbta-org-unit instead of (or together with) organizationalUnit in AldPro - so smth can work incorrectly
*/

type ALDRPOAdapter struct{}

// CAST

func (a ALDRPOAdapter) GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo {
	// TODO: think what else we need in normalized user info

	return &types.UserNormalizedInfo{
		DistinguishedName: ldapUser.GetAttributeValue("dn"),
		CommonName:        ldapUser.GetAttributeValue("cn"),
		Mobile:            ldapUser.GetAttributeValue("mobile"),
		Phone:             ldapUser.GetAttributeValue("telephoneNumber"),
		Mail:              ldapUser.GetAttributeValue("mail"),
		Department:        ldapUser.GetAttributeValue("rbtadp"),
		Title:             ldapUser.GetAttributeValue("title"),
		Manager:           ldapUser.GetAttributeValue("manager"),
		Photo:             ldapUser.GetAttributeValue("jpegPhoto"),
		Company:           "",
		Country:           ldapUser.GetAttributeValue("co"),
		Address:           ldapUser.GetAttributeValue("streetAddress"),
		City:              ldapUser.GetAttributeValue("l"),
		Index:             ldapUser.GetAttributeValue("postalCode"),
	}
}

func (a ALDRPOAdapter) OUInfoFromEntry(entry ldap.Entry) *types.OUInfo {
	return &types.OUInfo{
		DN:       entry.DN,
		Name:     entry.DN,
		OU:       entry.GetAttributeValue("ou"),
		Children: make([]*types.OUInfo, 0),
	}
}

// TYPE FILTERS

func (a ALDRPOAdapter) OUObjectFilter() string {
	return "(|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))"
}

func (a ALDRPOAdapter) GroupObjectFilter() string {
	return "(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))"
}

func (a ALDRPOAdapter) UserObjectFilter() string {
	return "(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))"
}

// SEARCH

func (a ALDRPOAdapter) SearchUserFilterTemplate() string {
	return "(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(uid=%s))"
}

// NB: filter syntax need check
func (a ALDRPOAdapter) SearchUserGroupsFilterTemplate() string {
	return "(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=uid=%s))"
}

func (a ALDRPOAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any {
	return []any{ldapUser.GetAttributeValue("uid")}
}

func (a ALDRPOAdapter) SearchOUFilterTemplate() string {
	return "(&(|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))(ou=%s))"
}

func (a ALDRPOAdapter) SearchGroupFilterTemplate() string {
	return "(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(cn=%s))"
}

// ATTRS

func (a ALDRPOAdapter) UserAttrs() []string {
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
		"jpegPhoto",
		"rbtadp", // department analogy

		// system&posix attrs
		"uidNumber",
		"gidNumber",
		"homeDirectory",
		"memberOf",

		// address
		"streetAddress",
		"l",
		"postalCode",

		// may be or not to be at all attrs
		"description",
		"manager",
		"co",
		"ou",
		"o",
	}
}

func (a ALDRPOAdapter) OUAttrs() []string {
	return []string{
		"dn",
		"ou",
		"description",
		"manager",
	}
}

func (a ALDRPOAdapter) GroupAttrs() []string {
	return []string{
		"cn",

		"entrydn",
		"description",

		"gidNumber", // NB: posixGroup

		"member",
		"memberOf",

		"ipaUniqueID",
		"ipaNTSecurityIdentifier",
	}
}
