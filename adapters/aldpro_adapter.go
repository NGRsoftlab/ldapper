// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

/*
NB: BE CAREFUL There are rbta-org-unit instead of (or together with) organizationalUnit in AldPro - so smth can work incorrectly
*/

type ALDPROAdapter struct{}

// CAST

func (a ALDPROAdapter) GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo {
	return &types.UserNormalizedInfo{
		DistinguishedName: ldapUser.DN,
		CommonName:        ldapUser.GetAttributeValue("cn"),
		Mobile:            ldapUser.GetAttributeValue("mobile"),
		Phone:             ldapUser.GetAttributeValue("telephoneNumber"),
		Mail:              ldapUser.GetAttributeValue("mail"),
		Department:        ldapUser.GetAttributeValue("rbtadp"),
		Title:             ldapUser.GetAttributeValue("title"),
		Manager:           ldapUser.GetAttributeValue("manager"),
		Photo:             ldapUser.GetAttributeValue("jpegPhoto"),
		Company:           ldapUser.GetAttributeValue("o"),
		Country:           ldapUser.GetAttributeValue("co"),
		Address:           ldapUser.GetAttributeValue("streetAddress"),
		City:              ldapUser.GetAttributeValue("l"),
		Index:             ldapUser.GetAttributeValue("postalCode"),
	}
}

func (a ALDPROAdapter) GetNormalizedOUInfoFromEntry(entry ldap.Entry) *types.OUNormalizedInfo {
	return &types.OUNormalizedInfo{
		DN:       entry.DN,
		Name:     ouNameFromDN(entry.DN),
		OU:       entry.GetAttributeValue("ou"),
		Children: make([]*types.OUNormalizedInfo, 0),
	}
}

// BIND

// BindIdentity passes the login through: ALDPro accepts UPN/DN as Simple
// Bind principals. Short-form bind is not supported — callers must supply
// a UPN or a full DN.
func (a ALDPROAdapter) BindIdentity(login, _ string) (string, error) {
	if login == "" {
		return "", fmt.Errorf("empty login")
	}
	return login, nil
}

// TYPE FILTERS

func (a ALDPROAdapter) OUObjectFilter() string {
	return "(|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))"
}

func (a ALDPROAdapter) GroupObjectFilter() string {
	return "(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))"
}

func (a ALDPROAdapter) UserObjectFilter() string {
	return "(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))"
}

// SEARCH

func (a ALDPROAdapter) SearchUserFilterTemplate() string {
	// Match by uid OR entryDN so that both a short uid and a full-DN
	// bind principal resolve correctly.
	return "(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(|(uid=%[1]s)(entryDN=%[1]s)))"
}

func (a ALDPROAdapter) SearchUserGroupsFilterTemplate() string {
	return "(|(&(|(objectClass=groupOfNames)(objectClass=ipausergroup)(objectClass=posixGroup))(member=%s))(&(objectClass=posixGroup)(memberUid=%s)))"
}

func (a ALDPROAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any {
	return []any{ldapUser.DN, ldapUser.GetAttributeValue("uid")}
}

func (a ALDPROAdapter) SearchOUFilterTemplate() string {
	return "(&(|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))(ou=%s))"
}

func (a ALDPROAdapter) SearchGroupFilterTemplate() string {
	return "(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(cn=%s))"
}

// ATTRS

func (a ALDPROAdapter) UserAttrs() []string {
	return []string{
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

func (a ALDPROAdapter) OUAttrs() []string {
	return []string{
		"dn",
		"ou",
		"description",
		"manager",
	}
}

func (a ALDPROAdapter) GroupAttrs() []string {
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
