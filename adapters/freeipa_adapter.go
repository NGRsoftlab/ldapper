// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

/*
NB: BE CAREFUL There are nsContainer instead of (or together with) organizationalUnit in FreeIPA (nsContainers - just one-level struct) - so smth can work incorrectly
*/

type FREEIPAAdapter struct{}

// CAST

func (a FREEIPAAdapter) GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo {
	return &types.UserNormalizedInfo{
		DistinguishedName: ldapUser.DN,
		CommonName:        ldapUser.GetAttributeValue("cn"),
		Mobile:            ldapUser.GetAttributeValue("mobile"),
		Phone:             ldapUser.GetAttributeValue("telephoneNumber"),
		Mail:              ldapUser.GetAttributeValue("mail"),
		Department:        "",
		Title:             ldapUser.GetAttributeValue("title"),
		Manager:           ldapUser.GetAttributeValue("manager"),
		Photo:             ldapUser.GetAttributeValue("jpegPhoto"),
		Company:           ldapUser.GetAttributeValue("o"),
		Country:           ldapUser.GetAttributeValue("co"),
		Address:           ldapUser.GetAttributeValue("street"),
		City:              ldapUser.GetAttributeValue("l"),
		Index:             ldapUser.GetAttributeValue("postalCode"),
	}
}

func (a FREEIPAAdapter) GetNormalizedOUInfoFromEntry(entry ldap.Entry) *types.OUNormalizedInfo {
	return &types.OUNormalizedInfo{
		DN:       entry.DN,
		Name:     ouNameFromDN(entry.DN),
		OU:       entry.GetAttributeValue("ou"),
		Children: make([]*types.OUNormalizedInfo, 0),
	}
}

// BIND

// BindIdentity accepts either a full DN (passed through) or a short uid,
// which is expanded to uid=<login>,cn=users,cn=accounts,<baseDN> — the
// standard FreeIPA user container.
func (a FREEIPAAdapter) BindIdentity(login, baseDN string) (string, error) {
	if login == "" {
		return "", fmt.Errorf("empty login")
	}
	if _, err := ldap.ParseDN(login); err == nil {
		return login, nil
	}
	if baseDN == "" {
		return "", fmt.Errorf("baseDN required for short-form bind")
	}
	users, err := appendRDN("cn", "users", baseDN)
	if err != nil {
		return "", err
	}
	accounts, err := appendRDN("cn", "accounts", users)
	if err != nil {
		return "", err
	}
	return appendRDN("uid", login, accounts)
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
	// Match by uid OR entryDN so that both the short-form login and the
	// full-DN bind principal resolve to the same user entry.
	return "(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(|(uid=%[1]s)(entryDN=%[1]s)))"
}

func (a FREEIPAAdapter) SearchUserGroupsFilterTemplate() string {
	return "(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=%s))"
}

func (a FREEIPAAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any {
	return []any{ldapUser.DN}
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
