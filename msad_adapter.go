// Copyright 2020-2026 NGR Softlab
package ldapper

import "github.com/go-ldap/ldap/v3"

type MSADAdapter struct{}

// CAST

func (a MSADAdapter) GetNormalizedUserInfo(ldapUser LDAPUser) *UserNormalizedInfo {
	// TODO: think what else we need in normalized info

	return &UserNormalizedInfo{
		DistinguishedName: ldapUser.GetAttributeValue("distinguishedName"),
		CommonName:        ldapUser.GetAttributeValue("cn"),
		Mobile:            ldapUser.GetAttributeValue("mobile"),
		Phone:             ldapUser.GetAttributeValue("telephoneNumber"),
		Mail:              ldapUser.GetAttributeValue("mail"),
		Department:        ldapUser.GetAttributeValue("department"),
		Title:             ldapUser.GetAttributeValue("title"),
		Manager:           ldapUser.GetAttributeValue("manager"),
		Photo:             ldapUser.GetFirstNonNullAttributeValue([]string{"thumbnailPhoto", "jpegPhoto"}),
		Company:           ldapUser.GetAttributeValue("company"),
		Country:           ldapUser.GetAttributeValue("co"),
		Address:           ldapUser.GetAttributeValue("streetAddress"),
		City:              ldapUser.GetAttributeValue("l"),
		Index:             ldapUser.GetAttributeValue("postalCode"),
	}
}

func (a MSADAdapter) OUInfoFromEntry(entry ldap.Entry) *OUInfo {
	return &OUInfo{
		DN:       entry.DN,
		Name:     entry.GetAttributeValue("name"),
		OU:       entry.DN,
		Children: make([]*OUInfo, 0),
	}
}

// TYPE FILTERS

func (a MSADAdapter) OUObjectFilter() string {
	return "(&(objectClass=organizationalUnit))"
}

func (a MSADAdapter) GroupObjectFilter() string {
	return "(&(objectCategory=group))"
}

func (a MSADAdapter) UserObjectFilter() string {
	return "(&(objectClass=user)(objectCategory=person))"
}

// SEARCH

func (a MSADAdapter) SearchUserFilterTemplate() string {
	return "(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))"
}

func (a MSADAdapter) SearchUserGroupsFilterTemplate() string {
	return "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=%s))"
}

func (a MSADAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser LDAPUser) []any {
	return []any{ldapUser.DN}
}

func (a MSADAdapter) SearchOUFilterTemplate() string {
	return "(&(objectClass=organizationalUnit)(ou=%s))"
}

func (a MSADAdapter) SearchGroupFilterTemplate() string {
	return "(&(objectCategory=group)(cn=%s))"
}

// ATTRS

func (a MSADAdapter) UserAttrs() []string {
	return []string{
		// common
		"cn",
		"distinguishedName",

		// personal
		"name",
		"sAMAccountName",
		"userPrincipalName",
		"givenName",
		"sn",
		"initials",
		"displayName",
		"description",
		"mail",

		// title and department info
		"title",
		"department",
		"company",
		"manager",
		"employeeID",
		"roomNumber",

		// address
		"street",
		"streetAddress",
		"l",
		"st",
		"co",
		"postalCode",

		// additional
		"userAccountControl",
		"memberOf",
		"objectGUID",
		"objectSid",

		// phone
		"telephoneNumber",
		"mobile",
		"ipPhone",

		// photo
		"thumbnailPhoto",
		"jpegPhoto",
	}
}

func (a MSADAdapter) ShortUserAttrs() []string {
	return []string{
		"distinguishedName",
		"cn",
		"mail",
		"userPrincipalName",
		"title",
		"department",
	}
}

func (a MSADAdapter) OUAttrs() []string {
	return []string{
		"distinguishedName",
		"name",
		"objectClass",
		"objectGUID",
		"description",
		"managedBy",
	}
}

func (a MSADAdapter) GroupAttrs() []string {
	return []string{
		"cn",
		"distinguishedName",
		"sAMAccountName",
		"groupType",
		"member",
		"memberOf",
		"description",
		"objectGUID",
	}
}
