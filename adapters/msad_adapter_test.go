// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"

	"github.com/NGRsoftlab/ldapper/types"
)

func TestMSADAdapter_GetNormalizedUserInfo_FullAttributes(t *testing.T) {
	adapter := MSADAdapter{}
	user := newLDAPUser("cn=John Doe,ou=people,dc=example,dc=com", map[string][]string{
		"distinguishedName": {"cn=John Doe,ou=people,dc=example,dc=com"},
		"cn":                {"John Doe"},
		"mobile":            {"+7-999-123-45-67"},
		"telephoneNumber":   {"+7-495-123-45-67"},
		"mail":              {"john.doe@example.com"},
		"department":        {"IT"},
		"title":             {"Engineer"},
		"manager":           {"cn=Jane Boss,ou=people,dc=example,dc=com"},
		"thumbnailPhoto":    {"thumb-bytes"},
		"jpegPhoto":         {"jpeg-bytes"},
		"company":           {"Example Inc."},
		"co":                {"RU"},
		"streetAddress":     {"Tverskaya 1"},
		"l":                 {"Moscow"},
		"postalCode":        {"101000"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	assert.Equal(t, "cn=John Doe,ou=people,dc=example,dc=com", info.DistinguishedName)
	assert.Equal(t, "John Doe", info.CommonName)
	assert.Equal(t, "+7-999-123-45-67", info.Mobile)
	assert.Equal(t, "+7-495-123-45-67", info.Phone)
	assert.Equal(t, "john.doe@example.com", info.Mail)
	assert.Equal(t, "IT", info.Department)
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "cn=Jane Boss,ou=people,dc=example,dc=com", info.Manager)
	assert.Equal(t, "thumb-bytes", info.Photo, "if there is thumbnailPhoto - it has more priority")
	assert.Equal(t, "Example Inc.", info.Company)
	assert.Equal(t, "RU", info.Country)
	assert.Equal(t, "Tverskaya 1", info.Address)
	assert.Equal(t, "Moscow", info.City)
	assert.Equal(t, "101000", info.Index)
}

func TestMSADAdapter_GetNormalizedUserInfo_PhotoFallbackToJpeg(t *testing.T) {
	adapter := MSADAdapter{}
	user := newLDAPUser("cn=John Doe,dc=example,dc=com", map[string][]string{
		"cn":        {"John Doe"},
		"jpegPhoto": {"jpeg-bytes"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	assert.Equal(t, "jpeg-bytes", info.Photo, "when no thumbnailPhoto - take jpegPhoto")
}

func TestMSADAdapter_GetNormalizedUserInfo_NoPhoto(t *testing.T) {
	adapter := MSADAdapter{}
	user := newLDAPUser("cn=John Doe,dc=example,dc=com", map[string][]string{
		"cn": {"John Doe"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	assert.Equal(t, "", info.Photo)
}

func TestMSADAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	// empty LDAPUser (zero value) — all fields empty, must be no error/panic
	adapter := MSADAdapter{}
	user := types.LDAPUser{}

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	assert.Equal(t, "", info.DistinguishedName)
	assert.Equal(t, "", info.CommonName)
	assert.Equal(t, "", info.Mobile)
	assert.Equal(t, "", info.Phone)
	assert.Equal(t, "", info.Mail)
	assert.Equal(t, "", info.Department)
	assert.Equal(t, "", info.Title)
	assert.Equal(t, "", info.Manager)
	assert.Equal(t, "", info.Photo)
	assert.Equal(t, "", info.Company)
	assert.Equal(t, "", info.Country)
	assert.Equal(t, "", info.Address)
	assert.Equal(t, "", info.City)
	assert.Equal(t, "", info.Index)
}

func TestMSADAdapter_GetNormalizedUserInfo_NilAttributesMap(t *testing.T) {
	// Attributes == nil must not lead to panic:
	// GetAttributeValue/GetFirstNonNullAttributeValue must process correctly nil-map (check fact behavior).
	adapter := MSADAdapter{}
	user := types.LDAPUser{DN: "cn=User,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		info := adapter.GetNormalizedUserInfo(user)
		assert.NotNil(t, info)
		assert.Empty(t, info.CommonName)
		assert.Empty(t, info.Photo)
	})
}

func TestMSADAdapter_GetNormalizedUserInfo_OnlyDistinguishedName(t *testing.T) {
	adapter := MSADAdapter{}
	user := newLDAPUser("cn=User,dc=example,dc=com", map[string][]string{
		"distinguishedName": {"cn=User,dc=example,dc=com"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	assert.Equal(t, "cn=User,dc=example,dc=com", info.DistinguishedName)
	assert.Empty(t, info.CommonName)
}

func TestMSADAdapter_OUInfoFromEntry_FullAttributes(t *testing.T) {
	adapter := MSADAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,ou=Departments,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IT"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.DN)
	assert.Equal(t, "IT", info.Name)
	// OU is intentionally set to the entry DN, not to a separate attribute.
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.OU)
}

func TestMSADAdapter_OUInfoFromEntry_ChildrenInitialized(t *testing.T) {
	// Children must be a non-nil, empty slice so callers can safely append
	// without a nil check.
	adapter := MSADAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IT"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info.Children, "Children must be initialized, not nil")
	assert.Empty(t, info.Children)
}

func TestMSADAdapter_OUInfoFromEntry_ChildrenAppendable(t *testing.T) {
	// Verify that appending to Children does not panic — a nil slice
	// would also support append, but the test documents the intended
	// non-nil contract and catches accidental removal of the initialization.
	adapter := MSADAdapter{}
	entry := ldap.Entry{DN: "ou=IT,dc=example,dc=com"}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotPanics(t, func() {
		info.Children = append(info.Children, &types.OUInfo{DN: "ou=Sub,ou=IT,dc=example,dc=com"})
	})
	assert.Len(t, info.Children, 1)
}

func TestMSADAdapter_OUInfoFromEntry_MissingNameAttribute(t *testing.T) {
	// If the "name" attribute is absent, Name stays empty — no error, no panic.
	adapter := MSADAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"organizationalUnit"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
	assert.Empty(t, info.Name)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.OU)
}

func TestMSADAdapter_OUInfoFromEntry_EmptyEntry(t *testing.T) {
	// An empty ldap.Entry (zero value) must not cause a panic.
	adapter := MSADAdapter{}
	entry := ldap.Entry{}

	assert.NotPanics(t, func() {
		info := adapter.OUInfoFromEntry(entry)
		assert.NotNil(t, info)
		assert.Empty(t, info.DN)
		assert.Empty(t, info.Name)
		assert.Empty(t, info.OU)
		assert.NotNil(t, info.Children)
		assert.Empty(t, info.Children)
	})
}

func TestMSADAdapter_OUInfoFromEntry_NilAttributes(t *testing.T) {
	// Attributes == nil must not cause a panic when reading "name".
	adapter := MSADAdapter{}
	entry := ldap.Entry{
		DN:         "ou=IT,dc=example,dc=com",
		Attributes: nil,
	}

	assert.NotPanics(t, func() {
		info := adapter.OUInfoFromEntry(entry)
		assert.NotNil(t, info)
		assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
		assert.Empty(t, info.Name)
	})
}

func TestMSADAdapter_OUInfoFromEntry_UsesFirstValueOfMultiValuedName(t *testing.T) {
	// ldap.Entry.GetAttributeValue returns the first value for multi-valued
	// attributes. Pin this behavior so a refactor cannot silently change it.
	adapter := MSADAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IT", "Information Technology"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "IT", info.Name,
		"GetAttributeValue returns the first value of a multi-valued attribute")
}

func TestMSADAdapter_OUInfoFromEntry_IgnoresUnrelatedAttributes(t *testing.T) {
	// Only "name" is used; other attributes present on the entry must not
	// leak into the resulting OUInfo fields.
	adapter := MSADAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IT"}},
			{Name: "description", Values: []string{"IT department"}},
			{Name: "managedBy", Values: []string{"cn=boss,dc=example,dc=com"}},
			{Name: "objectGUID", Values: []string{"guid-bytes"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
	assert.Equal(t, "IT", info.Name)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.OU)
	assert.Empty(t, info.Children)
	// OUInfo has no fields for description/managedBy/objectGUID —
	// this assertion documents that the mapping is limited to DN/Name/OU.
}

// ---------- TYPE FILTERS ----------

func TestMSADAdapter_OUObjectFilter(t *testing.T) {
	adapter := MSADAdapter{}
	assert.Equal(t, "(&(objectClass=organizationalUnit))", adapter.OUObjectFilter())
}

func TestMSADAdapter_GroupObjectFilter(t *testing.T) {
	adapter := MSADAdapter{}
	assert.Equal(t, "(&(objectCategory=group))", adapter.GroupObjectFilter())
}

func TestMSADAdapter_UserObjectFilter(t *testing.T) {
	adapter := MSADAdapter{}
	assert.Equal(t, "(&(objectClass=user)(objectCategory=person))", adapter.UserObjectFilter())
}

// ---------- SEARCH ----------

func TestMSADAdapter_SearchUserFilterTemplate(t *testing.T) {
	adapter := MSADAdapter{}
	assert.Equal(t,
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))",
		adapter.SearchUserFilterTemplate(),
	)
}

func TestMSADAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	adapter := MSADAdapter{}
	// Check being present OID 1.2.840.113556.1.4.1941 (LDAP_MATCHING_RULE_IN_CHAIN) —
	// without it - no recursive search in AD
	assert.Equal(t,
		"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=%s))",
		adapter.SearchUserGroupsFilterTemplate(),
	)
}

func TestMSADAdapter_SearchOUFilterTemplate(t *testing.T) {
	adapter := MSADAdapter{}
	assert.Equal(t,
		"(&(objectClass=organizationalUnit)(ou=%s))",
		adapter.SearchOUFilterTemplate(),
	)
}

func TestMSADAdapter_SearchGroupFilterTemplate(t *testing.T) {
	adapter := MSADAdapter{}
	assert.Equal(t,
		"(&(objectCategory=group)(cn=%s))",
		adapter.SearchGroupFilterTemplate(),
	)
}

// ---------- SearchUserGroupsFilterTemplateArgs ----------

func TestMSADAdapter_SearchUserGroupsFilterTemplateArgs_UsesUserDN(t *testing.T) {
	adapter := MSADAdapter{}
	user := newLDAPUser("cn=John Doe,ou=people,dc=example,dc=com", nil)

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 1)
	assert.Equal(t, "cn=John Doe,ou=people,dc=example,dc=com", args[0])
}

func TestMSADAdapter_SearchUserGroupsFilterTemplateArgs_IgnoresDistinguishedNameAttr(t *testing.T) {
	adapter := MSADAdapter{}
	user := newLDAPUser("uid=other,dc=example,dc=com", map[string][]string{
		"distinguishedName": {"cn=IGNORED,dc=example,dc=com"},
	})

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 1)
	assert.Equal(t, "uid=other,dc=example,dc=com", args[0],
		"user DN must be in arg, no distinguishedName")
}

func TestMSADAdapter_SearchUserGroupsFilterTemplateArgs_EmptyDN(t *testing.T) {
	adapter := MSADAdapter{}
	user := types.LDAPUser{}

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 1)
	assert.Equal(t, "", args[0])
}

// ---------- ATTRS ----------

func TestMSADAdapter_UserAttrs(t *testing.T) {
	adapter := MSADAdapter{}

	expected := []string{
		// common
		"cn", "distinguishedName",
		// personal
		"name", "sAMAccountName", "userPrincipalName", "givenName", "sn",
		"initials", "displayName", "description", "mail",
		// title and department info
		"title", "department", "company", "manager", "employeeID", "roomNumber",
		// address
		"street", "streetAddress", "l", "st", "co", "postalCode",
		// additional
		"userAccountControl", "memberOf", "objectGUID", "objectSid",
		// phone
		"telephoneNumber", "mobile", "ipPhone",
		// photo
		"thumbnailPhoto", "jpegPhoto",
	}

	assert.Equal(t, expected, adapter.UserAttrs())
}

func TestMSADAdapter_UserAttrs_ContainsCriticalAttributes(t *testing.T) {
	adapter := MSADAdapter{}
	attrs := adapter.UserAttrs()

	critical := []string{
		"sAMAccountName", "userPrincipalName", "mail", "distinguishedName",
		"thumbnailPhoto", "jpegPhoto", "objectGUID", "objectSid", "memberOf",
		"telephoneNumber", "mobile", "department", "title", "manager",
	}

	for _, attr := range critical {
		assert.Contains(t, attrs, attr, "critical attr %q is not present UserAttrs", attr)
	}
}

func TestMSADAdapter_UserAttrs_NoDuplicates(t *testing.T) {
	adapter := MSADAdapter{}
	seen := make(map[string]struct{}, len(adapter.UserAttrs()))

	for _, attr := range adapter.UserAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("attr duplicate in UserAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}

func TestMSADAdapter_ShortUserAttrs(t *testing.T) {
	adapter := MSADAdapter{}

	expected := []string{
		"distinguishedName", "cn", "mail", "userPrincipalName", "title", "department",
	}

	assert.Equal(t, expected, adapter.ShortUserAttrs())
}

func TestMSADAdapter_ShortUserAttrs_SubsetOfUserAttrs(t *testing.T) {
	// Must: ShortUserAttrs ⊆ UserAttrs. Otherwise GetUser and GetOUUsers can return different attrs for the same user
	adapter := MSADAdapter{}
	full := make(map[string]struct{}, len(adapter.UserAttrs()))
	for _, attr := range adapter.UserAttrs() {
		full[attr] = struct{}{}
	}

	for _, attr := range adapter.ShortUserAttrs() {
		_, ok := full[attr]
		assert.True(t, ok, "attr %q from ShortUserAttrs is not present in UserAttrs", attr)
	}
}

func TestMSADAdapter_OUAttrs(t *testing.T) {
	adapter := MSADAdapter{}

	expected := []string{
		"distinguishedName", "name", "objectClass", "objectGUID", "description", "managedBy",
	}

	assert.Equal(t, expected, adapter.OUAttrs())
}

func TestMSADAdapter_GroupAttrs(t *testing.T) {
	adapter := MSADAdapter{}

	expected := []string{
		"cn", "distinguishedName", "sAMAccountName", "groupType",
		"member", "memberOf", "description", "objectGUID",
	}

	assert.Equal(t, expected, adapter.GroupAttrs())
}

func TestMSADAdapter_GroupAttrs_NoDuplicates(t *testing.T) {
	adapter := MSADAdapter{}
	seen := make(map[string]struct{}, len(adapter.GroupAttrs()))

	for _, attr := range adapter.GroupAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("attr duplicate in GroupAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}
