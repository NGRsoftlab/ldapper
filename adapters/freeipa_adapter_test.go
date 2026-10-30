// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"

	"github.com/NGRsoftlab/ldapper/types"
)

// ---------- GetNormalizedUserInfo ----------

func TestFREEIPAAdapter_GetNormalizedUserInfo_FullAttributes(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,cn=users,cn=accounts,dc=example,dc=com", map[string][]string{
		"dn":              {"uid=jdoe,cn=users,cn=accounts,dc=example,dc=com"},
		"cn":              {"John Doe"},
		"mobile":          {"+7-999-123-45-67"},
		"telephoneNumber": {"+7-495-123-45-67"},
		"mail":            {"jdoe@example.com"},
		"title":           {"Engineer"},
		"manager":         {"uid=jboss,cn=users,cn=accounts,dc=example,dc=com"},
		"jpegPhoto":       {"jpeg-bytes"},
		"co":              {"RU"},
		"street":          {"Tverskaya 1"},
		"l":               {"Moscow"},
		"postalCode":      {"101000"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	// FREEIPA reads DN from the "dn" attribute, not from the struct field.
	assert.Equal(t, "uid=jdoe,cn=users,cn=accounts,dc=example,dc=com", info.DistinguishedName)
	assert.Equal(t, "John Doe", info.CommonName)
	assert.Equal(t, "+7-999-123-45-67", info.Mobile)
	assert.Equal(t, "+7-495-123-45-67", info.Phone)
	assert.Equal(t, "jdoe@example.com", info.Mail)
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "uid=jboss,cn=users,cn=accounts,dc=example,dc=com", info.Manager)
	assert.Equal(t, "jpeg-bytes", info.Photo)
	// Company and Department are hardcoded to empty in the FREEIPA adapter.
	assert.Empty(t, info.Company)
	assert.Empty(t, info.Department)
	assert.Equal(t, "RU", info.Country)
	// FREEIPA reads the address from "street", not "streetAddress".
	assert.Equal(t, "Tverskaya 1", info.Address)
	assert.Equal(t, "Moscow", info.City)
	assert.Equal(t, "101000", info.Index)
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	adapter := FREEIPAAdapter{}
	info := adapter.GetNormalizedUserInfo(types.LDAPUser{})

	assert.NotNil(t, info)
	assert.Empty(t, info.DistinguishedName)
	assert.Empty(t, info.CommonName)
	assert.Empty(t, info.Mobile)
	assert.Empty(t, info.Phone)
	assert.Empty(t, info.Mail)
	assert.Empty(t, info.Department)
	assert.Empty(t, info.Title)
	assert.Empty(t, info.Manager)
	assert.Empty(t, info.Photo)
	assert.Empty(t, info.Company)
	assert.Empty(t, info.Country)
	assert.Empty(t, info.Address)
	assert.Empty(t, info.City)
	assert.Empty(t, info.Index)
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_NilAttributesMap(t *testing.T) {
	// A nil Attributes map must not cause a panic.
	adapter := FREEIPAAdapter{}
	user := types.LDAPUser{DN: "uid=jdoe,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		info := adapter.GetNormalizedUserInfo(user)
		assert.NotNil(t, info)
		assert.Empty(t, info.CommonName)
	})
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_DistinguishedNameFromAttrOnly(t *testing.T) {
	// DN must come from the "dn" attribute; the struct's DN field is ignored.
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"cn": {"John Doe"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.DistinguishedName,
		"DistinguishedName must be filled only from the \"dn\" attribute")
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_PhotoOnlyJpeg(t *testing.T) {
	// Unlike MSAD, FREEIPA does not fall back to thumbnailPhoto.
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"thumbnailPhoto": {"thumb-bytes"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Photo, "thumbnailPhoto is not used by the FREEIPA adapter")
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_DepartmentAlwaysEmpty(t *testing.T) {
	// Department is hardcoded to empty. Any "department" / "departmentNumber" /
	// "rbtadp" attribute present on the entry must be ignored — unlike in
	// MSAD (department) or ALDRPO (rbtadp).
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"department":       {"IT"},
		"departmentNumber": {"IT-42"},
		"rbtadp":           {"IT-43"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Department)
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_AddressFromStreetOnly(t *testing.T) {
	// Address must be read from "street", not "streetAddress".
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"street":        {"Tverskaya 1"},
		"streetAddress": {"IGNORED"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Equal(t, "Tverskaya 1", info.Address)
	assert.NotEqual(t, "IGNORED", info.Address)
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_StreetAddressIgnored(t *testing.T) {
	// If only "streetAddress" is present, Address stays empty.
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"streetAddress": {"IGNORED"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Address)
}

// ---------- OUInfoFromEntry ----------

func TestFREEIPAAdapter_OUInfoFromEntry_FullAttributes(t *testing.T) {
	adapter := FREEIPAAdapter{}
	entry := ldap.Entry{
		DN: "cn=users,cn=accounts,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"users"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "cn=users,cn=accounts,dc=example,dc=com", info.DN)
	// Name equals the entry DN, not a "name" attribute.
	assert.Equal(t, "cn=users,cn=accounts,dc=example,dc=com", info.Name)
	// OU comes from the "ou" attribute, not from the DN.
	assert.Equal(t, "users", info.OU)
}

func TestFREEIPAAdapter_OUInfoFromEntry_NameIsAlwaysDN(t *testing.T) {
	// Name must equal DN regardless of any other attributes present.
	adapter := FREEIPAAdapter{}
	entry := ldap.Entry{
		DN: "cn=accounts,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IGNORED"}},
			{Name: "cn", Values: []string{"accounts"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "cn=accounts,dc=example,dc=com", info.Name)
	assert.NotEqual(t, "IGNORED", info.Name)
}

func TestFREEIPAAdapter_OUInfoFromEntry_MissingOUAttribute(t *testing.T) {
	// nsContainer entries may lack an "ou" attribute; OU stays empty.
	adapter := FREEIPAAdapter{}
	entry := ldap.Entry{
		DN: "cn=users,cn=accounts,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"nsContainer"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "cn=users,cn=accounts,dc=example,dc=com", info.DN)
	assert.Equal(t, "cn=users,cn=accounts,dc=example,dc=com", info.Name)
	assert.Empty(t, info.OU)
}

func TestFREEIPAAdapter_OUInfoFromEntry_ChildrenInitialized(t *testing.T) {
	// Children must be a non-nil empty slice so callers can append safely.
	adapter := FREEIPAAdapter{}
	info := adapter.OUInfoFromEntry(ldap.Entry{DN: "cn=users,dc=example,dc=com"})

	assert.NotNil(t, info.Children)
	assert.Empty(t, info.Children)
}

func TestFREEIPAAdapter_OUInfoFromEntry_EmptyEntry(t *testing.T) {
	adapter := FREEIPAAdapter{}

	assert.NotPanics(t, func() {
		info := adapter.OUInfoFromEntry(ldap.Entry{})
		assert.NotNil(t, info)
		assert.Empty(t, info.DN)
		assert.Empty(t, info.Name)
		assert.Empty(t, info.OU)
		assert.NotNil(t, info.Children)
	})
}

func TestFREEIPAAdapter_OUInfoFromEntry_NilAttributes(t *testing.T) {
	adapter := FREEIPAAdapter{}
	entry := ldap.Entry{DN: "cn=users,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		info := adapter.OUInfoFromEntry(entry)
		assert.Equal(t, "cn=users,dc=example,dc=com", info.DN)
		assert.Equal(t, "cn=users,dc=example,dc=com", info.Name)
		assert.Empty(t, info.OU)
	})
}

func TestFREEIPAAdapter_OUInfoFromEntry_UsesFirstValueOfMultiValuedOU(t *testing.T) {
	// Pin GetAttributeValue behavior for multi-valued "ou".
	adapter := FREEIPAAdapter{}
	entry := ldap.Entry{
		DN: "cn=users,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"users", "People"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "users", info.OU)
}

// ---------- TYPE FILTERS ----------

func TestFREEIPAAdapter_OUObjectFilter(t *testing.T) {
	adapter := FREEIPAAdapter{}
	// nsContainer is the FreeIPA-specific container class that complements
	// (or replaces) organizationalUnit for some entries.
	assert.Equal(t,
		"(|(objectClass=organizationalUnit)(objectClass=nsContainer))",
		adapter.OUObjectFilter(),
	)
}

func TestFREEIPAAdapter_GroupObjectFilter(t *testing.T) {
	adapter := FREEIPAAdapter{}
	assert.Equal(t,
		"(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))",
		adapter.GroupObjectFilter(),
	)
}

func TestFREEIPAAdapter_UserObjectFilter(t *testing.T) {
	adapter := FREEIPAAdapter{}
	assert.Equal(t,
		"(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))",
		adapter.UserObjectFilter(),
	)
}

// ---------- SEARCH ----------

func TestFREEIPAAdapter_SearchUserFilterTemplate(t *testing.T) {
	adapter := FREEIPAAdapter{}
	assert.Equal(t,
		"(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(uid=%s))",
		adapter.SearchUserFilterTemplate(),
	)
}

func TestFREEIPAAdapter_SearchUserFilterTemplate_FormatsUsername(t *testing.T) {
	adapter := FREEIPAAdapter{}
	filter := fmt.Sprintf(adapter.SearchUserFilterTemplate(), "jdoe")

	assert.Equal(t,
		"(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(uid=jdoe))",
		filter,
	)
	assert.NotContains(t, filter, "%", "no unresolved placeholders should remain")
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	adapter := FREEIPAAdapter{}

	// NB: "member=uid=%s" is semantically unusual — `member` is normally
	// a DN-valued attribute, not a uid. Pinned here to detect unintended
	// changes; if the adapter is corrected, update this test accordingly.
	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=uid=%s))",
		adapter.SearchUserGroupsFilterTemplate(),
	)
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplate_HasOnePlaceholder(t *testing.T) {
	adapter := FREEIPAAdapter{}
	template := adapter.SearchUserGroupsFilterTemplate()

	assert.Equal(t, 1, strings.Count(template, "%s"),
		"template is expected to contain exactly one placeholder")
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplate_FormatsCleanly(t *testing.T) {
	// Template has 1 placeholder and SearchUserGroupsFilterTemplateArgs returns
	// 1 arg — formatting must produce a clean filter with no artifacts.
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
		map[string][]string{"uid": {"jdoe"}})
	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	filter := fmt.Sprintf(adapter.SearchUserGroupsFilterTemplate(), args...)

	assert.NotContains(t, filter, "%!",
		"formatting must not produce an EXTRA/placeholder-mismatch artifact")
	assert.NotContains(t, filter, "%s",
		"no unresolved placeholder should remain")
	assert.Contains(t, filter, "uid=jdoe")
}

func TestFREEIPAAdapter_SearchOUFilterTemplate(t *testing.T) {
	adapter := FREEIPAAdapter{}
	// Both organizationalUnit and nsContainer must be matched.
	assert.Equal(t,
		"(&(|(objectClass=organizationalUnit)(objectClass=nsContainer))(ou=%s))",
		adapter.SearchOUFilterTemplate(),
	)
}

func TestFREEIPAAdapter_SearchGroupFilterTemplate(t *testing.T) {
	adapter := FREEIPAAdapter{}
	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(cn=%s))",
		adapter.SearchGroupFilterTemplate(),
	)
}

// TestFREEIPAAdapter_AllSearchTemplates_BalancedParentheses is a regression
// guard against malformed filters that LDAP servers would reject.
func TestFREEIPAAdapter_AllSearchTemplates_BalancedParentheses(t *testing.T) {
	adapter := FREEIPAAdapter{}

	templates := map[string]string{
		"SearchUserFilterTemplate":       adapter.SearchUserFilterTemplate(),
		"SearchUserGroupsFilterTemplate": adapter.SearchUserGroupsFilterTemplate(),
		"SearchOUFilterTemplate":         adapter.SearchOUFilterTemplate(),
		"SearchGroupFilterTemplate":      adapter.SearchGroupFilterTemplate(),
	}
	for name, tmpl := range templates {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, strings.Count(tmpl, "("), strings.Count(tmpl, ")"),
				"parentheses must be balanced")
			assert.True(t, strings.HasPrefix(tmpl, "("), "filter must start with '('")
			assert.True(t, strings.HasSuffix(tmpl, ")"), "filter must end with ')'")
		})
	}
}

// ---------- SearchUserGroupsFilterTemplateArgs ----------

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs_ReturnsUID(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,cn=users,cn=accounts,dc=example,dc=com",
		map[string][]string{"uid": {"jdoe"}})

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 1, "exactly one arg to match the single %s placeholder")
	assert.Equal(t, "jdoe", args[0],
		"the arg is the user's uid, taken from the \"uid\" attribute")
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs_IgnoresDN(t *testing.T) {
	// The DN is not used by this adapter's filter — unlike MSAD, which uses
	// LDAPUser.DN directly.
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
		"dn":  {"cn=IGNORED,dc=example,dc=com"},
	})

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 1)
	assert.Equal(t, "jdoe", args[0])
	assert.NotEqual(t, "uid=jdoe,dc=example,dc=com", args[0])
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs_EmptyUser(t *testing.T) {
	adapter := FREEIPAAdapter{}
	args := adapter.SearchUserGroupsFilterTemplateArgs(types.LDAPUser{})

	assert.Len(t, args, 1)
	assert.Equal(t, "", args[0])
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs_NilAttributesMap(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := types.LDAPUser{DN: "uid=jdoe,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		args := adapter.SearchUserGroupsFilterTemplateArgs(user)
		assert.Len(t, args, 1)
		assert.Equal(t, "", args[0])
	})
}

// ---------- ATTRS ----------

func TestFREEIPAAdapter_UserAttrs(t *testing.T) {
	adapter := FREEIPAAdapter{}

	expected := []string{
		"dn",

		"uid", "cn", "givenName", "sn", "displayName", "mail",
		"telephoneNumber", "mobile", "title", "ou", "o", "jpegPhoto",

		"nsAccountLock",

		// system&posix attrs
		"uidNumber", "gidNumber", "homeDirectory", "memberOf", "ipaUniqueID",

		// address
		"street", "l", "st", "postalCode",

		// may be or not to be at all attrs
		"description", "manager", "co",
	}

	assert.Equal(t, expected, adapter.UserAttrs())
}

func TestFREEIPAAdapter_UserAttrs_ContainsCriticalAttributes(t *testing.T) {
	adapter := FREEIPAAdapter{}
	attrs := adapter.UserAttrs()

	critical := []string{
		"dn", "cn", "uid", "mail", "mobile", "telephoneNumber",
		"jpegPhoto", "manager", "title", "co",
		"uidNumber", "gidNumber", "homeDirectory", "memberOf",
		"ipaUniqueID", "nsAccountLock",
		"street", "l", "st", "postalCode",
	}
	for _, attr := range critical {
		assert.Contains(t, attrs, attr, "critical attribute %q is missing", attr)
	}
}

func TestFREEIPAAdapter_UserAttrs_FreeIPASpecific(t *testing.T) {
	// nsAccountLock and ipaUniqueID are FreeIPA-specific attributes.
	adapter := FREEIPAAdapter{}
	attrs := adapter.UserAttrs()

	for _, attr := range []string{"nsAccountLock", "ipaUniqueID"} {
		assert.Contains(t, attrs, attr, "FreeIPA-specific attribute %q is missing", attr)
	}
}

func TestFREEIPAAdapter_UserAttrs_NoDuplicates(t *testing.T) {
	adapter := FREEIPAAdapter{}
	seen := make(map[string]struct{}, len(adapter.UserAttrs()))
	for _, attr := range adapter.UserAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in UserAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}

func TestFREEIPAAdapter_OUAttrs(t *testing.T) {
	adapter := FREEIPAAdapter{}

	expected := []string{"dn", "ou", "objectClass", "description"}
	assert.Equal(t, expected, adapter.OUAttrs())
}

func TestFREEIPAAdapter_OUAttrs_IncludesObjectClass(t *testing.T) {
	// objectClass is required to distinguish nsContainer from
	// organizationalUnit at read time.
	adapter := FREEIPAAdapter{}

	assert.Contains(t, adapter.OUAttrs(), "objectClass")
}

func TestFREEIPAAdapter_GroupAttrs(t *testing.T) {
	adapter := FREEIPAAdapter{}

	expected := []string{
		"cn",
		"ou",
		"description",
		"objectClass",

		"gidNumber", // posixGroup
		"memberUid", // posixGroup

		"member",
		"memberIndirect",
		"memberOf",

		"mepManagedBy",
		"ipaUniqueID",
		"ipaNTSecurityIdentifier",
	}
	assert.Equal(t, expected, adapter.GroupAttrs())
}

func TestFREEIPAAdapter_GroupAttrs_ContainsBothGroupTypes(t *testing.T) {
	// GroupAttrs must cover groupOfNames, posixGroup and ipausergroup.
	adapter := FREEIPAAdapter{}
	attrs := adapter.GroupAttrs()

	// groupOfNames
	for _, attr := range []string{"cn", "member"} {
		assert.Contains(t, attrs, attr, "groupOfNames: attribute %q is missing", attr)
	}
	// posixGroup
	for _, attr := range []string{"gidNumber", "memberUid"} {
		assert.Contains(t, attrs, attr, "posixGroup: attribute %q is missing", attr)
	}
	// ipausergroup
	for _, attr := range []string{"ipaUniqueID", "ipaNTSecurityIdentifier"} {
		assert.Contains(t, attrs, attr, "ipausergroup: attribute %q is missing", attr)
	}
}

func TestFREEIPAAdapter_GroupAttrs_NoDuplicates(t *testing.T) {
	adapter := FREEIPAAdapter{}
	seen := make(map[string]struct{}, len(adapter.GroupAttrs()))
	for _, attr := range adapter.GroupAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in GroupAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}
