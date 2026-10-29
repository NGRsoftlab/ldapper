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

func TestOPENLDAPAdapter_GetNormalizedUserInfo_FullAttributes(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	user := newLDAPUser("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"dn":               {"uid=jdoe,ou=people,dc=example,dc=com"},
		"cn":               {"John Doe"},
		"mobile":           {"+7-999-123-45-67"},
		"telephoneNumber":  {"+7-495-123-45-67"},
		"mail":             {"jdoe@example.com"},
		"departmentNumber": {"IT-42"},
		"title":            {"Engineer"},
		"manager":          {"uid=jboss,ou=people,dc=example,dc=com"},
		"jpegPhoto":        {"jpeg-bytes"},
		"postalAddress":    {"Tverskaya 1, Moscow, 101000"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	// OpenLDAP adapter reads DN from the "dn" attribute, not from the struct field.
	assert.Equal(t, "uid=jdoe,ou=people,dc=example,dc=com", info.DistinguishedName)
	assert.Equal(t, "John Doe", info.CommonName)
	assert.Equal(t, "+7-999-123-45-67", info.Mobile)
	assert.Equal(t, "+7-495-123-45-67", info.Phone)
	assert.Equal(t, "jdoe@example.com", info.Mail)
	// OpenLDAP stores department in departmentNumber, unlike AD's "department".
	assert.Equal(t, "IT-42", info.Department)
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "uid=jboss,ou=people,dc=example,dc=com", info.Manager)
	assert.Equal(t, "jpeg-bytes", info.Photo)
	assert.Equal(t, "Tverskaya 1, Moscow, 101000", info.Address)
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_UnsetFieldsAreEmpty(t *testing.T) {
	// Company, Country, City and Index are hardcoded to empty strings
	// in the OpenLDAP adapter, even when the corresponding LDAP attributes exist.
	adapter := OPENLDAPAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"cn":         {"John Doe"},
		"company":    {"Example Inc."},
		"co":         {"RU"},
		"l":          {"Moscow"},
		"postalCode": {"101000"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Company)
	assert.Empty(t, info.Country)
	assert.Empty(t, info.City)
	assert.Empty(t, info.Index)
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_DistinguishedNameFromAttrNotFromField(t *testing.T) {
	// Key difference from MSAD: DN is taken from the "dn" attribute,
	// not from the LDAPUser.DN field. If the attribute is missing,
	// the resulting DistinguishedName stays empty even when LDAPUser.DN is set.
	adapter := OPENLDAPAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"cn": {"John Doe"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.DistinguishedName,
		"DistinguishedName must be filled only from the \"dn\" attribute")
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	user := types.LDAPUser{}

	info := adapter.GetNormalizedUserInfo(user)

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
	assert.Empty(t, info.Address)
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_NilAttributesMap(t *testing.T) {
	// A nil Attributes map must not cause a panic.
	adapter := OPENLDAPAdapter{}
	user := types.LDAPUser{DN: "uid=jdoe,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		info := adapter.GetNormalizedUserInfo(user)
		assert.NotNil(t, info)
	})
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_PhotoFromJpegOnly(t *testing.T) {
	// Unlike the MSAD adapter, OpenLDAP does not fall back to thumbnailPhoto;
	// only jpegPhoto is used.
	adapter := OPENLDAPAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"cn":             {"John Doe"},
		"thumbnailPhoto": {"thumb-bytes"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Photo, "thumbnailPhoto is not used by the OpenLDAP adapter")
}

func TestOPENLDAPAdapter_OUInfoFromEntry_FullAttributes(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,ou=Departments,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.DN)
	// Unlike MSAD, Name is set to the entry DN, not to the "name" attribute.
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.Name)
	// OU is read from the "ou" attribute, not from the DN.
	assert.Equal(t, "IT", info.OU)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_NameIsDN(t *testing.T) {
	// Key difference from MSADAdapter: Name is always the full DN,
	// regardless of the "name" or "ou" attributes present on the entry.
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
			{Name: "name", Values: []string{"IGNORED-NAME"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name,
		"Name must be the entry DN, not the \"name\" attribute")
	assert.NotEqual(t, "IGNORED-NAME", info.Name)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_OUFromAttribute(t *testing.T) {
	// OU comes from the "ou" attribute, unlike MSAD where OU is the DN.
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "IT", info.OU,
		"OU must come from the \"ou\" attribute, not from the DN")
}

func TestOPENLDAPAdapter_OUInfoFromEntry_MissingOUAttribute(t *testing.T) {
	// If the "ou" attribute is absent, OU stays empty — no error, no panic.
	// Name and DN are still populated from entry.DN.
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"organizationalUnit"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name)
	assert.Empty(t, info.OU)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_ChildrenInitialized(t *testing.T) {
	// Children must be a non-nil, empty slice so callers can safely append
	// without a nil check.
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info.Children, "Children must be initialized, not nil")
	assert.Empty(t, info.Children)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_ChildrenAppendable(t *testing.T) {
	// Verify that appending to Children works and does not panic.
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{DN: "ou=IT,dc=example,dc=com"}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotPanics(t, func() {
		info.Children = append(info.Children, &types.OUInfo{DN: "ou=Sub,ou=IT,dc=example,dc=com"})
	})
	assert.Len(t, info.Children, 1)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_EmptyEntry(t *testing.T) {
	// An empty ldap.Entry (zero value) must not cause a panic.
	adapter := OPENLDAPAdapter{}
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

func TestOPENLDAPAdapter_OUInfoFromEntry_NilAttributes(t *testing.T) {
	// Attributes == nil must not cause a panic when reading "ou".
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN:         "ou=IT,dc=example,dc=com",
		Attributes: nil,
	}

	assert.NotPanics(t, func() {
		info := adapter.OUInfoFromEntry(entry)
		assert.NotNil(t, info)
		assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
		assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name)
		assert.Empty(t, info.OU)
	})
}

func TestOPENLDAPAdapter_OUInfoFromEntry_UsesFirstValueOfMultiValuedOU(t *testing.T) {
	// ldap.Entry.GetAttributeValue returns the first value of a multi-valued
	// attribute. Pin this behavior so a refactor cannot silently change it.
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT", "Information Technology"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "IT", info.OU,
		"GetAttributeValue returns the first value of a multi-valued attribute")
}

func TestOPENLDAPAdapter_OUInfoFromEntry_IgnoresUnrelatedAttributes(t *testing.T) {
	// Only the "ou" attribute is used for the OU field; other attributes
	// present on the entry must not leak into the resulting OUInfo.
	adapter := OPENLDAPAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
			{Name: "description", Values: []string{"IT department"}},
			{Name: "objectClass", Values: []string{"organizationalUnit"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name)
	assert.Equal(t, "IT", info.OU)
	assert.Empty(t, info.Children)
	// OUInfo has no fields for description/objectClass — this assertion
	// documents that the mapping is limited to DN/Name/OU/Children.
}

// ---------- TYPE FILTERS ----------

func TestOPENLDAPAdapter_OUObjectFilter(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	assert.Equal(t, "(&(objectClass=organizationalUnit))", adapter.OUObjectFilter())
}

func TestOPENLDAPAdapter_GroupObjectFilter(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	// OpenLDAP groups are either groupOfNames or posixGroup.
	assert.Equal(t,
		"(|(objectClass=groupOfNames)(objectClass=posixGroup))",
		adapter.GroupObjectFilter(),
	)
}

func TestOPENLDAPAdapter_UserObjectFilter(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	assert.Equal(t, "(&(objectClass=person))", adapter.UserObjectFilter())
}

// ---------- SEARCH ----------

func TestOPENLDAPAdapter_SearchUserFilterTemplate(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	got := adapter.SearchUserFilterTemplate()

	// The template must use the indexed placeholder %[1]s so that the same
	// username argument is substituted into both uid and cn. The whole
	// filter must be wrapped in balanced parentheses.
	assert.Equal(t,
		"(&(!(objectClass=computer))(|(uid=%[1]s)(cn=%[1]s)))",
		got,
	)
}

func TestOPENLDAPAdapter_SearchUserFilterTemplate_FormatsUsernameInBothPlaces(t *testing.T) {
	// The template is fed to fmt.Sprintf with a single argument (the username).
	// Verify that the indexed placeholder produces a well-formed filter with
	// the username substituted into both uid= and cn=.
	adapter := OPENLDAPAdapter{}
	template := adapter.SearchUserFilterTemplate()

	filter := fmt.Sprintf(template, "jdoe")

	assert.Equal(t,
		"(&(!(objectClass=computer))(|(uid=jdoe)(cn=jdoe)))",
		filter,
	)
	assert.NotContains(t, filter, "%", "no unresolved placeholders should remain")
	assert.NotContains(t, filter, "username", "the literal 'username' must not leak into the filter")
}

func TestOPENLDAPAdapter_SearchUserFilterTemplate_ExcludesComputers(t *testing.T) {
	// The template must exclude computer objects — otherwise workstations
	// and servers could be returned as users.
	adapter := OPENLDAPAdapter{}
	got := adapter.SearchUserFilterTemplate()

	assert.Contains(t, got, "(!(objectClass=computer))",
		"computers must be excluded from the user search")
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	got := adapter.SearchUserGroupsFilterTemplate()

	// Exact match: the template must be a single well-formed OR filter
	// covering both groupOfNames and posixGroup.
	assert.Equal(t,
		"(|(&(objectClass=groupOfNames)(member=%s))(&(objectClass=posixGroup)(memberUid=%s)))",
		got,
	)
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplate_HasTwoPlaceholders(t *testing.T) {
	// The template must contain exactly two %s placeholders — one for member
	// and one for memberUid.
	adapter := OPENLDAPAdapter{}
	got := adapter.SearchUserGroupsFilterTemplate()

	assert.Equal(t, 2, strings.Count(got, "%s"),
		"expected two placeholders: member and memberUid")
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplate_FormatsArgs(t *testing.T) {
	// Feed the template with concrete arguments and verify the resulting
	// filter is what an LDAP server would accept.
	adapter := OPENLDAPAdapter{}
	template := adapter.SearchUserGroupsFilterTemplate()

	filter := fmt.Sprintf(template, "uid=jdoe,dc=example,dc=com", "jdoe")

	assert.Equal(t,
		"(|(&(objectClass=groupOfNames)(member=uid=jdoe,dc=example,dc=com))"+
			"(&(objectClass=posixGroup)(memberUid=jdoe)))",
		filter,
	)
	assert.NotContains(t, filter, "%", "no unresolved placeholders should remain")
}

func TestOPENLDAPAdapter_SearchOUFilterTemplate(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	assert.Equal(t,
		"(&(objectClass=organizationalUnit)(ou=%s))",
		adapter.SearchOUFilterTemplate(),
	)
}

func TestOPENLDAPAdapter_SearchGroupFilterTemplate(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	// Both the OR group and the outer AND filter must be wrapped in
	// balanced parentheses so that OpenLDAP accepts the filter as valid.
	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup))(cn=%s))",
		adapter.SearchGroupFilterTemplate(),
	)
}

func TestOPENLDAPAdapter_SearchGroupFilterTemplate_FormatsArg(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	template := adapter.SearchGroupFilterTemplate()

	filter := fmt.Sprintf(template, "admins")

	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup))(cn=admins))",
		filter,
	)
	assert.NotContains(t, filter, "%", "no unresolved placeholders should remain")
}

// TestOPENLDAPAdapter_AllSearchTemplates_BalancedParentheses verifies that
// every search template has a balanced number of parentheses and that the
// result starts with '(' and ends with ')'. This is a regression guard against
// malformed filters that LDAP servers reject.
func TestOPENLDAPAdapter_AllSearchTemplates_BalancedParentheses(t *testing.T) {
	adapter := OPENLDAPAdapter{}

	templates := map[string]string{
		"SearchUserFilterTemplate":       adapter.SearchUserFilterTemplate(),
		"SearchUserGroupsFilterTemplate": adapter.SearchUserGroupsFilterTemplate(),
		"SearchOUFilterTemplate":         adapter.SearchOUFilterTemplate(),
		"SearchGroupFilterTemplate":      adapter.SearchGroupFilterTemplate(),
	}

	for name, tmpl := range templates {
		t.Run(name, func(t *testing.T) {
			opens := strings.Count(tmpl, "(")
			closes := strings.Count(tmpl, ")")

			assert.Equal(t, opens, closes,
				"parentheses must be balanced: %d opening vs %d closing", opens, closes)
			assert.True(t, strings.HasPrefix(tmpl, "("), "filter must start with '('")
			assert.True(t, strings.HasSuffix(tmpl, ")"), "filter must end with ')'")
		})
	}
}

// ---------- SearchUserGroupsFilterTemplateArgs ----------

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplateArgs_UsesDNAndUID(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	user := newLDAPUser("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
	})

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 2)
	assert.Equal(t, "uid=jdoe,ou=people,dc=example,dc=com", args[0],
		"first argument is the DN used for member in groupOfNames")
	assert.Equal(t, "jdoe", args[1],
		"second argument is the uid used for memberUid in posixGroup")
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplateArgs_DNUsesStructField(t *testing.T) {
	// The DN for the member filter must come from the struct field, not
	// from the "dn" attribute.
	adapter := OPENLDAPAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"dn":  {"cn=IGNORED,dc=example,dc=com"},
		"uid": {"jdoe"},
	})

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Equal(t, "uid=jdoe,dc=example,dc=com", args[0],
		"LDAPUser.DN is used, not the \"dn\" attribute")
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplateArgs_EmptyUser(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	user := types.LDAPUser{}

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 2)
	assert.Equal(t, "", args[0])
	assert.Equal(t, "", args[1])
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplateArgs_NilAttributesMap(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	user := types.LDAPUser{DN: "uid=jdoe,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		args := adapter.SearchUserGroupsFilterTemplateArgs(user)
		assert.Len(t, args, 2)
		assert.Equal(t, "uid=jdoe,dc=example,dc=com", args[0])
		assert.Equal(t, "", args[1])
	})
}

// ---------- ATTRS ----------

func TestOPENLDAPAdapter_UserAttrs(t *testing.T) {
	adapter := OPENLDAPAdapter{}

	expected := []string{
		"dn",
		// common (person class)
		"cn", "sn",
		// organizationalPerson class
		"ou", "title", "telephoneNumber", "postalAddress",
		// inetOrgPerson class
		"uid", "givenName", "displayName", "mail", "mobile",
		"departmentNumber", "employeeNumber", "employeeType", "jpegPhoto",
		// posixAccount class
		"uidNumber", "gidNumber", "homeDirectory",
		// may be or not to be at all attrs
		"description", "manager",
	}

	assert.Equal(t, expected, adapter.UserAttrs())
}

func TestOPENLDAPAdapter_UserAttrs_ContainsCriticalAttributes(t *testing.T) {
	// Less brittle than an exact equality check: catches accidental removal
	// of important attributes during refactoring.
	adapter := OPENLDAPAdapter{}
	attrs := adapter.UserAttrs()

	critical := []string{
		"dn", "cn", "sn", "uid", "mail", "mobile", "telephoneNumber",
		"departmentNumber", "jpegPhoto", "manager", "title", "postalAddress",
		"uidNumber", "gidNumber", "homeDirectory",
	}

	for _, attr := range critical {
		assert.Contains(t, attrs, attr, "critical attribute %q is missing from UserAttrs", attr)
	}
}

func TestOPENLDAPAdapter_UserAttrs_NoDuplicates(t *testing.T) {
	// Duplicates lead to redundant data in LDAP responses.
	adapter := OPENLDAPAdapter{}
	seen := make(map[string]struct{}, len(adapter.UserAttrs()))

	for _, attr := range adapter.UserAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in UserAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}

func TestOPENLDAPAdapter_ShortUserAttrs(t *testing.T) {
	adapter := OPENLDAPAdapter{}

	expected := []string{
		"uid", "cn", "dn", "mail", "title", "departmentNumber",
	}

	assert.Equal(t, expected, adapter.ShortUserAttrs())
}

func TestOPENLDAPAdapter_ShortUserAttrs_SubsetOfUserAttrs(t *testing.T) {
	// Contract: ShortUserAttrs must be a subset of UserAttrs.
	// Otherwise GetUser and GetOUUsers return different attribute sets
	// for the same user.
	adapter := OPENLDAPAdapter{}
	full := make(map[string]struct{}, len(adapter.UserAttrs()))
	for _, attr := range adapter.UserAttrs() {
		full[attr] = struct{}{}
	}

	for _, attr := range adapter.ShortUserAttrs() {
		_, ok := full[attr]
		assert.True(t, ok, "attribute %q from ShortUserAttrs is missing in UserAttrs", attr)
	}
}

func TestOPENLDAPAdapter_OUAttrs(t *testing.T) {
	adapter := OPENLDAPAdapter{}

	expected := []string{
		"ou", "objectClass", "description",
	}

	assert.Equal(t, expected, adapter.OUAttrs())
}

func TestOPENLDAPAdapter_GroupAttrs(t *testing.T) {
	adapter := OPENLDAPAdapter{}

	expected := []string{
		"cn",
		"member",
		"uniqueMember",
		"gidNumber",
		"description",
		"o",
		"ou",
		"owner",
		"businessCategory",
		"memberUid",
		"memberOf",
	}

	assert.Equal(t, expected, adapter.GroupAttrs())
}

func TestOPENLDAPAdapter_GroupAttrs_ContainsAttributesForBothGroupTypes(t *testing.T) {
	// GroupAttrs must cover both groupOfNames and posixGroup.
	adapter := OPENLDAPAdapter{}
	attrs := adapter.GroupAttrs()

	requiredForGroupOfNames := []string{"cn", "member"}
	for _, attr := range requiredForGroupOfNames {
		assert.Contains(t, attrs, attr, "groupOfNames: attribute %q is missing", attr)
	}

	requiredForPosixGroup := []string{"cn", "gidNumber", "memberUid"}
	for _, attr := range requiredForPosixGroup {
		assert.Contains(t, attrs, attr, "posixGroup: attribute %q is missing", attr)
	}
}

func TestOPENLDAPAdapter_GroupAttrs_NoDuplicates(t *testing.T) {
	adapter := OPENLDAPAdapter{}
	seen := make(map[string]struct{}, len(adapter.GroupAttrs()))

	for _, attr := range adapter.GroupAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in GroupAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}
