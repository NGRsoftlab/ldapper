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

func TestALDRPOAdapter_GetNormalizedUserInfo_FullAttributes(t *testing.T) {
	adapter := ALDRPOAdapter{}
	user := newLDAPUser("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"dn":              {"uid=jdoe,ou=people,dc=example,dc=com"},
		"cn":              {"John Doe"},
		"mobile":          {"+7-999-123-45-67"},
		"telephoneNumber": {"+7-495-123-45-67"},
		"mail":            {"jdoe@example.com"},
		"rbtadp":          {"IT-42"},
		"title":           {"Engineer"},
		"manager":         {"uid=jboss,ou=people,dc=example,dc=com"},
		"jpegPhoto":       {"jpeg-bytes"},
		"co":              {"RU"},
		"streetAddress":   {"Tverskaya 1"},
		"l":               {"Moscow"},
		"postalCode":      {"101000"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.NotNil(t, info)
	// ALDRPO reads DN from the "dn" attribute, not from the struct field.
	assert.Equal(t, "uid=jdoe,ou=people,dc=example,dc=com", info.DistinguishedName)
	assert.Equal(t, "John Doe", info.CommonName)
	assert.Equal(t, "+7-999-123-45-67", info.Mobile)
	assert.Equal(t, "+7-495-123-45-67", info.Phone)
	assert.Equal(t, "jdoe@example.com", info.Mail)
	// ALDRPO stores department in "rbtadp", not in "department".
	assert.Equal(t, "IT-42", info.Department)
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "uid=jboss,ou=people,dc=example,dc=com", info.Manager)
	assert.Equal(t, "jpeg-bytes", info.Photo)
	// Company is hardcoded to empty in the ALDRPO adapter.
	assert.Empty(t, info.Company)
	assert.Equal(t, "RU", info.Country)
	assert.Equal(t, "Tverskaya 1", info.Address)
	assert.Equal(t, "Moscow", info.City)
	assert.Equal(t, "101000", info.Index)
}

func TestALDRPOAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	adapter := ALDRPOAdapter{}
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

func TestALDRPOAdapter_GetNormalizedUserInfo_NilAttributesMap(t *testing.T) {
	// A nil Attributes map must not cause a panic.
	adapter := ALDRPOAdapter{}
	user := types.LDAPUser{DN: "uid=jdoe,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		info := adapter.GetNormalizedUserInfo(user)
		assert.NotNil(t, info)
		assert.Empty(t, info.CommonName)
	})
}

func TestALDRPOAdapter_GetNormalizedUserInfo_DistinguishedNameFromAttrOnly(t *testing.T) {
	// DN must come from the "dn" attribute; the struct's DN field is ignored.
	adapter := ALDRPOAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"cn": {"John Doe"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.DistinguishedName,
		"DistinguishedName must be filled only from the \"dn\" attribute")
}

func TestALDRPOAdapter_GetNormalizedUserInfo_PhotoOnlyJpeg(t *testing.T) {
	// Unlike MSAD, ALDRPO does not fall back to thumbnailPhoto.
	adapter := ALDRPOAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"thumbnailPhoto": {"thumb-bytes"},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Photo, "thumbnailPhoto is not used by the ALDRPO adapter")
}

func TestALDRPOAdapter_GetNormalizedUserInfo_CompanyAlwaysEmpty(t *testing.T) {
	// Company is hardcoded, ignoring any "company" attribute present.
	adapter := ALDRPOAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"company": {"Example Inc."},
	})

	info := adapter.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Company)
}

// ---------- OUInfoFromEntry ----------

func TestALDRPOAdapter_OUInfoFromEntry_FullAttributes(t *testing.T) {
	adapter := ALDRPOAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,ou=Departments,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.DN)
	// Unlike MSAD, Name equals the entry DN rather than a "name" attribute.
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.Name)
	// OU comes from the "ou" attribute, not from the DN.
	assert.Equal(t, "IT", info.OU)
}

func TestALDRPOAdapter_OUInfoFromEntry_NameIsAlwaysDN(t *testing.T) {
	// Name must equal DN regardless of the entry's "name" attribute.
	adapter := ALDRPOAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IGNORED"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name)
	assert.NotEqual(t, "IGNORED", info.Name)
}

func TestALDRPOAdapter_OUInfoFromEntry_MissingOUAttribute(t *testing.T) {
	// Absent "ou" attribute leaves OU empty; DN and Name stay populated.
	adapter := ALDRPOAdapter{}
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

func TestALDRPOAdapter_OUInfoFromEntry_ChildrenInitialized(t *testing.T) {
	// Children must be a non-nil empty slice so callers can append safely.
	adapter := ALDRPOAdapter{}
	info := adapter.OUInfoFromEntry(ldap.Entry{DN: "ou=IT,dc=example,dc=com"})

	assert.NotNil(t, info.Children)
	assert.Empty(t, info.Children)
}

func TestALDRPOAdapter_OUInfoFromEntry_EmptyEntry(t *testing.T) {
	adapter := ALDRPOAdapter{}

	assert.NotPanics(t, func() {
		info := adapter.OUInfoFromEntry(ldap.Entry{})
		assert.NotNil(t, info)
		assert.Empty(t, info.DN)
		assert.Empty(t, info.Name)
		assert.Empty(t, info.OU)
		assert.NotNil(t, info.Children)
	})
}

func TestALDRPOAdapter_OUInfoFromEntry_NilAttributes(t *testing.T) {
	adapter := ALDRPOAdapter{}
	entry := ldap.Entry{DN: "ou=IT,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		info := adapter.OUInfoFromEntry(entry)
		assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
		assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name)
		assert.Empty(t, info.OU)
	})
}

func TestALDRPOAdapter_OUInfoFromEntry_UsesFirstValueOfMultiValuedOU(t *testing.T) {
	// Pin GetAttributeValue behavior for multi-valued "ou".
	adapter := ALDRPOAdapter{}
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT", "Information Technology"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)

	assert.Equal(t, "IT", info.OU)
}

// ---------- TYPE FILTERS ----------

func TestALDRPOAdapter_OUObjectFilter(t *testing.T) {
	adapter := ALDRPOAdapter{}
	// rbta-org-unit is the ALD Pro-specific replacement for organizationalUnit.
	assert.Equal(t,
		"(|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))",
		adapter.OUObjectFilter(),
	)
}

func TestALDRPOAdapter_GroupObjectFilter(t *testing.T) {
	adapter := ALDRPOAdapter{}
	assert.Equal(t,
		"(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))",
		adapter.GroupObjectFilter(),
	)
}

func TestALDRPOAdapter_UserObjectFilter(t *testing.T) {
	adapter := ALDRPOAdapter{}
	assert.Equal(t,
		"(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))",
		adapter.UserObjectFilter(),
	)
}

// ---------- SEARCH ----------

func TestALDRPOAdapter_SearchUserFilterTemplate(t *testing.T) {
	adapter := ALDRPOAdapter{}
	assert.Equal(t,
		"(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(uid=%s))",
		adapter.SearchUserFilterTemplate(),
	)
}

func TestALDRPOAdapter_SearchUserFilterTemplate_FormatsUsername(t *testing.T) {
	adapter := ALDRPOAdapter{}
	filter := fmt.Sprintf(adapter.SearchUserFilterTemplate(), "jdoe")

	assert.Equal(t,
		"(&(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))(uid=jdoe))",
		filter,
	)
	assert.NotContains(t, filter, "%", "no unresolved placeholders should remain")
}

func TestALDRPOAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	adapter := ALDRPOAdapter{}

	// NB: "member=uid=%s" is semantically unusual — `member` is normally a
	// DN-valued attribute, not a uid. Pinned here to detect unintended changes;
	// if the adapter is corrected, this test must be updated accordingly.
	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=uid=%s))",
		adapter.SearchUserGroupsFilterTemplate(),
	)
}

func TestALDRPOAdapter_SearchUserGroupsFilterTemplate_HasOnePlaceholder(t *testing.T) {
	adapter := ALDRPOAdapter{}
	template := adapter.SearchUserGroupsFilterTemplate()

	assert.Equal(t, 1, strings.Count(template, "%s"),
		"template is expected to contain exactly one placeholder")
}

func TestALDRPOAdapter_SearchUserGroupsFilterTemplate_FormatsCleanly(t *testing.T) {
	// Template has 1 placeholder and SearchUserGroupsFilterTemplateArgs returns
	// 1 arg — formatting must produce a clean filter with no artifacts.
	adapter := ALDRPOAdapter{}
	user := newLDAPUser("uid=jdoe,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
	})
	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	filter := fmt.Sprintf(adapter.SearchUserGroupsFilterTemplate(), args...)

	assert.NotContains(t, filter, "%!",
		"formatting must not produce an EXTRA/placeholder-mismatch artifact")
	assert.NotContains(t, filter, "%s",
		"no unresolved placeholder should remain")
	assert.Contains(t, filter, "uid=jdoe")
}

func TestALDRPOAdapter_SearchOUFilterTemplate(t *testing.T) {
	adapter := ALDRPOAdapter{}
	// Both organizationalUnit and rbta-org-unit must be matched.
	assert.Equal(t,
		"(&(|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))(ou=%s))",
		adapter.SearchOUFilterTemplate(),
	)
}

func TestALDRPOAdapter_SearchGroupFilterTemplate(t *testing.T) {
	adapter := ALDRPOAdapter{}
	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(cn=%s))",
		adapter.SearchGroupFilterTemplate(),
	)
}

// TestALDRPOAdapter_AllSearchTemplates_BalancedParentheses is a regression
// guard against malformed filters that LDAP servers would reject.
func TestALDRPOAdapter_AllSearchTemplates_BalancedParentheses(t *testing.T) {
	adapter := ALDRPOAdapter{}

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

func TestALDRPOAdapter_SearchUserGroupsFilterTemplateArgs_ReturnsUID(t *testing.T) {
	adapter := ALDRPOAdapter{}
	user := newLDAPUser("uid=jdoe,ou=people,dc=example,dc=com", map[string][]string{
		"uid": {"jdoe"},
	})

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)

	assert.Len(t, args, 1, "exactly one arg to match the single %s placeholder")
	assert.Equal(t, "jdoe", args[0],
		"the arg is the user's uid, taken from the \"uid\" attribute")
}

func TestALDRPOAdapter_SearchUserGroupsFilterTemplateArgs_EmptyUser(t *testing.T) {
	adapter := ALDRPOAdapter{}
	args := adapter.SearchUserGroupsFilterTemplateArgs(types.LDAPUser{})

	assert.Len(t, args, 1)
	assert.Equal(t, "", args[0])
}

func TestALDRPOAdapter_SearchUserGroupsFilterTemplateArgs_NilAttributesMap(t *testing.T) {
	adapter := ALDRPOAdapter{}
	user := types.LDAPUser{DN: "uid=jdoe,dc=example,dc=com", Attributes: nil}

	assert.NotPanics(t, func() {
		args := adapter.SearchUserGroupsFilterTemplateArgs(user)
		assert.Len(t, args, 1)
		assert.Equal(t, "", args[0])
	})
}

// ---------- ATTRS ----------

func TestALDRPOAdapter_UserAttrs(t *testing.T) {
	adapter := ALDRPOAdapter{}

	expected := []string{
		"dn",

		"uid", "cn", "givenName", "sn", "displayName", "mail",
		"telephoneNumber", "mobile", "title", "jpegPhoto",
		"rbtadp", // department analogy

		// system&posix attrs
		"uidNumber", "gidNumber", "homeDirectory", "memberOf",

		// address
		"streetAddress", "l", "postalCode",

		// may be or not to be at all attrs
		"description", "manager", "co", "ou", "o",
	}

	assert.Equal(t, expected, adapter.UserAttrs())
}

func TestALDRPOAdapter_UserAttrs_ContainsCriticalAttributes(t *testing.T) {
	adapter := ALDRPOAdapter{}
	attrs := adapter.UserAttrs()

	critical := []string{
		"dn", "cn", "uid", "mail", "mobile", "telephoneNumber",
		"rbtadp", "jpegPhoto", "manager", "title", "co",
		"uidNumber", "gidNumber", "homeDirectory", "memberOf",
	}
	for _, attr := range critical {
		assert.Contains(t, attrs, attr, "critical attribute %q is missing", attr)
	}
}

func TestALDRPOAdapter_UserAttrs_NoDuplicates(t *testing.T) {
	adapter := ALDRPOAdapter{}
	seen := make(map[string]struct{}, len(adapter.UserAttrs()))
	for _, attr := range adapter.UserAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in UserAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}

func TestALDRPOAdapter_OUAttrs(t *testing.T) {
	adapter := ALDRPOAdapter{}

	expected := []string{"dn", "ou", "description", "manager"}
	assert.Equal(t, expected, adapter.OUAttrs())
}

func TestALDRPOAdapter_GroupAttrs(t *testing.T) {
	adapter := ALDRPOAdapter{}

	expected := []string{
		"cn",
		"entrydn",
		"description",
		"gidNumber", // posixGroup
		"member",
		"memberOf",
		"ipaUniqueID",
		"ipaNTSecurityIdentifier",
	}
	assert.Equal(t, expected, adapter.GroupAttrs())
}

func TestALDRPOAdapter_GroupAttrs_ContainsIpausergroupAttrs(t *testing.T) {
	// ipausergroup-specific attributes must be requested.
	adapter := ALDRPOAdapter{}
	attrs := adapter.GroupAttrs()

	for _, attr := range []string{"ipaUniqueID", "ipaNTSecurityIdentifier"} {
		assert.Contains(t, attrs, attr, "ipausergroup: attribute %q is missing", attr)
	}
}

func TestALDRPOAdapter_GroupAttrs_NoDuplicates(t *testing.T) {
	adapter := ALDRPOAdapter{}
	seen := make(map[string]struct{}, len(adapter.GroupAttrs()))
	for _, attr := range adapter.GroupAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in GroupAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}
