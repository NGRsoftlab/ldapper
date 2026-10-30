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
	// MSAD reads DN from the "distinguishedName" attribute, not the struct field.
	assert.Equal(t, "cn=John Doe,ou=people,dc=example,dc=com", info.DistinguishedName)
	assert.Equal(t, "John Doe", info.CommonName)
	assert.Equal(t, "+7-999-123-45-67", info.Mobile)
	assert.Equal(t, "+7-495-123-45-67", info.Phone)
	assert.Equal(t, "john.doe@example.com", info.Mail)
	assert.Equal(t, "IT", info.Department)
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "cn=Jane Boss,ou=people,dc=example,dc=com", info.Manager)
	// thumbnailPhoto wins over jpegPhoto when both are present.
	assert.Equal(t, "thumb-bytes", info.Photo,
		"thumbnailPhoto takes precedence over jpegPhoto")
	assert.Equal(t, "Example Inc.", info.Company)
	assert.Equal(t, "RU", info.Country)
	assert.Equal(t, "Tverskaya 1", info.Address)
	assert.Equal(t, "Moscow", info.City)
	assert.Equal(t, "101000", info.Index)
}

// TestMSADAdapter_GetNormalizedUserInfo_PhotoFallback documents the
// GetFirstNonNullAttributeValue(["thumbnailPhoto", "jpegPhoto"]) chain:
// thumbnailPhoto if set, else jpegPhoto, else empty.
func TestMSADAdapter_GetNormalizedUserInfo_PhotoFallback(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string][]string
		want  string
	}{
		{
			name:  "both present, thumbnail wins",
			attrs: map[string][]string{"thumbnailPhoto": {"thumb"}, "jpegPhoto": {"jpeg"}},
			want:  "thumb",
		},
		{
			name:  "only jpeg",
			attrs: map[string][]string{"jpegPhoto": {"jpeg"}},
			want:  "jpeg",
		},
		{
			name:  "thumbnail empty value, jpeg used",
			attrs: map[string][]string{"thumbnailPhoto": {""}, "jpegPhoto": {"jpeg"}},
			want:  "jpeg",
		},
		{
			name:  "neither",
			attrs: map[string][]string{},
			want:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := MSADAdapter{}.GetNormalizedUserInfo(newLDAPUser("cn=u", tc.attrs))
			assert.Equal(t, tc.want, info.Photo)
		})
	}
}

func TestMSADAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	info := MSADAdapter{}.GetNormalizedUserInfo(types.LDAPUser{})

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

func TestMSADAdapter_GetNormalizedUserInfo_NilAttributesMap(t *testing.T) {
	user := types.LDAPUser{DN: "cn=u,dc=x", Attributes: nil}

	assert.NotPanics(t, func() {
		info := MSADAdapter{}.GetNormalizedUserInfo(user)
		assert.NotNil(t, info)
		assert.Empty(t, info.CommonName)
		assert.Empty(t, info.Photo)
	})
}

func TestMSADAdapter_GetNormalizedUserInfo_DistinguishedNameFromAttrOnly(t *testing.T) {
	// DN comes from the "distinguishedName" attribute; the struct field is
	// ignored.
	user := newLDAPUser("cn=IGNORED,dc=x", map[string][]string{
		"cn": {"John"},
	})

	info := MSADAdapter{}.GetNormalizedUserInfo(user)

	assert.Empty(t, info.DistinguishedName,
		"DistinguishedName must be filled only from the \"distinguishedName\" attribute")
}

// ---------- OUInfoFromEntry ----------

func TestMSADAdapter_OUInfoFromEntry_FullAttributes(t *testing.T) {
	entry := ldap.Entry{
		DN: "ou=IT,ou=Departments,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IT"}},
		},
	}

	info := MSADAdapter{}.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.DN)
	// MSAD: Name comes from the "name" attribute.
	assert.Equal(t, "IT", info.Name)
	// MSAD: OU is set to the entry DN, not the "ou" attribute.
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.OU)
}

func TestMSADAdapter_OUInfoFromEntry_MissingNameAttribute(t *testing.T) {
	// If "name" is absent, Name stays empty; DN and OU keep their values.
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"organizationalUnit"}},
		},
	}

	info := MSADAdapter{}.OUInfoFromEntry(entry)

	assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
	assert.Empty(t, info.Name)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.OU)
}

func TestMSADAdapter_OUInfoFromEntry_UsesFirstValueOfMultiValuedName(t *testing.T) {
	// GetAttributeValue returns the first value of a multi-valued attribute.
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "name", Values: []string{"IT", "Information Technology"}},
		},
	}

	info := MSADAdapter{}.OUInfoFromEntry(entry)

	assert.Equal(t, "IT", info.Name)
}

// TestMSADAdapter_OUInfoFromEntry_DegenerateInputs covers empty entries and
// nil attributes; Children must always be a non-nil empty slice.
func TestMSADAdapter_OUInfoFromEntry_DegenerateInputs(t *testing.T) {
	tests := []struct {
		name  string
		entry ldap.Entry
	}{
		{"empty entry", ldap.Entry{}},
		{"nil attributes", ldap.Entry{DN: "ou=IT,dc=x", Attributes: nil}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				info := MSADAdapter{}.OUInfoFromEntry(tc.entry)
				assert.NotNil(t, info)
				assert.Equal(t, tc.entry.DN, info.DN)
				assert.NotNil(t, info.Children)
				assert.Empty(t, info.Children)
			})
		})
	}
}

func TestMSADAdapter_OUInfoFromEntry_ChildrenAppendable(t *testing.T) {
	// Pin the non-nil contract: callers must be able to append to Children.
	info := MSADAdapter{}.OUInfoFromEntry(ldap.Entry{DN: "ou=IT,dc=x"})

	assert.NotPanics(t, func() {
		info.Children = append(info.Children, &types.OUInfo{DN: "ou=Sub,ou=IT,dc=x"})
	})
	assert.Len(t, info.Children, 1)
}

// ---------- TYPE FILTERS ----------

func TestMSADAdapter_TypeFilters(t *testing.T) {
	adapter := MSADAdapter{}

	assert.Equal(t, "(&(objectClass=organizationalUnit))", adapter.OUObjectFilter())
	assert.Equal(t, "(&(objectCategory=group))", adapter.GroupObjectFilter())
	assert.Equal(t, "(&(objectClass=user)(objectCategory=person))", adapter.UserObjectFilter())
}

// ---------- SEARCH ----------

func TestMSADAdapter_SearchUserFilterTemplate(t *testing.T) {
	assert.Equal(t,
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))",
		MSADAdapter{}.SearchUserFilterTemplate(),
	)
}

// TestMSADAdapter_SearchUserGroupsFilterTemplate verifies the LDAP_MATCHING_RULE_IN_CHAIN
// OID (1.2.840.113556.1.4.1941) is used for recursive group expansion — without
// it AD would return only direct memberships.
func TestMSADAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	tmpl := MSADAdapter{}.SearchUserGroupsFilterTemplate()

	assert.Equal(t,
		"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=%s))",
		tmpl,
	)
	assert.Contains(t, tmpl, "1.2.840.113556.1.4.1941",
		"LDAP_MATCHING_RULE_IN_CHAIN OID must be present for recursive group search")
}

func TestMSADAdapter_SearchOUFilterTemplate(t *testing.T) {
	assert.Equal(t,
		"(&(objectClass=organizationalUnit)(ou=%s))",
		MSADAdapter{}.SearchOUFilterTemplate(),
	)
}

func TestMSADAdapter_SearchGroupFilterTemplate(t *testing.T) {
	assert.Equal(t,
		"(&(objectCategory=group)(cn=%s))",
		MSADAdapter{}.SearchGroupFilterTemplate(),
	)
}

// TestMSADAdapter_AllSearchTemplates_BalancedParentheses is a regression guard
// against malformed filters that AD would reject.
func TestMSADAdapter_AllSearchTemplates_BalancedParentheses(t *testing.T) {
	adapter := MSADAdapter{}
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
			assert.True(t, strings.HasPrefix(tmpl, "("))
			assert.True(t, strings.HasSuffix(tmpl, ")"))
		})
	}
}

// ---------- SearchUserGroupsFilterTemplateArgs ----------

func TestMSADAdapter_SearchUserGroupsFilterTemplateArgs(t *testing.T) {
	tests := []struct {
		name string
		user types.LDAPUser
		want string
	}{
		{
			name: "uses struct DN field",
			user: newLDAPUser("cn=John Doe,ou=people,dc=x", nil),
			want: "cn=John Doe,ou=people,dc=x",
		},
		{
			name: "distinguishedName attribute is ignored",
			user: newLDAPUser("uid=other,dc=x",
				map[string][]string{"distinguishedName": {"cn=IGNORED,dc=x"}}),
			want: "uid=other,dc=x",
		},
		{
			name: "empty user",
			user: types.LDAPUser{},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := MSADAdapter{}.SearchUserGroupsFilterTemplateArgs(tc.user)
			assert.Len(t, args, 1)
			assert.Equal(t, tc.want, args[0])
		})
	}
}

// ---------- ATTRS ----------

func TestMSADAdapter_UserAttrs(t *testing.T) {
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
	assert.Equal(t, expected, MSADAdapter{}.UserAttrs())
}

func TestMSADAdapter_UserAttrs_ContainsCriticalAttributes(t *testing.T) {
	// Less brittle than exact equality — catches accidental removal during
	// refactoring.
	attrs := MSADAdapter{}.UserAttrs()

	critical := []string{
		"sAMAccountName", "userPrincipalName", "mail", "distinguishedName",
		"thumbnailPhoto", "jpegPhoto", "objectGUID", "objectSid", "memberOf",
		"telephoneNumber", "mobile", "department", "title", "manager",
	}
	for _, attr := range critical {
		assert.Contains(t, attrs, attr, "critical attribute %q is missing", attr)
	}
}

func TestMSADAdapter_UserAttrs_NoDuplicates(t *testing.T) {
	seen := make(map[string]struct{})
	for _, attr := range (MSADAdapter{}).UserAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in UserAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}

func TestMSADAdapter_OUAttrs(t *testing.T) {
	expected := []string{
		"distinguishedName", "name", "objectClass", "objectGUID", "description", "managedBy",
	}
	assert.Equal(t, expected, MSADAdapter{}.OUAttrs())
}

func TestMSADAdapter_GroupAttrs(t *testing.T) {
	expected := []string{
		"cn", "distinguishedName", "sAMAccountName", "groupType",
		"member", "memberOf", "description", "objectGUID",
	}
	assert.Equal(t, expected, MSADAdapter{}.GroupAttrs())
}

func TestMSADAdapter_GroupAttrs_NoDuplicates(t *testing.T) {
	seen := make(map[string]struct{})
	for _, attr := range (MSADAdapter{}).GroupAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in GroupAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}

// Silence unused import when only compilation of fmt is needed elsewhere.
var _ = fmt.Sprintf
