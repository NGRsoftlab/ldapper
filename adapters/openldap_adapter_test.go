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
	// OpenLDAP reads DN from the "dn" attribute, not from the struct field.
	assert.Equal(t, "uid=jdoe,ou=people,dc=example,dc=com", info.DistinguishedName)
	assert.Equal(t, "John Doe", info.CommonName)
	assert.Equal(t, "+7-999-123-45-67", info.Mobile)
	assert.Equal(t, "+7-495-123-45-67", info.Phone)
	assert.Equal(t, "jdoe@example.com", info.Mail)
	// OpenLDAP stores department in "departmentNumber", not in "department".
	assert.Equal(t, "IT-42", info.Department)
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "uid=jboss,ou=people,dc=example,dc=com", info.Manager)
	assert.Equal(t, "jpeg-bytes", info.Photo)
	// OpenLDAP reads address from "postalAddress", not "streetAddress" / "street".
	assert.Equal(t, "Tverskaya 1, Moscow, 101000", info.Address)
}

// TestOPENLDAPAdapter_GetNormalizedUserInfo_HardcodedEmptyFields documents
// that Company, Country, City and Index are hardcoded to empty in the
// OpenLDAP adapter — even if matching LDAP attributes exist on the entry.
func TestOPENLDAPAdapter_GetNormalizedUserInfo_HardcodedEmptyFields(t *testing.T) {
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

func TestOPENLDAPAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	info := OPENLDAPAdapter{}.GetNormalizedUserInfo(types.LDAPUser{})

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
	user := types.LDAPUser{DN: "uid=jdoe,dc=x", Attributes: nil}

	assert.NotPanics(t, func() {
		info := OPENLDAPAdapter{}.GetNormalizedUserInfo(user)
		assert.NotNil(t, info)
		assert.Empty(t, info.CommonName)
	})
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_DistinguishedNameFromAttrOnly(t *testing.T) {
	// DN must come from the "dn" attribute; the struct's DN field is ignored.
	user := newLDAPUser("uid=jdoe,dc=x", map[string][]string{
		"cn": {"John"},
	})

	info := OPENLDAPAdapter{}.GetNormalizedUserInfo(user)

	assert.Empty(t, info.DistinguishedName,
		"DistinguishedName must be filled only from the \"dn\" attribute")
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_PhotoOnlyJpeg(t *testing.T) {
	// OpenLDAP adapter does NOT fall back to thumbnailPhoto.
	user := newLDAPUser("uid=jdoe,dc=x", map[string][]string{
		"thumbnailPhoto": {"thumb-bytes"},
	})

	info := OPENLDAPAdapter{}.GetNormalizedUserInfo(user)

	assert.Empty(t, info.Photo,
		"thumbnailPhoto is not used by the OpenLDAP adapter")
}

// ---------- OUInfoFromEntry ----------

func TestOPENLDAPAdapter_OUInfoFromEntry_FullAttributes(t *testing.T) {
	entry := ldap.Entry{
		DN: "ou=IT,ou=Departments,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
		},
	}

	info := OPENLDAPAdapter{}.OUInfoFromEntry(entry)

	assert.NotNil(t, info)
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.DN)
	// OpenLDAP: Name equals the entry DN, not the "name"/"ou" attribute.
	assert.Equal(t, "ou=IT,ou=Departments,dc=example,dc=com", info.Name)
	// OpenLDAP: OU comes from the "ou" attribute, not from the DN.
	assert.Equal(t, "IT", info.OU)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_NameIsAlwaysDN(t *testing.T) {
	// Name must equal DN regardless of a "name" attribute on the entry.
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT"}},
			{Name: "name", Values: []string{"IGNORED"}},
		},
	}

	info := OPENLDAPAdapter{}.OUInfoFromEntry(entry)

	assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name)
	assert.NotEqual(t, "IGNORED", info.Name)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_MissingOUAttribute(t *testing.T) {
	// Absent "ou" attribute leaves OU empty; DN and Name stay populated.
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"organizationalUnit"}},
		},
	}

	info := OPENLDAPAdapter{}.OUInfoFromEntry(entry)

	assert.Equal(t, "ou=IT,dc=example,dc=com", info.DN)
	assert.Equal(t, "ou=IT,dc=example,dc=com", info.Name)
	assert.Empty(t, info.OU)
}

func TestOPENLDAPAdapter_OUInfoFromEntry_UsesFirstValueOfMultiValuedOU(t *testing.T) {
	entry := ldap.Entry{
		DN: "ou=IT,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"IT", "Information Technology"}},
		},
	}

	info := OPENLDAPAdapter{}.OUInfoFromEntry(entry)

	assert.Equal(t, "IT", info.OU)
}

// TestOPENLDAPAdapter_OUInfoFromEntry_DegenerateInputs covers empty entries and
// nil attributes; Children must always be a non-nil empty slice.
func TestOPENLDAPAdapter_OUInfoFromEntry_DegenerateInputs(t *testing.T) {
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
				info := OPENLDAPAdapter{}.OUInfoFromEntry(tc.entry)
				assert.NotNil(t, info)
				assert.Equal(t, tc.entry.DN, info.DN)
				assert.NotNil(t, info.Children)
				assert.Empty(t, info.Children)
			})
		})
	}
}

func TestOPENLDAPAdapter_OUInfoFromEntry_ChildrenAppendable(t *testing.T) {
	info := OPENLDAPAdapter{}.OUInfoFromEntry(ldap.Entry{DN: "ou=IT,dc=x"})

	assert.NotPanics(t, func() {
		info.Children = append(info.Children, &types.OUInfo{DN: "ou=Sub,ou=IT,dc=x"})
	})
	assert.Len(t, info.Children, 1)
}

// ---------- TYPE FILTERS ----------

func TestOPENLDAPAdapter_TypeFilters(t *testing.T) {
	adapter := OPENLDAPAdapter{}

	assert.Equal(t, "(&(objectClass=organizationalUnit))", adapter.OUObjectFilter())
	// OpenLDAP groups are either groupOfNames or posixGroup.
	assert.Equal(t,
		"(|(objectClass=groupOfNames)(objectClass=posixGroup))",
		adapter.GroupObjectFilter(),
	)
	assert.Equal(t, "(&(objectClass=person))", adapter.UserObjectFilter())
}

// ---------- SEARCH ----------

func TestOPENLDAPAdapter_SearchUserFilterTemplate(t *testing.T) {
	tmpl := OPENLDAPAdapter{}.SearchUserFilterTemplate()

	assert.Equal(t,
		"(&(!(objectClass=computer))(|(uid=%[1]s)(cn=%[1]s)))",
		tmpl,
	)
	// Computer objects must be excluded, otherwise workstations and servers
	// could be returned as users.
	assert.Contains(t, tmpl, "(!(objectClass=computer))",
		"computers must be excluded from the user search")
}

// TestOPENLDAPAdapter_SearchUserFilterTemplate_FormatsIndexedPlaceholder verifies
// the indexed %[1]s placeholder is substituted into BOTH uid= and cn=.
func TestOPENLDAPAdapter_SearchUserFilterTemplate_FormatsIndexedPlaceholder(t *testing.T) {
	tmpl := OPENLDAPAdapter{}.SearchUserFilterTemplate()
	filter := fmt.Sprintf(tmpl, "jdoe")

	assert.Equal(t,
		"(&(!(objectClass=computer))(|(uid=jdoe)(cn=jdoe)))",
		filter,
	)
	assert.NotContains(t, filter, "%", "no unresolved placeholders should remain")
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	tmpl := OPENLDAPAdapter{}.SearchUserGroupsFilterTemplate()

	assert.Equal(t,
		"(|(&(objectClass=groupOfNames)(member=uid=%s))(&(objectClass=posixGroup)(memberUid=%s)))",
		tmpl,
	)
	// Two placeholders: one for member (groupOfNames), one for memberUid (posixGroup).
	assert.Equal(t, 2, strings.Count(tmpl, "%s"),
		"template must have two placeholders: member and memberUid")
}

// TestOPENLDAPAdapter_SearchUserGroupsFilterTemplate_FormatsBothArgs verifies
// that args (DN + uid) are correctly substituted into the two placeholders —
// producing a well-formed filter with no fmt EXTRA artifacts.
func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplate_FormatsBothArgs(t *testing.T) {
	tmpl := OPENLDAPAdapter{}.SearchUserGroupsFilterTemplate()
	filter := fmt.Sprintf(tmpl, "jdoe,dc=example,dc=com", "jdoe")

	assert.Equal(t,
		"(|(&(objectClass=groupOfNames)(member=uid=jdoe,dc=example,dc=com))"+
			"(&(objectClass=posixGroup)(memberUid=jdoe)))",
		filter,
	)
	assert.NotContains(t, filter, "%", "no unresolved placeholders should remain")
	assert.NotContains(t, filter, "%!", "no fmt EXTRA artifact should be present")
}

func TestOPENLDAPAdapter_SearchOUFilterTemplate(t *testing.T) {
	assert.Equal(t,
		"(&(objectClass=organizationalUnit)(ou=%s))",
		OPENLDAPAdapter{}.SearchOUFilterTemplate(),
	)
}

func TestOPENLDAPAdapter_SearchGroupFilterTemplate(t *testing.T) {
	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup))(cn=%s))",
		OPENLDAPAdapter{}.SearchGroupFilterTemplate(),
	)
}

// TestOPENLDAPAdapter_AllSearchTemplates_BalancedParentheses is a regression
// guard against malformed filters that OpenLDAP would reject.
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
			assert.Equal(t, strings.Count(tmpl, "("), strings.Count(tmpl, ")"),
				"parentheses must be balanced")
			assert.True(t, strings.HasPrefix(tmpl, "("))
			assert.True(t, strings.HasSuffix(tmpl, ")"))
		})
	}
}

// ---------- SearchUserGroupsFilterTemplateArgs ----------

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplateArgs(t *testing.T) {
	tests := []struct {
		name    string
		user    types.LDAPUser
		wantDN  string
		wantUID string
	}{
		{
			name:    "DN and uid from attributes",
			user:    newLDAPUser("uid=jdoe,dc=x", map[string][]string{"uid": {"jdoe"}}),
			wantDN:  "uid=jdoe,dc=x",
			wantUID: "jdoe",
		},
		{
			name: "DN uses struct field, not dn attribute",
			user: newLDAPUser("uid=jdoe,dc=x", map[string][]string{
				"dn":  {"cn=IGNORED,dc=x"},
				"uid": {"jdoe"},
			}),
			wantDN:  "uid=jdoe,dc=x",
			wantUID: "jdoe",
		},
		{
			name:    "empty user",
			user:    types.LDAPUser{},
			wantDN:  "",
			wantUID: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := OPENLDAPAdapter{}.SearchUserGroupsFilterTemplateArgs(tc.user)

			assert.Len(t, args, 2)
			assert.Equal(t, tc.wantDN, args[0],
				"first arg is the DN for groupOfNames member")
			assert.Equal(t, tc.wantUID, args[1],
				"second arg is the uid for posixGroup memberUid")
		})
	}
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplateArgs_NilAttributesMap(t *testing.T) {
	user := types.LDAPUser{DN: "uid=jdoe,dc=x", Attributes: nil}

	assert.NotPanics(t, func() {
		args := OPENLDAPAdapter{}.SearchUserGroupsFilterTemplateArgs(user)
		assert.Len(t, args, 2)
		assert.Equal(t, "uid=jdoe,dc=x", args[0])
		assert.Equal(t, "", args[1])
	})
}

// ---------- ATTRS ----------

func TestOPENLDAPAdapter_UserAttrs(t *testing.T) {
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
	assert.Equal(t, expected, OPENLDAPAdapter{}.UserAttrs())
}

func TestOPENLDAPAdapter_UserAttrs_ContainsCriticalAttributes(t *testing.T) {
	attrs := OPENLDAPAdapter{}.UserAttrs()

	critical := []string{
		"dn", "cn", "sn", "uid", "mail", "mobile", "telephoneNumber",
		"departmentNumber", "jpegPhoto", "manager", "title", "postalAddress",
		"uidNumber", "gidNumber", "homeDirectory",
	}
	for _, attr := range critical {
		assert.Contains(t, attrs, attr, "critical attribute %q is missing", attr)
	}
}

func TestOPENLDAPAdapter_UserAttrs_NoDuplicates(t *testing.T) {
	seen := make(map[string]struct{})
	for _, attr := range (OPENLDAPAdapter{}).UserAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in UserAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}

func TestOPENLDAPAdapter_OUAttrs(t *testing.T) {
	expected := []string{"ou", "objectClass", "description"}
	assert.Equal(t, expected, OPENLDAPAdapter{}.OUAttrs())
}

func TestOPENLDAPAdapter_GroupAttrs(t *testing.T) {
	expected := []string{
		"cn",
		"member",       // groupOfNames
		"uniqueMember", // groupOfUniqueNames
		"gidNumber",    // posixGroup

		"description",

		"o",
		"ou",
		"owner",
		"businessCategory",

		"memberUid", // posixGroup

		"memberOf", // operational, may be empty
	}
	assert.Equal(t, expected, OPENLDAPAdapter{}.GroupAttrs())
}

func TestOPENLDAPAdapter_GroupAttrs_ContainsBothGroupTypes(t *testing.T) {
	attrs := OPENLDAPAdapter{}.GroupAttrs()

	// groupOfNames / groupOfUniqueNames
	for _, attr := range []string{"cn", "member", "uniqueMember", "owner", "businessCategory"} {
		assert.Contains(t, attrs, attr,
			"groupOfNames/groupOfUniqueNames: attribute %q is missing", attr)
	}
	// posixGroup
	for _, attr := range []string{"gidNumber", "memberUid"} {
		assert.Contains(t, attrs, attr, "posixGroup: attribute %q is missing", attr)
	}
}

func TestOPENLDAPAdapter_GroupAttrs_NoDuplicates(t *testing.T) {
	seen := make(map[string]struct{})
	for _, attr := range (OPENLDAPAdapter{}).GroupAttrs() {
		if _, exists := seen[attr]; exists {
			t.Fatalf("duplicate attribute in GroupAttrs: %q", attr)
		}
		seen[attr] = struct{}{}
	}
}
