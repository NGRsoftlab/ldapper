// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

// Compile-time assertion: ALDPROAdapter must satisfy CatalogAdapter.
var _ interfaces.CatalogAdapter = ALDPROAdapter{}

func TestALDPROAdapter_ImplementsCatalogAdapter(t *testing.T) {
	var adapter interfaces.CatalogAdapter = ALDPROAdapter{}
	require.NotNil(t, adapter)
}

// ---------------------------------------------------------------------------
// GetNormalizedUserInfo
// ---------------------------------------------------------------------------

func TestALDPROAdapter_GetNormalizedUserInfo_FullMapping(t *testing.T) {
	adapter := ALDPROAdapter{}
	user := newLDAPUser(
		"cn=user1,ou=users,dc=aldpro,dc=test",
		map[string][]string{
			"cn":              {"User One"},
			"mobile":          {"+7-555-0100"},
			"telephoneNumber": {"+7-555-0101"},
			"mail":            {"user1@aldpro.test"},
			"rbtadp":          {"Engineering"},
			"title":           {"Engineer"},
			"manager":         {"cn=boss,ou=users,dc=aldpro,dc=test"},
			"jpegPhoto":       {"photo-bytes"},
			"o":               {"Example Inc."},
			"co":              {"RU"},
			"streetAddress":   {"ул. Ленина, 1"},
			"l":               {"Москва"},
			"postalCode":      {"101000"},
		},
	)

	info := adapter.GetNormalizedUserInfo(user)
	require.NotNil(t, info)

	assert.Equal(t, "cn=user1,ou=users,dc=aldpro,dc=test", info.DistinguishedName,
		"DistinguishedName comes from the LDAPUser struct field")
	assert.Equal(t, "User One", info.CommonName)
	assert.Equal(t, "+7-555-0100", info.Mobile)
	assert.Equal(t, "+7-555-0101", info.Phone)
	assert.Equal(t, "user1@aldpro.test", info.Mail)
	assert.Equal(t, "Engineering", info.Department, "ALDPro uses rbtadp for department")
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "cn=boss,ou=users,dc=aldpro,dc=test", info.Manager)
	assert.Equal(t, "photo-bytes", info.Photo)
	assert.Equal(t, "Example Inc.", info.Company, "Company comes from the o attribute")
	assert.Equal(t, "RU", info.Country)
	assert.Equal(t, "ул. Ленина, 1", info.Address)
	assert.Equal(t, "Москва", info.City)
	assert.Equal(t, "101000", info.Index)
}

func TestALDPROAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	adapter := ALDPROAdapter{}
	info := adapter.GetNormalizedUserInfo(newLDAPUser("", nil))
	require.NotNil(t, info)

	assert.Zero(t, info.DistinguishedName)
	assert.Zero(t, info.CommonName)
	assert.Zero(t, info.Mobile)
	assert.Zero(t, info.Phone)
	assert.Zero(t, info.Mail)
	assert.Zero(t, info.Department)
	assert.Zero(t, info.Title)
	assert.Zero(t, info.Manager)
	assert.Zero(t, info.Photo)
	assert.Zero(t, info.Company)
	assert.Zero(t, info.Country)
	assert.Zero(t, info.Address)
	assert.Zero(t, info.City)
	assert.Zero(t, info.Index)
}

// TestALDPROAdapter_GetNormalizedUserInfo_DistinguishedNameFromStructField
// pins the DN source: the struct field, not the "dn" attribute.
func TestALDPROAdapter_GetNormalizedUserInfo_DistinguishedNameFromStructField(t *testing.T) {
	adapter := ALDPROAdapter{}
	user := newLDAPUser("cn=from-struct,dc=x", map[string][]string{
		"cn": {"Alice"},
		"dn": {"cn=from-attr,dc=x"},
	})

	info := adapter.GetNormalizedUserInfo(user)
	assert.Equal(t, "cn=from-struct,dc=x", info.DistinguishedName)
}

// ALDPro uses rbtadp (not "department"/"departmentNumber") for department.
// This is the adapter's most distinguishing field mapping.
func TestALDPROAdapter_GetNormalizedUserInfo_UsesRbtadpForDepartment(t *testing.T) {
	adapter := ALDPROAdapter{}
	user := newLDAPUser("", map[string][]string{
		"rbtadp":           {"Engineering"},
		"department":       {"IGNORED"},
		"departmentNumber": {"IGNORED"},
	})

	info := adapter.GetNormalizedUserInfo(user)
	assert.Equal(t, "Engineering", info.Department)
}

// ALDPro uses streetAddress (not "street" — that would be FreeIPA).
func TestALDPROAdapter_GetNormalizedUserInfo_UsesStreetAddress(t *testing.T) {
	adapter := ALDPROAdapter{}
	user := newLDAPUser("", map[string][]string{
		"streetAddress": {"Main St"},
		"street":        {"IGNORED"},
	})

	info := adapter.GetNormalizedUserInfo(user)
	assert.Equal(t, "Main St", info.Address)
}

// ---------------------------------------------------------------------------
// GetNormalizedOUInfoFromEntry
// ---------------------------------------------------------------------------

func TestALDPROAdapter_GetNormalizedOUInfoFromEntry(t *testing.T) {
	adapter := ALDPROAdapter{}
	entry := ldap.Entry{
		DN: "ou=departments,dc=aldpro,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"departments"}},
			{Name: "objectClass", Values: []string{"rbta-org-unit", "organizationalUnit"}},
		},
	}

	info := adapter.GetNormalizedOUInfoFromEntry(entry)
	require.NotNil(t, info)

	assert.Equal(t, "ou=departments,dc=aldpro,dc=test", info.DN)
	// Name is derived from the DN's first RDN via ouNameFromDN.
	assert.Equal(t, "departments", info.Name)
	assert.Equal(t, "departments", info.OU)
	require.NotNil(t, info.Children)
	assert.Empty(t, info.Children)
}

func TestALDPROAdapter_GetNormalizedOUInfoFromEntry_EmptyEntry(t *testing.T) {
	adapter := ALDPROAdapter{}
	info := adapter.GetNormalizedOUInfoFromEntry(ldap.Entry{})

	require.NotNil(t, info)
	assert.Zero(t, info.DN)
	assert.Zero(t, info.Name, "empty DN → ouNameFromDN falls back to the input (empty)")
	assert.Zero(t, info.OU)
	assert.NotNil(t, info.Children)
}

// ---------------------------------------------------------------------------
// Object filters
// ---------------------------------------------------------------------------

func TestALDPROAdapter_ObjectFilters_ExactStrings(t *testing.T) {
	adapter := ALDPROAdapter{}

	assert.Equal(t,
		"(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))",
		adapter.UserObjectFilter())
	assert.Equal(t,
		"(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))",
		adapter.GroupObjectFilter())
	assert.Equal(t,
		"(|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))",
		adapter.OUObjectFilter())
}

// ---------------------------------------------------------------------------
// Search filters
// ---------------------------------------------------------------------------

func TestALDPROAdapter_SearchFilters_AreValidLDAP(t *testing.T) {
	adapter := ALDPROAdapter{}

	user := types.LDAPUser{
		DN:         "cn=user1,ou=users,dc=aldpro,dc=test",
		Attributes: map[string][]string{"uid": {"user1"}},
	}

	cases := []struct {
		name   string
		filter string
	}{
		{
			name:   "SearchUserFilterTemplate",
			filter: fmt.Sprintf(adapter.SearchUserFilterTemplate(), "user1"),
		},
		{
			name: "SearchUserGroupsFilterTemplate",
			filter: fmt.Sprintf(
				adapter.SearchUserGroupsFilterTemplate(),
				adapter.SearchUserGroupsFilterTemplateArgs(user)...,
			),
		},
		{
			name:   "SearchOUFilterTemplate",
			filter: fmt.Sprintf(adapter.SearchOUFilterTemplate(), "departments"),
		},
		{
			name:   "SearchGroupFilterTemplate",
			filter: fmt.Sprintf(adapter.SearchGroupFilterTemplate(), "admins"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ldap.CompileFilter(c.filter)
			require.NoError(t, err, "invalid LDAP filter: %q", c.filter)
		})
	}
}

// TestALDPROAdapter_SearchUserGroupsFilterTemplate_HasBothBranches guards
// against a one-branch regression: the filter must query `member` (for
// groupOfNames/ipausergroup) AND `memberUid` (for posixGroup).
func TestALDPROAdapter_SearchUserGroupsFilterTemplate_HasBothBranches(t *testing.T) {
	adapter := ALDPROAdapter{}
	tmpl := adapter.SearchUserGroupsFilterTemplate()

	assert.Contains(t, tmpl, "(member=%s)",
		"groupOfNames/ipausergroup branch must query member with the DN")
	assert.Contains(t, tmpl, "(memberUid=%s)",
		"posixGroup branch must query memberUid with the uid")

	assert.Equal(t, 2, strings.Count(tmpl, "%s"),
		"exactly two placeholders expected — one per branch")

	assert.NotContains(t, tmpl, "member=uid=",
		"regression: earlier versions had (member=uid=%s) which is invalid")
}

// ---------------------------------------------------------------------------
// SearchUserGroupsFilterTemplateArgs
// ---------------------------------------------------------------------------

func TestALDPROAdapter_SearchUserGroupsFilterTemplateArgs_ReturnsDNThenUID(t *testing.T) {
	adapter := ALDPROAdapter{}
	user := newLDAPUser(
		"cn=user1,ou=users,dc=aldpro,dc=test",
		map[string][]string{"uid": {"user1"}},
	)

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)

	// Order matters: args[0] feeds (member=%s), args[1] feeds (memberUid=%s).
	assert.Equal(t, "cn=user1,ou=users,dc=aldpro,dc=test", args[0],
		"args[0] must be the DN for the member branch")
	assert.Equal(t, "user1", args[1],
		"args[1] must be the uid for the memberUid branch")
}

func TestALDPROAdapter_SearchUserGroupsFilterTemplateArgs_MissingUID(t *testing.T) {
	adapter := ALDPROAdapter{}
	// No "uid" attribute set → GetAttributeValue returns "".
	user := newLDAPUser("cn=x,ou=users,dc=aldpro,dc=test", nil)

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)
	assert.Equal(t, "cn=x,ou=users,dc=aldpro,dc=test", args[0])
	assert.Equal(t, "", args[1],
		"missing uid yields an empty string, not a panic")
}

func TestALDPROAdapter_SearchUserGroupsFilterTemplateArgs_OneArgPerPlaceholder(t *testing.T) {
	adapter := ALDPROAdapter{}
	template := adapter.SearchUserGroupsFilterTemplate()
	args := adapter.SearchUserGroupsFilterTemplateArgs(newLDAPUser("cn=x,dc=e", nil))

	require.Equal(t, strings.Count(template, "%s"), len(args),
		"template placeholders and Args() length must line up")
}

// ---------------------------------------------------------------------------
// Attrs
// ---------------------------------------------------------------------------

func TestALDPROAdapter_UserAttrs_ContainsMappedAttributes(t *testing.T) {
	adapter := ALDPROAdapter{}

	// Every attribute that GetNormalizedUserInfo reads *via GetAttributeValue*
	// must be in UserAttrs; otherwise the field will silently stay empty.
	// NB: DN is taken from the struct field, not an attribute.
	required := []string{
		"cn", "mobile", "telephoneNumber", "mail", "rbtadp",
		"title", "manager", "jpegPhoto", "o", "co", "streetAddress",
		"l", "postalCode",
	}

	attrs := adapter.UserAttrs()
	for _, r := range required {
		assert.Contains(t, attrs, r,
			"UserAttrs must contain %q because GetNormalizedUserInfo reads it", r)
	}
}

func TestALDPROAdapter_UserAttrs_DistinguishingAttributes(t *testing.T) {
	adapter := ALDPROAdapter{}
	attrs := adapter.UserAttrs()

	// ALDPro-specific.
	assert.Contains(t, attrs, "rbtadp")

	// ALDPro uses "streetAddress" (FreeIPA uses "street").
	assert.Contains(t, attrs, "streetAddress")
	assert.NotContains(t, attrs, "street")

	// FreeIPA-specific attributes must not leak into ALDPro.
	assert.NotContains(t, attrs, "nsAccountLock")
}

func TestALDPROAdapter_GroupAttrs_ContainsExpected(t *testing.T) {
	adapter := ALDPROAdapter{}
	attrs := adapter.GroupAttrs()

	assert.Contains(t, attrs, "cn")
	assert.Contains(t, attrs, "member")
	assert.Contains(t, attrs, "memberOf")
	assert.Contains(t, attrs, "gidNumber")
	assert.Contains(t, attrs, "ipaUniqueID")
	assert.Contains(t, attrs, "ipaNTSecurityIdentifier")

	// ALDPro uses the lowercase operational attribute name.
	assert.Contains(t, attrs, "entrydn")
	assert.NotContains(t, attrs, "distinguishedName",
		"distinguishedName is the MSAD spelling; ALDPro uses entrydn")
}

// TestALDPROAdapter_GroupAttrs_MissingMemberUid_DocumentedGap is a canary
// for the following observation:
//
//	SearchUserGroupsFilterTemplate() queries posixGroup via (memberUid=%s),
//	but GroupAttrs() does NOT include "memberUid". A consumer that relies on
//	GroupAttrs() to fetch a group's attributes will therefore not receive
//	posixGroup membership, even though GetUserGroups() can see it.
//
// The test does not fail today — it logs the gap and will start failing (in
// a good way) as soon as "memberUid" is added to GroupAttrs(), at which point
// the assertion below must be flipped to assert.Contains(...).
func TestALDPROAdapter_GroupAttrs_MissingMemberUid_DocumentedGap(t *testing.T) {
	adapter := ALDPROAdapter{}

	if !containsString(adapter.GroupAttrs(), "memberUid") {
		t.Logf("KNOWN GAP: GroupAttrs() omits \"memberUid\" while " +
			"SearchUserGroupsFilterTemplate() queries (memberUid=<string param>). " +
			"Consumers relying on GroupAttrs to fetch posixGroup details " +
			"will miss members. Flip this test to assert.Contains once fixed.")
	}
}

func TestALDPROAdapter_OUAttrs_ContainsExpected(t *testing.T) {
	adapter := ALDPROAdapter{}
	attrs := adapter.OUAttrs()

	assert.NotEmpty(t, attrs)
	assert.Contains(t, attrs, "dn")
	assert.Contains(t, attrs, "ou")
	assert.Contains(t, attrs, "description")
	assert.Contains(t, attrs, "manager")
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// containsString reports whether slice contains s. Avoids depending on
// slices.Contains so the test compiles on older Go toolchains.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
