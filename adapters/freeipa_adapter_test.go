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

// Compile-time assertion: FREEIPAAdapter must satisfy CatalogAdapter.
// If a method signature drifts, this line fails first with a clear message.
var _ interfaces.CatalogAdapter = FREEIPAAdapter{}

// TestFREEIPAAdapter_ImplementsCatalogAdapter is a runtime companion to the
// package-level var _ above. Keeps the conformance check visible in `go test`
// output when someone wonders whether the adapter is wired up correctly.
func TestFREEIPAAdapter_ImplementsCatalogAdapter(t *testing.T) {
	var adapter interfaces.CatalogAdapter = FREEIPAAdapter{}
	require.NotNil(t, adapter)
}

// ---------------------------------------------------------------------------
// GetNormalizedUserInfo
// ---------------------------------------------------------------------------

func TestFREEIPAAdapter_GetNormalizedUserInfo_FullMapping(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := newLDAPUser(
		"uid=user1,cn=users,cn=accounts,dc=example,dc=test",
		map[string][]string{
			"dn":              {"uid=user1,cn=users,cn=accounts,dc=example,dc=test"},
			"cn":              {"User One"},
			"mobile":          {"+1-555-0100"},
			"telephoneNumber": {"+1-555-0101"},
			"mail":            {"user1@example.test"},
			"title":           {"Engineer"},
			"manager":         {"uid=boss,cn=users,cn=accounts,dc=example,dc=test"},
			"jpegPhoto":       {"photo-bytes"},
			"co":              {"US"},
			"street":          {"123 Main St"},
			"l":               {"Springfield"},
			"postalCode":      {"12345"},
		},
	)

	info := adapter.GetNormalizedUserInfo(user)
	require.NotNil(t, info)

	assert.Equal(t, "uid=user1,cn=users,cn=accounts,dc=example,dc=test", info.DistinguishedName)
	assert.Equal(t, "User One", info.CommonName)
	assert.Equal(t, "+1-555-0100", info.Mobile)
	assert.Equal(t, "+1-555-0101", info.Phone)
	assert.Equal(t, "user1@example.test", info.Mail)
	assert.Equal(t, "Engineer", info.Title)
	assert.Equal(t, "uid=boss,cn=users,cn=accounts,dc=example,dc=test", info.Manager)
	assert.Equal(t, "photo-bytes", info.Photo)
	assert.Equal(t, "US", info.Country)
	assert.Equal(t, "123 Main St", info.Address)
	assert.Equal(t, "Springfield", info.City)
	assert.Equal(t, "12345", info.Index)

	// FreeIPA hardcodes these to "" (department is not exposed on users,
	// company is not present in FreeIPA schema).
	assert.Equal(t, "", info.Department)
	assert.Equal(t, "", info.Company)
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_EmptyUser(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("", nil)

	info := adapter.GetNormalizedUserInfo(user)
	require.NotNil(t, info)

	// Every field must default to "" and the call must not panic.
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

func TestFREEIPAAdapter_GetNormalizedUserInfo_FirstValueWins(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("", map[string][]string{
		"cn":   {"First CN", "Second CN"},
		"mail": {"first@x", "second@x"},
	})

	info := adapter.GetNormalizedUserInfo(user)
	assert.Equal(t, "First CN", info.CommonName)
	assert.Equal(t, "first@x", info.Mail)
}

// FreeIPA uses "street" for the address field — this guard catches an
// accidental copy-paste of the ALDPro/MSAD mapping, which uses "streetAddress".
func TestFREEIPAAdapter_GetNormalizedUserInfo_UsesStreetNotStreetAddress(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := newLDAPUser("", map[string][]string{
		"street":        {"Main Street"},
		"streetAddress": {"IGNORED"},
	})

	info := adapter.GetNormalizedUserInfo(user)
	assert.Equal(t, "Main Street", info.Address)
}

// ---------------------------------------------------------------------------
// OUInfoFromEntry
// ---------------------------------------------------------------------------

func TestFREEIPAAdapter_OUInfoFromEntry(t *testing.T) {
	adapter := FREEIPAAdapter{}
	entry := ldap.Entry{
		DN: "ou=people,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "ou", Values: []string{"people"}},
		},
	}

	info := adapter.OUInfoFromEntry(entry)
	require.NotNil(t, info)

	assert.Equal(t, "ou=people,dc=example,dc=test", info.DN)
	// FreeIPA sets Name = full DN (not just the leaf ou value).
	assert.Equal(t, "ou=people,dc=example,dc=test", info.Name)
	assert.Equal(t, "people", info.OU)

	// Children must be a non-nil empty slice so callers can append without
	// a nil check.
	require.NotNil(t, info.Children)
	assert.Empty(t, info.Children)
}

func TestFREEIPAAdapter_OUInfoFromEntry_EmptyEntry(t *testing.T) {
	adapter := FREEIPAAdapter{}
	info := adapter.OUInfoFromEntry(ldap.Entry{})

	require.NotNil(t, info)
	assert.Zero(t, info.DN)
	assert.Zero(t, info.OU)
	assert.NotNil(t, info.Children)
}

// ---------------------------------------------------------------------------
// Object filters (exact strings act as regression guards)
// ---------------------------------------------------------------------------

func TestFREEIPAAdapter_ObjectFilters_ExactStrings(t *testing.T) {
	adapter := FREEIPAAdapter{}

	assert.Equal(t,
		"(|(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))",
		adapter.UserObjectFilter())
	assert.Equal(t,
		"(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))",
		adapter.GroupObjectFilter())
	assert.Equal(t,
		"(|(objectClass=organizationalUnit)(objectClass=nsContainer))",
		adapter.OUObjectFilter())
}

// ---------------------------------------------------------------------------
// Search filters — sanity check via go-ldap's parser, plus exact string
// regression guards for the two most-touched filters.
// ---------------------------------------------------------------------------

// TestFREEIPAAdapter_SearchFilters_AreValidLDAP substitutes real values into
// every Search* template and asks go-ldap to parse the result. This catches
// typos and the previous (member=uid=%s) regression on the syntax level.
func TestFREEIPAAdapter_SearchFilters_AreValidLDAP(t *testing.T) {
	adapter := FREEIPAAdapter{}

	user := types.LDAPUser{
		DN:         "uid=user1,cn=users,cn=accounts,dc=example,dc=test",
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
			filter: fmt.Sprintf(adapter.SearchOUFilterTemplate(), "people"),
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

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplate_ExactString(t *testing.T) {
	adapter := FREEIPAAdapter{}

	// FreeIPA groups are matched via `member` (DN-valued). Regression guard
	// against reintroducing (member=uid=%s) or similar.
	assert.Equal(t,
		"(&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=%s))",
		adapter.SearchUserGroupsFilterTemplate())

	assert.NotContains(t, adapter.SearchUserGroupsFilterTemplate(), "member=uid=",
		"regression: earlier versions had (member=uid=%s) which is not a valid DN lookup")
}

// ---------------------------------------------------------------------------
// SearchUserGroupsFilterTemplateArgs
// ---------------------------------------------------------------------------

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs_ReturnsDN(t *testing.T) {
	adapter := FREEIPAAdapter{}
	user := newLDAPUser(
		"uid=user1,cn=users,cn=accounts,dc=example,dc=test",
		map[string][]string{"uid": {"user1"}},
	)

	args := adapter.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 1)
	assert.Equal(t, "uid=user1,cn=users,cn=accounts,dc=example,dc=test", args[0],
		"args[0] must be the user's DN for (member=%s) to match groupOfNames")
}

// TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs_OneArgPerPlaceholder
// is a structural check: template placeholders must line up with the args.
// This is what breaks when someone edits the template without editing Args().
func TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs_OneArgPerPlaceholder(t *testing.T) {
	adapter := FREEIPAAdapter{}
	template := adapter.SearchUserGroupsFilterTemplate()
	args := adapter.SearchUserGroupsFilterTemplateArgs(newLDAPUser("uid=x,dc=e", nil))

	placeholderCount := strings.Count(template, "%s")
	require.Equal(t, placeholderCount, len(args),
		"template has %d placeholder(s) but Args() returned %d value(s)",
		placeholderCount, len(args))
}

// ---------------------------------------------------------------------------
// Attrs — verify the key attributes required by GetNormalizedUserInfo are
// actually fetched from the server.
// ---------------------------------------------------------------------------

func TestFREEIPAAdapter_UserAttrs_ContainsMappedAttributes(t *testing.T) {
	adapter := FREEIPAAdapter{}

	// Every attribute that GetNormalizedUserInfo reads from LDAPUser must be
	// present in UserAttrs; otherwise the data is never requested from the
	// server and the normalized field stays empty.
	required := []string{
		"dn", "cn", "mobile", "telephoneNumber", "mail", "title",
		"manager", "jpegPhoto", "co", "street", "l", "postalCode",
	}

	attrs := adapter.UserAttrs()
	for _, r := range required {
		assert.Contains(t, attrs, r,
			"UserAttrs must contain %q because GetNormalizedUserInfo reads it", r)
	}
}

func TestFREEIPAAdapter_UserAttrs_DistinguishingAttributes(t *testing.T) {
	adapter := FREEIPAAdapter{}
	attrs := adapter.UserAttrs()

	// FreeIPA-specific attributes.
	assert.Contains(t, attrs, "nsAccountLock")
	assert.Contains(t, attrs, "ipaUniqueID")

	// FreeIPA uses "street", not "streetAddress".
	assert.Contains(t, attrs, "street")
	assert.NotContains(t, attrs, "streetAddress",
		"streetAddress is the MSAD/ALDPro spelling; FreeIPA uses street")

	// ALDPro-specific attribute must not leak into FreeIPA.
	assert.NotContains(t, attrs, "rbtadp")
}

func TestFREEIPAAdapter_GroupAttrs_DistinguishingAttributes(t *testing.T) {
	adapter := FREEIPAAdapter{}
	attrs := adapter.GroupAttrs()

	assert.Contains(t, attrs, "cn")
	assert.Contains(t, attrs, "member")
	assert.Contains(t, attrs, "memberUid")
	assert.Contains(t, attrs, "memberIndirect") // FreeIPA-specific operational attr
	assert.Contains(t, attrs, "ipaUniqueID")
	assert.Contains(t, attrs, "ipaNTSecurityIdentifier")
}

func TestFREEIPAAdapter_OUAttrs_ContainsExpected(t *testing.T) {
	adapter := FREEIPAAdapter{}
	attrs := adapter.OUAttrs()

	assert.NotEmpty(t, attrs)
	assert.Contains(t, attrs, "ou")
	assert.Contains(t, attrs, "objectClass")
	assert.Contains(t, attrs, "description")
}
