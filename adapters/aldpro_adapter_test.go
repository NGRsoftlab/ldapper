// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/types"
)

// ================== GetNormalizedUserInfo ==================

func TestALDPROAdapter_GetNormalizedUserInfo_AllFields(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,ou=people,dc=example", attrMap(map[string]string{
		"cn":              "Alice Smith",
		"mobile":          "+1-555-0100",
		"telephoneNumber": "+1-555-0101",
		"mail":            "alice@example.com",
		"rbtadp":          "Engineering", // ALDPro's department analogue
		"title":           "Senior Engineer",
		"manager":         "uid=bob,ou=people,dc=example",
		"o":               "Acme Corp",
		"co":              "US",
		"streetAddress":   "123 Main St",
		"l":               "Springfield",
		"postalCode":      "12345",
	}))

	info := ALDPROAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)

	assert.Equal(t, "uid=alice,ou=people,dc=example", info.DistinguishedName)
	assert.Equal(t, "Alice Smith", info.CommonName)
	assert.Equal(t, "+1-555-0100", info.Mobile)
	assert.Equal(t, "+1-555-0101", info.Phone)
	assert.Equal(t, "alice@example.com", info.Mail)

	// The mapping from rbtadp (not "department") to Department is
	// ALDPro-specific — the whole reason this adapter exists separately.
	assert.Equal(t, "Engineering", info.Department)

	assert.Equal(t, "Senior Engineer", info.Title)
	assert.Equal(t, "uid=bob,ou=people,dc=example", info.Manager)
	assert.Equal(t, "Acme Corp", info.Company)
	assert.Equal(t, "US", info.Country)
	assert.Equal(t, "123 Main St", info.Address)
	assert.Equal(t, "Springfield", info.City)
	assert.Equal(t, "12345", info.Index)
}

func TestALDPROAdapter_GetNormalizedUserInfo_DepartmentFromRbtadp(t *testing.T) {
	t.Parallel()

	// Explicit contract: even if a "department" attribute is present, the
	// adapter must read rbtadp — ALDPro writes department into rbtadp,
	// not into the standard department attribute.
	user := newLDAPUser("uid=alice,dc=x", map[string][]string{
		"rbtadp":     {"from-rbtadp"},
		"department": {"from-department"},
	})

	info := ALDPROAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)
	assert.Equal(t, "from-rbtadp", info.Department,
		"ALDPro department lives in rbtadp, not department")
}

func TestALDPROAdapter_GetNormalizedUserInfo_Photo(t *testing.T) {
	t.Parallel()

	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	user := newLDAPUser("uid=alice,dc=x", map[string][]string{
		"jpegPhoto": {string(jpeg)},
	})

	info := ALDPROAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)
	assert.Equal(t, jpeg, info.Photo)
}

func TestALDPROAdapter_GetNormalizedUserInfo_EmptyAttributes(t *testing.T) {
	t.Parallel()

	info := ALDPROAdapter{}.GetNormalizedUserInfo(newLDAPUser("uid=alice,dc=x", nil))
	require.NotNil(t, info)
	assert.Equal(t, "uid=alice,dc=x", info.DistinguishedName)
	assert.Empty(t, info.CommonName)
	assert.Empty(t, info.Department)
	assert.Nil(t, info.Photo)
}

// ================== GetNormalizedOUInfoFromEntry ==================

func TestALDPROAdapter_GetNormalizedOUInfoFromEntry(t *testing.T) {
	t.Parallel()

	t.Run("organizationalUnit uses ou attribute", func(t *testing.T) {
		t.Parallel()

		entry := newLDAPEntry("ou=sales,dc=example", map[string][]string{
			"ou":          {"sales"},
			"objectClass": {"organizationalUnit"},
		})

		info := ALDPROAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info)
		assert.Equal(t, "sales", info.Name)
		assert.Equal(t, "sales", info.OU)
	})

	t.Run("rbta-org-unit falls back to cn attribute", func(t *testing.T) {
		t.Parallel()

		// rbta-org-unit is ALDPro's alternative to organizationalUnit;
		// it uses cn for the name, exactly like FreeIPA's nsContainer.
		entry := newLDAPEntry("cn=departments,dc=example", map[string][]string{
			"cn":          {"departments"},
			"objectClass": {"rbta-org-unit"},
		})

		info := ALDPROAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info)
		assert.Equal(t, "departments", info.OU,
			"rbta-org-unit must yield cn as OU")
		assert.Equal(t, "departments", info.Name)
	})

	t.Run("neither ou nor cn leaves OU empty", func(t *testing.T) {
		t.Parallel()

		entry := newLDAPEntry("ou=sales,dc=example", nil)
		info := ALDPROAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info)
		assert.Equal(t, "sales", info.Name)
		assert.Empty(t, info.OU, "OU must not be fabricated when both attrs are absent")
	})

	t.Run("Children is non-nil empty slice", func(t *testing.T) {
		t.Parallel()

		entry := newLDAPEntry("ou=x,dc=x", nil)
		info := ALDPROAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info.Children)
		assert.Empty(t, info.Children)
	})
}

// ================== BindIdentity ==================

func TestALDPROAdapter_BindIdentity(t *testing.T) {
	t.Parallel()

	t.Run("empty login", func(t *testing.T) {
		t.Parallel()
		_, err := ALDPROAdapter{}.BindIdentity("", "dc=x")
		require.Error(t, err)
	})

	t.Run("passes login through unchanged", func(t *testing.T) {
		t.Parallel()

		// ALDPro accepts UPN and DN as bind principals, like AD. There is
		// no short-form support: a bare login is passed through as-is and
		// the server rejects it if it cannot be mapped.
		cases := []string{
			"alice@example.com",
			"uid=alice,ou=people,dc=example",
			"cn=Alice Smith,dc=example",
			"alice", // passed through; the server decides
		}
		for _, login := range cases {
			login := login
			t.Run(login, func(t *testing.T) {
				t.Parallel()
				got, err := ALDPROAdapter{}.BindIdentity(login, "dc=ignored")
				require.NoError(t, err)
				assert.Equal(t, login, got,
					"ALDPro must pass the login through without transformation")
			})
		}
	})

	t.Run("baseDN is ignored", func(t *testing.T) {
		t.Parallel()

		// Unlike OPENLDAP/FREEIPA, ALDPro does not use baseDN to construct
		// the principal. Verify baseDN truly has no effect.
		got1, _ := ALDPROAdapter{}.BindIdentity("alice", "dc=a")
		got2, _ := ALDPROAdapter{}.BindIdentity("alice", "dc=b")
		assert.Equal(t, got1, got2)
	})
}

// ================== Filter templates ==================

func TestALDPROAdapter_SearchUserFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := ALDPROAdapter{}.SearchUserFilterTemplate()

	t.Run("valid with plain arg", func(t *testing.T) {
		t.Parallel()

		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("alice"))
		requireValidFilter(t, f)

		assert.Contains(t, f, "objectClass=posixAccount")
		assert.Contains(t, f, "objectClass=inetOrgPerson")
		assert.Contains(t, f, "objectClass=person")
		assert.Contains(t, f, "uid=alice")
		assert.Contains(t, f, "entryDN=alice",
			"DN-form bind principals must match via entryDN")
	})

	t.Run("escapes special chars", func(t *testing.T) {
		t.Parallel()

		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("a*b(c)"))
		requireValidFilter(t, f)
		assert.Contains(t, f, `a\2ab\28c\29`)
	})
}

func TestALDPROAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := ALDPROAdapter{}.SearchUserGroupsFilterTemplate()
	f := fmt.Sprintf(tmpl,
		ldap.EscapeFilter("uid=alice,ou=people,dc=example"),
		ldap.EscapeFilter("alice"),
	)
	requireValidFilter(t, f)

	// DN-based membership.
	assert.Contains(t, f, "objectClass=groupOfNames")
	assert.Contains(t, f, "objectClass=ipaUserGroup")
	assert.Contains(t, f, "member=uid=alice")
	assert.Contains(t, f, "memberIndirect=uid=alice")

	// posixGroup uses the SHORT uid.
	assert.Contains(t, f, "objectClass=posixGroup")
	assert.Contains(t, f, "memberUid=alice")
	assert.NotContains(t, f, "memberUid=uid=alice")
}

func TestALDPROAdapter_SearchUserGroupsFilterTemplateArgs(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,ou=people,dc=example",
		attrMap(map[string]string{"uid": "alice"}))

	args := ALDPROAdapter{}.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)
	assert.Equal(t, "uid=alice,ou=people,dc=example", args[0])
	assert.Equal(t, "alice", args[1])
}

func TestALDPROAdapter_SearchOUFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(ALDPROAdapter{}.SearchOUFilterTemplate(), ldap.EscapeFilter("sales"))
	requireValidFilter(t, f)

	// Both object classes must be accepted (rbta-org-unit is ALDPro's
	// equivalent of organizationalUnit).
	assert.Contains(t, f, "objectClass=organizationalUnit")
	assert.Contains(t, f, "objectClass=rbta-org-unit")
	// Both ou= and cn= alternatives, because rbta-org-unit has cn, not ou.
	assert.Contains(t, f, "ou=sales")
	assert.Contains(t, f, "cn=sales")
}

func TestALDPROAdapter_SearchGroupFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(ALDPROAdapter{}.SearchGroupFilterTemplate(), ldap.EscapeFilter("admins"))
	requireValidFilter(t, f)

	assert.Contains(t, f, "groupOfNames")
	assert.Contains(t, f, "posixGroup")
	assert.Contains(t, f, "ipaUserGroup")
	assert.Contains(t, f, "cn=admins")
}

func TestALDPROAdapter_ObjectFilters(t *testing.T) {
	t.Parallel()

	a := ALDPROAdapter{}
	for name, f := range map[string]string{
		"UserObjectFilter":  a.UserObjectFilter(),
		"GroupObjectFilter": a.GroupObjectFilter(),
		"OUObjectFilter":    a.OUObjectFilter(),
	} {
		f := f
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireValidFilter(t, f)
		})
	}
}

func TestALDPROAdapter_OUObjectFilter_IncludesRbtaOrgUnit(t *testing.T) {
	t.Parallel()

	// Without rbta-org-unit in this union, GetCatalogTree would miss
	// every ALDPro-specific container node.
	f := ALDPROAdapter{}.OUObjectFilter()
	assert.Contains(t, f, "objectClass=organizationalUnit")
	assert.Contains(t, f, "objectClass=rbta-org-unit")
}

// ================== Attrs ==================

func TestALDPROAdapter_Attrs_ContainRequiredForSearch(t *testing.T) {
	t.Parallel()

	attrs := ALDPROAdapter{}.UserAttrs()

	// uid powers SearchUserGroupsFilterTemplateArgs → memberUid.
	assert.Contains(t, attrs, "uid")
	// rbtadp feeds Department in UserNormalizedInfo.
	assert.Contains(t, attrs, "rbtadp")
	// jpegPhoto feeds Photo.
	assert.Contains(t, attrs, "jpegPhoto")
}

func TestALDPROAdapter_Attrs_NonEmpty(t *testing.T) {
	t.Parallel()

	a := ALDPROAdapter{}
	assert.NotEmpty(t, a.UserAttrs())
	assert.NotEmpty(t, a.OUAttrs())
	assert.NotEmpty(t, a.GroupAttrs())
}

func TestALDPROAdapter_OUAttrs_IncludeCnAndOu(t *testing.T) {
	t.Parallel()

	// Both needed for the fallback logic in GetNormalizedOUInfoFromEntry.
	attrs := ALDPROAdapter{}.OUAttrs()
	assert.Contains(t, attrs, "ou")
	assert.Contains(t, attrs, "cn")
	assert.Contains(t, attrs, "objectClass")
}

func TestALDPROAdapter_GroupAttrs_CoverAllMembershipModels(t *testing.T) {
	t.Parallel()

	attrs := ALDPROAdapter{}.GroupAttrs()
	assert.Contains(t, attrs, "member")
	assert.Contains(t, attrs, "memberIndirect")
	assert.Contains(t, attrs, "memberUid")
}

// Compile-time guard: adapter must satisfy the catalog interface.
var _ interface {
	BindIdentity(login, baseDN string) (string, error)
	SearchUserGroupsFilterTemplateArgs(types.LDAPUser) []any
} = ALDPROAdapter{}
