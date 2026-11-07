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

func TestOPENLDAPAdapter_GetNormalizedUserInfo_AllFields(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,ou=people,dc=example", attrMap(map[string]string{
		"cn":               "Alice Smith",
		"mobile":           "+1-555-0100",
		"telephoneNumber":  "+1-555-0101",
		"mail":             "alice@example.com",
		"departmentNumber": "Engineering",
		"title":            "Senior Engineer",
		"manager":          "uid=bob,ou=people,dc=example",
		"o":                "Acme Corp",
		"postalAddress":    "123 Main St$Springfield$12345",
	}))

	info := OPENLDAPAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)

	assert.Equal(t, "uid=alice,ou=people,dc=example", info.DistinguishedName)
	assert.Equal(t, "Alice Smith", info.CommonName)
	assert.Equal(t, "+1-555-0100", info.Mobile)
	assert.Equal(t, "+1-555-0101", info.Phone)
	assert.Equal(t, "alice@example.com", info.Mail)
	assert.Equal(t, "Engineering", info.Department)
	assert.Equal(t, "Senior Engineer", info.Title)
	assert.Equal(t, "uid=bob,ou=people,dc=example", info.Manager)
	assert.Equal(t, "Acme Corp", info.Company)
	assert.Equal(t, "123 Main St$Springfield$12345", info.Address)

	// OPENLDAP schema has no obvious analogue for these; the adapter
	// deliberately leaves them empty rather than guessing.
	assert.Empty(t, info.Country)
	assert.Empty(t, info.City)
	assert.Empty(t, info.Index)
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_Photo(t *testing.T) {
	t.Parallel()

	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	user := newLDAPUser("uid=alice,dc=x", map[string][]string{
		"jpegPhoto": {string(jpeg)},
	})

	info := OPENLDAPAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)
	assert.Equal(t, jpeg, info.Photo,
		"jpegPhoto must be read via GetAttributeRawValue (lossless binary)")
}

func TestOPENLDAPAdapter_GetNormalizedUserInfo_EmptyAttributes(t *testing.T) {
	t.Parallel()

	info := OPENLDAPAdapter{}.GetNormalizedUserInfo(newLDAPUser("uid=alice,dc=x", nil))
	require.NotNil(t, info)
	assert.Equal(t, "uid=alice,dc=x", info.DistinguishedName)
	assert.Empty(t, info.CommonName)
	assert.Nil(t, info.Photo)
}

// ================== GetNormalizedOUInfoFromEntry ==================

func TestOPENLDAPAdapter_GetNormalizedOUInfoFromEntry(t *testing.T) {
	t.Parallel()

	entry := newLDAPEntry("ou=sales,dc=example,dc=com", map[string][]string{
		"ou": {"sales"},
	})

	info := OPENLDAPAdapter{}.GetNormalizedOUInfoFromEntry(entry)
	require.NotNil(t, info)

	assert.Equal(t, "ou=sales,dc=example,dc=com", info.DN)
	assert.Equal(t, "sales", info.Name)
	// OPENLDAP reads OU from the "ou" attribute, unlike MSAD which uses
	// the whole DN. This distinction is the reason a shared helper would
	// be wrong here.
	assert.Equal(t, "sales", info.OU)
	assert.NotNil(t, info.Children)
	assert.Empty(t, info.Children)
}

func TestOPENLDAPAdapter_GetNormalizedOUInfoFromEntry_MissingOuAttr(t *testing.T) {
	t.Parallel()

	// No ou attribute in the entry: OU ends up empty, but Name still
	// derives from the DN (via ouNameFromDN) — the adapter must not
	// fabricate a value that isn't there.
	entry := newLDAPEntry("ou=sales,dc=example", nil)

	info := OPENLDAPAdapter{}.GetNormalizedOUInfoFromEntry(entry)
	require.NotNil(t, info)
	assert.Equal(t, "sales", info.Name)
	assert.Empty(t, info.OU)
}

// ================== BindIdentity ==================

func TestOPENLDAPAdapter_BindIdentity(t *testing.T) {
	t.Parallel()

	t.Run("empty login", func(t *testing.T) {
		t.Parallel()
		_, err := OPENLDAPAdapter{}.BindIdentity("", "dc=x")
		require.Error(t, err)
	})

	t.Run("DN passes through unchanged", func(t *testing.T) {
		t.Parallel()

		cases := []string{
			"uid=alice,ou=people,dc=example",
			"cn=Alice Smith,dc=example",
			"dc=example", // valid DN, though an odd bind principal
		}
		for _, dn := range cases {
			dn := dn
			t.Run(dn, func(t *testing.T) {
				t.Parallel()
				got, err := OPENLDAPAdapter{}.BindIdentity(dn, "dc=ignored")
				require.NoError(t, err)
				assert.Equal(t, dn, got,
					"anything that parses as a DN must be passed through verbatim")
			})
		}
	})

	t.Run("short uid expanded with baseDN", func(t *testing.T) {
		t.Parallel()

		got, err := OPENLDAPAdapter{}.BindIdentity("alice", "ou=people,dc=example")
		require.NoError(t, err)
		assert.Equal(t, "uid=alice,ou=people,dc=example", got)
	})

	t.Run("short uid without baseDN is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := OPENLDAPAdapter{}.BindIdentity("alice", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "baseDN")
	})

	t.Run("special chars in uid are escaped", func(t *testing.T) {
		t.Parallel()

		// A short login may carry RFC 4514 metacharacters (commas, plus
		// signs, backslashes). appendRDN escapes them via ldap.DN.String().
		got, err := OPENLDAPAdapter{}.BindIdentity("alice,admin", "dc=example")
		require.NoError(t, err)

		parsed, err := ldap.ParseDN(got)
		require.NoError(t, err, "BindIdentity must produce a parsable DN: %q", got)
		require.Len(t, parsed.RDNs[0].Attributes, 1)
		assert.Equal(t, "uid", parsed.RDNs[0].Attributes[0].Type)
		assert.Equal(t, "alice,admin", parsed.RDNs[0].Attributes[0].Value,
			"original value must round-trip through the escaped DN")
	})

	t.Run("invalid baseDN is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := OPENLDAPAdapter{}.BindIdentity("alice", "not-a-dn")
		require.Error(t, err)
	})
}

// ================== Filter templates ==================

func TestOPENLDAPAdapter_SearchUserFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := OPENLDAPAdapter{}.SearchUserFilterTemplate()

	t.Run("valid with plain arg", func(t *testing.T) {
		t.Parallel()

		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("alice"))
		requireValidFilter(t, f)
		assert.Contains(t, f, "objectClass=person")
		assert.Contains(t, f, "uid=alice")
		// entryDN alternative: a caller may pass a full DN as the login
		// (it is passed through by BindIdentity), so the search must
		// match it as well.
		assert.Contains(t, f, "entryDN=alice")
	})

	t.Run("escapes special chars", func(t *testing.T) {
		t.Parallel()

		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("a*b(c)"))
		requireValidFilter(t, f)
		assert.Contains(t, f, `a\2ab\28c\29`)
	})
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := OPENLDAPAdapter{}.SearchUserGroupsFilterTemplate()

	// Build with two args: full DN (members) and short uid (posixGroup).
	f := fmt.Sprintf(tmpl,
		ldap.EscapeFilter("uid=alice,ou=people,dc=example"),
		ldap.EscapeFilter("alice"),
	)
	requireValidFilter(t, f)

	// All three membership models must be represented.
	assert.Contains(t, f, "objectClass=groupOfNames")
	assert.Contains(t, f, "member=uid=alice")
	assert.Contains(t, f, "objectClass=groupOfUniqueNames")
	assert.Contains(t, f, "uniqueMember=uid=alice")
	assert.Contains(t, f, "objectClass=posixGroup")
	// posixGroup membership uses the SHORT uid, not the DN — this is the
	// whole reason the template takes two arguments.
	assert.Contains(t, f, "memberUid=alice")
	assert.NotContains(t, f, "memberUid=uid=alice",
		"memberUid must carry the short uid, not the full DN")
}

func TestOPENLDAPAdapter_SearchUserGroupsFilterTemplateArgs(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,ou=people,dc=example", attrMap(map[string]string{
		"uid": "alice",
	}))

	args := OPENLDAPAdapter{}.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)
	assert.Equal(t, "uid=alice,ou=people,dc=example", args[0],
		"arg 0 (DN) feeds member/uniqueMember")
	assert.Equal(t, "alice", args[1],
		"arg 1 (short uid) feeds memberUid")
}

func TestOPENLDAPAdapter_SearchOUFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(OPENLDAPAdapter{}.SearchOUFilterTemplate(), ldap.EscapeFilter("sales"))
	requireValidFilter(t, f)
	assert.Contains(t, f, "objectClass=organizationalUnit")
	assert.Contains(t, f, "ou=sales")
}

func TestOPENLDAPAdapter_SearchGroupFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(OPENLDAPAdapter{}.SearchGroupFilterTemplate(), ldap.EscapeFilter("admins"))
	requireValidFilter(t, f)

	// All three group object classes the adapter recognises must be in
	// the search filter; otherwise a GetGroup call would miss half the
	// directory.
	assert.Contains(t, f, "groupOfNames")
	assert.Contains(t, f, "groupOfUniqueNames")
	assert.Contains(t, f, "posixGroup")
	assert.Contains(t, f, "cn=admins")
}

func TestOPENLDAPAdapter_ObjectFilters(t *testing.T) {
	t.Parallel()

	a := OPENLDAPAdapter{}
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

// ================== Attrs ==================

func TestOPENLDAPAdapter_Attrs_ContainRequiredForSearch(t *testing.T) {
	t.Parallel()

	// SearchUserFilterTemplate references uid and entryDN; the
	// group-membership resolver needs uid. If any of these disappear from
	// UserAttrs, GetUserGroups will silently drop posixGroup memberships.
	attrs := OPENLDAPAdapter{}.UserAttrs()
	assert.Contains(t, attrs, "uid")

	// jpegPhoto must be requested or GetNormalizedUserInfo's Photo will
	// always be nil.
	assert.Contains(t, attrs, "jpegPhoto")
}

func TestOPENLDAPAdapter_Attrs_NonEmpty(t *testing.T) {
	t.Parallel()

	a := OPENLDAPAdapter{}
	assert.NotEmpty(t, a.UserAttrs())
	assert.NotEmpty(t, a.OUAttrs())
	assert.NotEmpty(t, a.GroupAttrs())
}

func TestOPENLDAPAdapter_GroupAttrs_CoverAllMembershipModels(t *testing.T) {
	t.Parallel()

	// GroupAttrs is used by GetGroup; it must expose the membership
	// attributes for all three models so callers can inspect them.
	attrs := OPENLDAPAdapter{}.GroupAttrs()
	assert.Contains(t, attrs, "member", "groupOfNames membership")
	assert.Contains(t, attrs, "uniqueMember", "groupOfUniqueNames membership")
	assert.Contains(t, attrs, "memberUid", "posixGroup membership")
}

// Compile-time guard: the adapter must satisfy the catalog interface.
var _ interface {
	BindIdentity(login, baseDN string) (string, error)
	SearchUserGroupsFilterTemplateArgs(types.LDAPUser) []any
} = OPENLDAPAdapter{}
