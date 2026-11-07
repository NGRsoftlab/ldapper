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

func TestFREEIPAAdapter_GetNormalizedUserInfo_AllFields(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,cn=users,cn=accounts,dc=example", attrMap(map[string]string{
		"cn":              "Alice Smith",
		"mobile":          "+1-555-0100",
		"telephoneNumber": "+1-555-0101",
		"mail":            "alice@example.com",
		"title":           "Senior Engineer",
		"manager":         "uid=bob,cn=users,cn=accounts,dc=example",
		"o":               "Acme Corp",
		"co":              "US",
		"street":          "123 Main St",
		"l":               "Springfield",
		"postalCode":      "12345",
	}))

	info := FREEIPAAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)

	assert.Equal(t, "uid=alice,cn=users,cn=accounts,dc=example", info.DistinguishedName)
	assert.Equal(t, "Alice Smith", info.CommonName)
	assert.Equal(t, "+1-555-0100", info.Mobile)
	assert.Equal(t, "+1-555-0101", info.Phone)
	assert.Equal(t, "alice@example.com", info.Mail)
	assert.Equal(t, "Senior Engineer", info.Title)
	assert.Equal(t, "uid=bob,cn=users,cn=accounts,dc=example", info.Manager)
	assert.Equal(t, "Acme Corp", info.Company)
	assert.Equal(t, "US", info.Country)
	assert.Equal(t, "123 Main St", info.Address)
	assert.Equal(t, "Springfield", info.City)
	assert.Equal(t, "12345", info.Index)

	// FreeIPA has no direct analogue for department in the fields the
	// adapter reads; it deliberately returns empty rather than guessing.
	assert.Empty(t, info.Department)
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_Photo(t *testing.T) {
	t.Parallel()

	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	user := newLDAPUser("uid=alice,dc=x", map[string][]string{
		"jpegPhoto": {string(jpeg)},
	})

	info := FREEIPAAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)
	assert.Equal(t, jpeg, info.Photo)
}

func TestFREEIPAAdapter_GetNormalizedUserInfo_EmptyAttributes(t *testing.T) {
	t.Parallel()

	info := FREEIPAAdapter{}.GetNormalizedUserInfo(newLDAPUser("uid=alice,dc=x", nil))
	require.NotNil(t, info)
	assert.Equal(t, "uid=alice,dc=x", info.DistinguishedName)
	assert.Empty(t, info.CommonName)
	assert.Nil(t, info.Photo)
}

// ================== GetNormalizedOUInfoFromEntry ==================

func TestFREEIPAAdapter_GetNormalizedOUInfoFromEntry(t *testing.T) {
	t.Parallel()

	t.Run("organizationalUnit uses ou attribute", func(t *testing.T) {
		t.Parallel()

		entry := newLDAPEntry("ou=sales,dc=example,dc=com", map[string][]string{
			"ou":          {"sales"},
			"objectClass": {"organizationalUnit"},
		})

		info := FREEIPAAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info)
		assert.Equal(t, "sales", info.Name)
		assert.Equal(t, "sales", info.OU)
	})

	t.Run("nsContainer falls back to cn attribute", func(t *testing.T) {
		t.Parallel()

		// nsContainer has cn, not ou — the fallback is what makes
		// FreeIPA's container objects appear with a sensible OU value.
		entry := newLDAPEntry("cn=users,cn=accounts,dc=example", map[string][]string{
			"cn":          {"users"},
			"objectClass": {"nsContainer"},
		})

		info := FREEIPAAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info)
		assert.Equal(t, "users", info.OU,
			"nsContainer must yield cn as OU")
		assert.Equal(t, "users", info.Name)
	})

	t.Run("neither ou nor cn leaves OU empty", func(t *testing.T) {
		t.Parallel()

		entry := newLDAPEntry("ou=sales,dc=example", nil)
		info := FREEIPAAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info)
		assert.Equal(t, "sales", info.Name, "Name still derives from the DN")
		assert.Empty(t, info.OU, "OU must not be fabricated when both attrs are absent")
	})

	t.Run("Children is non-nil empty slice", func(t *testing.T) {
		t.Parallel()

		entry := newLDAPEntry("ou=x,dc=x", nil)
		info := FREEIPAAdapter{}.GetNormalizedOUInfoFromEntry(entry)
		require.NotNil(t, info.Children)
		assert.Empty(t, info.Children)
	})
}

// ================== BindIdentity ==================

func TestFREEIPAAdapter_BindIdentity(t *testing.T) {
	t.Parallel()

	t.Run("empty login", func(t *testing.T) {
		t.Parallel()
		_, err := FREEIPAAdapter{}.BindIdentity("", "dc=x")
		require.Error(t, err)
	})

	t.Run("DN passes through unchanged", func(t *testing.T) {
		t.Parallel()

		cases := []string{
			"uid=alice,cn=users,cn=accounts,dc=example",
			"cn=Alice,dc=example",
			"dc=example",
		}
		for _, dn := range cases {
			dn := dn
			t.Run(dn, func(t *testing.T) {
				t.Parallel()
				got, err := FREEIPAAdapter{}.BindIdentity(dn, "dc=ignored")
				require.NoError(t, err)
				assert.Equal(t, dn, got)
			})
		}
	})

	t.Run("short uid expanded through users/accounts chain", func(t *testing.T) {
		t.Parallel()

		got, err := FREEIPAAdapter{}.BindIdentity("alice", "dc=example,dc=com")
		require.NoError(t, err)
		assert.Equal(t, "uid=alice,cn=users,cn=accounts,dc=example,dc=com", got,
			"FreeIPA user DN must nest uid under cn=users,cn=accounts")
	})

	t.Run("short uid without baseDN is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := FREEIPAAdapter{}.BindIdentity("alice", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "baseDN")
	})

	t.Run("special chars in uid are escaped", func(t *testing.T) {
		t.Parallel()

		got, err := FREEIPAAdapter{}.BindIdentity("alice,admin", "dc=example")
		require.NoError(t, err)

		parsed, err := ldap.ParseDN(got)
		require.NoError(t, err, "BindIdentity must produce a parsable DN: %q", got)
		require.Len(t, parsed.RDNs[0].Attributes, 1)
		assert.Equal(t, "uid", parsed.RDNs[0].Attributes[0].Type)
		assert.Equal(t, "alice,admin", parsed.RDNs[0].Attributes[0].Value)
	})

	t.Run("invalid baseDN is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := FREEIPAAdapter{}.BindIdentity("alice", "not-a-dn")
		require.Error(t, err)
	})

	t.Run("chain order is uid,users,accounts,base", func(t *testing.T) {
		t.Parallel()

		// Parse and walk the RDN list explicitly: a regression that
		// swapped "users" and "accounts" would still parse but bind
		// would fail against a real FreeIPA server, and only this
		// ordering assertion catches it deterministically.
		got, err := FREEIPAAdapter{}.BindIdentity("alice", "dc=example")
		require.NoError(t, err)

		parsed, err := ldap.ParseDN(got)
		require.NoError(t, err)
		require.Len(t, parsed.RDNs, 4)

		assert.Equal(t, "uid=alice", parsed.RDNs[0].String())
		assert.Equal(t, "cn=users", parsed.RDNs[1].String())
		assert.Equal(t, "cn=accounts", parsed.RDNs[2].String())
		assert.Equal(t, "dc=example", parsed.RDNs[3].String())
	})
}

// ================== Filter templates ==================

func TestFREEIPAAdapter_SearchUserFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := FREEIPAAdapter{}.SearchUserFilterTemplate()

	t.Run("valid with plain arg", func(t *testing.T) {
		t.Parallel()

		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("alice"))
		requireValidFilter(t, f)

		// Union of object classes FreeIPA users can have.
		assert.Contains(t, f, "objectClass=posixAccount")
		assert.Contains(t, f, "objectClass=inetOrgPerson")
		assert.Contains(t, f, "objectClass=person")

		// uid OR entryDN so the same filter matches both short-login
		// and full-DN bind principals.
		assert.Contains(t, f, "uid=alice")
		assert.Contains(t, f, "entryDN=alice")
	})

	t.Run("escapes special chars", func(t *testing.T) {
		t.Parallel()

		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("a*b(c)"))
		requireValidFilter(t, f)
		assert.Contains(t, f, `a\2ab\28c\29`)
	})
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := FREEIPAAdapter{}.SearchUserGroupsFilterTemplate()
	f := fmt.Sprintf(tmpl,
		ldap.EscapeFilter("uid=alice,cn=users,cn=accounts,dc=example"),
		ldap.EscapeFilter("alice"),
	)
	requireValidFilter(t, f)

	// DN-based membership: member OR memberIndirect (nested groups).
	assert.Contains(t, f, "objectClass=groupOfNames")
	assert.Contains(t, f, "objectClass=ipaUserGroup")
	assert.Contains(t, f, "member=uid=alice")
	assert.Contains(t, f, "memberIndirect=uid=alice")

	// posixGroup uses the SHORT uid.
	assert.Contains(t, f, "objectClass=posixGroup")
	assert.Contains(t, f, "memberUid=alice")
	assert.NotContains(t, f, "memberUid=uid=alice",
		"memberUid must carry the short uid, not the DN")
}

func TestFREEIPAAdapter_SearchUserGroupsFilterTemplateArgs(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,cn=users,cn=accounts,dc=example",
		attrMap(map[string]string{"uid": "alice"}))

	args := FREEIPAAdapter{}.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)
	assert.Equal(t, "uid=alice,cn=users,cn=accounts,dc=example", args[0])
	assert.Equal(t, "alice", args[1])
}

func TestFREEIPAAdapter_SearchOUFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(FREEIPAAdapter{}.SearchOUFilterTemplate(), ldap.EscapeFilter("users"))
	requireValidFilter(t, f)

	// nsContainer must be accepted alongside organizationalUnit —
	// FreeIPA stores user containers as nsContainer.
	assert.Contains(t, f, "objectClass=organizationalUnit")
	assert.Contains(t, f, "objectClass=nsContainer")
	assert.Contains(t, f, "ou=users")
	assert.Contains(t, f, "cn=users",
		"nsContainer has cn, not ou — the filter must match on both")
}

func TestFREEIPAAdapter_SearchGroupFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(FREEIPAAdapter{}.SearchGroupFilterTemplate(), ldap.EscapeFilter("admins"))
	requireValidFilter(t, f)

	assert.Contains(t, f, "groupOfNames")
	assert.Contains(t, f, "posixGroup")
	assert.Contains(t, f, "ipaUserGroup")
	assert.Contains(t, f, "cn=admins")
}

func TestFREEIPAAdapter_ObjectFilters(t *testing.T) {
	t.Parallel()

	a := FREEIPAAdapter{}
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

func TestFREEIPAAdapter_OUObjectFilter_IncludesNsContainer(t *testing.T) {
	t.Parallel()

	// nsContainer objects are organisational units in FreeIPA's model.
	// If this union disappears from the object filter, GetCatalogTree
	// will silently miss every nsContainer node.
	f := FREEIPAAdapter{}.OUObjectFilter()
	assert.Contains(t, f, "objectClass=organizationalUnit")
	assert.Contains(t, f, "objectClass=nsContainer")
}

// ================== Attrs ==================

func TestFREEIPAAdapter_Attrs_ContainRequiredForSearch(t *testing.T) {
	t.Parallel()

	attrs := FREEIPAAdapter{}.UserAttrs()

	// uid powers SearchUserGroupsFilterTemplateArgs → memberUid.
	assert.Contains(t, attrs, "uid")
	// jpegPhoto must be requested or Photo in the normalized info is
	// always nil.
	assert.Contains(t, attrs, "jpegPhoto")
	// nsAccountLock distinguishes disabled accounts; it's part of the
	// adapter's contract even if not surfaced in UserNormalizedInfo.
	assert.Contains(t, attrs, "nsAccountLock")
}

func TestFREEIPAAdapter_Attrs_NonEmpty(t *testing.T) {
	t.Parallel()

	a := FREEIPAAdapter{}
	assert.NotEmpty(t, a.UserAttrs())
	assert.NotEmpty(t, a.OUAttrs())
	assert.NotEmpty(t, a.GroupAttrs())
}

func TestFREEIPAAdapter_OUAttrs_IncludeCnAndOu(t *testing.T) {
	t.Parallel()

	// Both are needed: ou for organizationalUnit, cn for nsContainer
	// fallback in GetNormalizedOUInfoFromEntry.
	attrs := FREEIPAAdapter{}.OUAttrs()
	assert.Contains(t, attrs, "ou")
	assert.Contains(t, attrs, "cn")
	assert.Contains(t, attrs, "objectClass")
}

func TestFREEIPAAdapter_GroupAttrs_CoverAllMembershipModels(t *testing.T) {
	t.Parallel()

	attrs := FREEIPAAdapter{}.GroupAttrs()
	assert.Contains(t, attrs, "member", "groupOfNames/ipaUserGroup membership")
	assert.Contains(t, attrs, "memberIndirect", "nested FreeIPA membership")
	assert.Contains(t, attrs, "memberUid", "posixGroup membership")
}

// Compile-time guard: adapter must satisfy the catalog interface.
var _ interface {
	BindIdentity(login, baseDN string) (string, error)
	SearchUserGroupsFilterTemplateArgs(types.LDAPUser) []any
} = FREEIPAAdapter{}
