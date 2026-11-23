// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

// SAMBAAdapter is a strict extension of MSADAdapter: every behaviour must
// match the AD one. These tests assert the delegation explicitly, so a
// future refactor that accidentally overrides a method cannot silently
// drift from the AD contract.
func TestSAMBAAdapter_DelegatesToMSAD(t *testing.T) {
	t.Parallel()

	a := SAMBAAdapter{}
	ad := MSADAdapter{}

	user := newLDAPUser("cn=alice,dc=x", attrMap(map[string]string{
		"cn":             "Alice",
		"mail":           "alice@example.com",
		"department":     "Engineering",
		"thumbnailPhoto": "thumb-bytes",
	}))

	assert.Equal(t, ad.GetNormalizedUserInfo(user), a.GetNormalizedUserInfo(user))

	entry := newLDAPEntry("ou=sales,dc=x", map[string][]string{"name": {"Sales"}})
	assert.Equal(t, ad.GetNormalizedOUInfoFromEntry(entry), a.GetNormalizedOUInfoFromEntry(entry))

	for name, f := range map[string]string{
		"UserObjectFilter":  ad.UserObjectFilter(),
		"GroupObjectFilter": ad.GroupObjectFilter(),
		"OUObjectFilter":    ad.OUObjectFilter(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			switch name {
			case "UserObjectFilter":
				assert.Equal(t, f, a.UserObjectFilter())
			case "GroupObjectFilter":
				assert.Equal(t, f, a.GroupObjectFilter())
			case "OUObjectFilter":
				assert.Equal(t, f, a.OUObjectFilter())
			}
		})
	}

	assert.Equal(t, ad.SearchUserFilterTemplate(), a.SearchUserFilterTemplate())
	assert.Equal(t, ad.SearchUserGroupsFilterTemplate(), a.SearchUserGroupsFilterTemplate())
	assert.Equal(t, ad.SearchOUFilterTemplate(), a.SearchOUFilterTemplate())
	assert.Equal(t, ad.SearchGroupFilterTemplate(), a.SearchGroupFilterTemplate())
	assert.Equal(t, ad.UserAttrs(), a.UserAttrs())
	assert.Equal(t, ad.OUAttrs(), a.OUAttrs())
	assert.Equal(t, ad.GroupAttrs(), a.GroupAttrs())
}

func TestSAMBAAdapter_ImplementsPrimaryGroupResolver(t *testing.T) {
	t.Parallel()

	// Samba AD DC supports primaryGroupID / objectSid exactly like MS AD,
	// so the resolver inherited from MSADAdapter must be reachable through
	// the interface — this is what GetUserGroups type-asserts on.
	var _ interface {
		ResolvePrimaryGroupDN(ctx context.Context, user types.LDAPUser, conn interfaces.LDAPConn) (string, error)
	} = SAMBAAdapter{}
}
