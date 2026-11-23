// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenDJAdapter_UserAttrs_IncludesIsMemberOf(t *testing.T) {
	t.Parallel()

	attrs := OpenDJAdapter{}.UserAttrs()
	assert.Contains(t, attrs, "isMemberOf",
		"OpenDJ generates isMemberOf on user entries; UserAttrs must request it")

	// Inherited from OpenLDAP: still present.
	assert.Contains(t, attrs, "uid")
	assert.Contains(t, attrs, "jpegPhoto")
}

func TestOpenDJAdapter_GroupObjectFilter_InheritedFromOpenLDAP(t *testing.T) {
	t.Parallel()

	f := OpenDJAdapter{}.GroupObjectFilter()
	requireValidFilter(t, f)

	assert.Contains(t, f, "groupOfNames")
	assert.Contains(t, f, "groupOfUniqueNames")
	assert.Contains(t, f, "posixGroup")
}

func TestOpenDJAdapter_GroupAttrs_CoverAllMembershipModels(t *testing.T) {
	t.Parallel()

	attrs := OpenDJAdapter{}.GroupAttrs()
	assert.Contains(t, attrs, "member", "groupOfNames membership")
	assert.Contains(t, attrs, "uniqueMember", "groupOfUniqueNames membership")
	assert.Contains(t, attrs, "memberUid", "posixGroup membership")
}

func TestOpenDJAdapter_GetNormalizedUserInfo_InheritedMapping(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,ou=People,dc=x", attrMap(map[string]string{
		"cn":               "Alice",
		"departmentNumber": "Engineering",
		"jpegPhoto":        "photo-bytes",
		"mobile":           "+1-555-0100",
		"telephoneNumber":  "+1-555-0101",
		"mail":             "alice@example.com",
		"manager":          "uid=bob,ou=People,dc=x",
	}))

	info := OpenDJAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)
	assert.Equal(t, "Alice", info.CommonName)
	assert.Equal(t, "Engineering", info.Department)
	assert.Equal(t, []byte("photo-bytes"), info.Photo)
	assert.Equal(t, "+1-555-0100", info.Mobile)
	assert.Equal(t, "+1-555-0101", info.Phone)
	assert.Equal(t, "alice@example.com", info.Mail)
	assert.Equal(t, "uid=bob,ou=People,dc=x", info.Manager)
}

func TestOpenDJAdapter_BindIdentity_ShortForm(t *testing.T) {
	t.Parallel()

	got, err := OpenDJAdapter{}.BindIdentity("alice", "ou=People,dc=example")
	require.NoError(t, err)
	assert.Equal(t, "uid=alice,ou=People,dc=example", got)
}

func TestOpenDJAdapter_SearchUserGroupsFilterTemplate_Valid(t *testing.T) {
	t.Parallel()

	tmpl := OpenDJAdapter{}.SearchUserGroupsFilterTemplate()
	f := fmt.Sprintf(tmpl,
		ldap.EscapeFilter("uid=alice,ou=People,dc=example"),
		ldap.EscapeFilter("alice"),
	)
	requireValidFilter(t, f)

	// Inherited union of three branches.
	assert.Contains(t, f, "objectClass=groupOfNames")
	assert.Contains(t, f, "objectClass=groupOfUniqueNames")
	assert.Contains(t, f, "objectClass=posixGroup")
	assert.Contains(t, f, "member=uid=alice")
	assert.Contains(t, f, "uniqueMember=uid=alice")
	assert.Contains(t, f, "memberUid=alice")
}
