// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OUDAdapter is a strict extension of OpenDJAdapter: every behaviour must
// match the OpenDJ one. The tests mirror the OpenDJ suite and exist so
// that a future refactor cannot silently drift OUD from OpenDJ without
// changing these expectations.
func TestOUDAdapter_DelegatesToOpenDJ(t *testing.T) {
	t.Parallel()

	a := OUDAdapter{}
	odj := OpenDJAdapter{}

	user := newLDAPUser("uid=alice,ou=People,dc=x", attrMap(map[string]string{
		"cn":               "Alice",
		"departmentNumber": "Engineering",
		"jpegPhoto":        "photo-bytes",
	}))

	assert.Equal(t, odj.GetNormalizedUserInfo(user), a.GetNormalizedUserInfo(user))
	assert.Equal(t, odj.UserObjectFilter(), a.UserObjectFilter())
	assert.Equal(t, odj.GroupObjectFilter(), a.GroupObjectFilter())
	assert.Equal(t, odj.OUObjectFilter(), a.OUObjectFilter())
	assert.Equal(t, odj.SearchUserFilterTemplate(), a.SearchUserFilterTemplate())
	assert.Equal(t, odj.SearchUserGroupsFilterTemplate(), a.SearchUserGroupsFilterTemplate())
	assert.Equal(t, odj.SearchOUFilterTemplate(), a.SearchOUFilterTemplate())
	assert.Equal(t, odj.SearchGroupFilterTemplate(), a.SearchGroupFilterTemplate())
	assert.Equal(t, odj.UserAttrs(), a.UserAttrs())
	assert.Equal(t, odj.OUAttrs(), a.OUAttrs())
	assert.Equal(t, odj.GroupAttrs(), a.GroupAttrs())
}

func TestOUDAdapter_UserAttrs_IncludesIsMemberOf(t *testing.T) {
	t.Parallel()

	attrs := OUDAdapter{}.UserAttrs()
	assert.Contains(t, attrs, "isMemberOf")
}

func TestOUDAdapter_BindIdentity_ShortForm(t *testing.T) {
	t.Parallel()

	got, err := OUDAdapter{}.BindIdentity("alice", "ou=People,dc=example")
	require.NoError(t, err)
	assert.Equal(t, "uid=alice,ou=People,dc=example", got)
}
