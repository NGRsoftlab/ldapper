// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDS389Adapter_UserObjectFilter_IncludesNetscapeClasses(t *testing.T) {
	t.Parallel()

	f := DS389Adapter{}.UserObjectFilter()
	requireValidFilter(t, f)

	assert.Contains(t, f, "objectClass=nsAccount")
	assert.Contains(t, f, "objectClass=nsOrgPerson")
	assert.Contains(t, f, "objectClass=posixAccount")
	assert.Contains(t, f, "objectClass=inetOrgPerson")
	assert.Contains(t, f, "objectClass=person")
}

func TestDS389Adapter_GroupObjectFilter_InheritedFromOpenLDAP(t *testing.T) {
	t.Parallel()

	// 389-DS uses the same three group models as OpenLDAP.
	f := DS389Adapter{}.GroupObjectFilter()
	requireValidFilter(t, f)

	assert.Contains(t, f, "groupOfNames")
	assert.Contains(t, f, "groupOfUniqueNames")
	assert.Contains(t, f, "posixGroup")
}

func TestDS389Adapter_UserAttrs_IncludesNsAccountLock(t *testing.T) {
	t.Parallel()

	attrs := DS389Adapter{}.UserAttrs()
	assert.Contains(t, attrs, "nsAccountLock",
		"389-DS exposes account state via nsAccountLock; UserAttrs must request it")

	// Inherited from OpenLDAP: still present.
	assert.Contains(t, attrs, "uid")
	assert.Contains(t, attrs, "jpegPhoto")
}

func TestDS389Adapter_GetNormalizedUserInfo_InheritedMapping(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("uid=alice,ou=People,dc=x", attrMap(map[string]string{
		"cn":               "Alice",
		"departmentNumber": "Engineering",
		"jpegPhoto":        "photo-bytes",
		"mobile":           "+1-555-0100",
	}))

	info := DS389Adapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)
	assert.Equal(t, "Alice", info.CommonName)
	assert.Equal(t, "Engineering", info.Department)
	assert.Equal(t, []byte("photo-bytes"), info.Photo)
	assert.Equal(t, "+1-555-0100", info.Mobile)
}

func TestDS389Adapter_BindIdentity_InheritedFromOpenLDAP(t *testing.T) {
	t.Parallel()

	// Short-form login expands to uid=<login>,<baseDN>; full DNs pass through.
	got, err := DS389Adapter{}.BindIdentity("alice", "ou=People,dc=example")
	require.NoError(t, err)
	assert.Equal(t, "uid=alice,ou=People,dc=example", got)

	_, err = DS389Adapter{}.BindIdentity("", "dc=x")
	require.Error(t, err)
}

func TestDS389Adapter_SearchUserFilterTemplate_Valid(t *testing.T) {
	t.Parallel()

	tmpl := DS389Adapter{}.SearchUserFilterTemplate()
	f := fmt.Sprintf(tmpl, ldap.EscapeFilter("alice"))
	requireValidFilter(t, f)
	assert.Contains(t, f, "uid=alice")
	assert.Contains(t, f, "entryDN=alice")
}
