// Copyright 2020-2026 NGR Softlab
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ================== GetAttributeValue ==================

func TestLDAPGroup_GetAttributeValue(t *testing.T) {
	t.Parallel()

	group := &LDAPGroup{
		DN: "cn=admins,dc=x",
		Attributes: map[string][]string{
			"cn":     {"admins"},
			"member": {"uid=alice,dc=x", "uid=bob,dc=x"},
		},
	}

	t.Run("single value", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "admins", group.GetAttributeValue("cn"))
	})

	t.Run("multi value returns first", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "uid=alice,dc=x", group.GetAttributeValue("member"))
	})

	t.Run("missing attribute", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, group.GetAttributeValue("description"))
	})

	t.Run("nil Attributes", func(t *testing.T) {
		t.Parallel()
		empty := &LDAPGroup{DN: "cn=x,dc=x"}
		assert.Empty(t, empty.GetAttributeValue("cn"))
	})
}

// ================== GetFirstNonNullAttributeValue ==================

func TestLDAPGroup_GetFirstNonNullAttributeValue(t *testing.T) {
	t.Parallel()

	t.Run("first present wins", func(t *testing.T) {
		t.Parallel()

		group := &LDAPGroup{Attributes: map[string][]string{
			"cn":             {"admins"},
			"sAMAccountName": {"Admins"},
		}}
		assert.Equal(t, "admins",
			group.GetFirstNonNullAttributeValue([]string{"cn", "sAMAccountName"}))
	})

	t.Run("empty first falls through", func(t *testing.T) {
		t.Parallel()

		group := &LDAPGroup{Attributes: map[string][]string{
			"cn":             {""},
			"sAMAccountName": {"Admins"},
		}}
		assert.Equal(t, "Admins",
			group.GetFirstNonNullAttributeValue([]string{"cn", "sAMAccountName"}))
	})

	t.Run("all missing returns empty", func(t *testing.T) {
		t.Parallel()

		group := &LDAPGroup{}
		assert.Empty(t,
			group.GetFirstNonNullAttributeValue([]string{"cn", "sAMAccountName"}))
	})

	t.Run("nil alternatives", func(t *testing.T) {
		t.Parallel()

		group := &LDAPGroup{Attributes: map[string][]string{"cn": {"admins"}}}
		assert.Empty(t, group.GetFirstNonNullAttributeValue(nil))
	})
}

// ================== multi-valued membership ==================

func TestLDAPGroup_MembershipAttributesAreMultiValued(t *testing.T) {
	t.Parallel()

	// Group members are the primary reason Attributes is []string rather
	// than string. GetAttributeValue intentionally returns only the first
	// member; callers needing the full list must read .Attributes directly.
	group := &LDAPGroup{Attributes: map[string][]string{
		"member": {"uid=a,dc=x", "uid=b,dc=x", "uid=c,dc=x"},
	}}

	assert.Equal(t, "uid=a,dc=x", group.GetAttributeValue("member"))
	assert.Equal(t,
		[]string{"uid=a,dc=x", "uid=b,dc=x", "uid=c,dc=x"},
		group.Attributes["member"],
		"full list remains accessible on Attributes")
}

// ================== DN field ==================

func TestLDAPGroup_DNIsPreservedVerbatim(t *testing.T) {
	t.Parallel()

	dn := "CN=Admins,OU=Groups,DC=Example"
	group := &LDAPGroup{DN: dn}

	assert.Equal(t, dn, group.DN)
	assert.Empty(t, group.GetAttributeValue("cn"),
		"getters read Attributes, not DN")
}

// ================== nil-attributes value ==================

func TestLDAPGroup_ZeroValueDoesNotPanic(t *testing.T) {
	t.Parallel()

	var group LDAPGroup
	assert.Empty(t, group.GetAttributeValue("cn"))
	assert.Empty(t, group.GetFirstNonNullAttributeValue([]string{"cn", "sAMAccountName"}))
}
