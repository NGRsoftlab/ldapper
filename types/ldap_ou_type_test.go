// Copyright 2020-2026 NGR Softlab
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ================== GetAttributeValue ==================

func TestLDAPOU_GetAttributeValue(t *testing.T) {
	t.Parallel()

	ou := &LDAPOU{
		DN: "ou=sales,dc=x",
		Attributes: map[string][]string{
			"ou":          {"sales"},
			"description": {"Sales department", "Second line"},
		},
	}

	t.Run("single value", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "sales", ou.GetAttributeValue("ou"))
	})

	t.Run("multi value returns first", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "Sales department", ou.GetAttributeValue("description"))
	})

	t.Run("missing attribute", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, ou.GetAttributeValue("managedBy"))
	})

	t.Run("nil Attributes", func(t *testing.T) {
		t.Parallel()
		empty := &LDAPOU{DN: "ou=x,dc=x"}
		assert.Empty(t, empty.GetAttributeValue("ou"))
	})
}

// ================== GetFirstNonNullAttributeValue ==================

func TestLDAPOU_GetFirstNonNullAttributeValue(t *testing.T) {
	t.Parallel()

	t.Run("first present wins", func(t *testing.T) {
		t.Parallel()

		ou := &LDAPOU{Attributes: map[string][]string{
			"ou": {"sales"},
			"cn": {"SalesContainer"},
		}}
		assert.Equal(t, "sales",
			ou.GetFirstNonNullAttributeValue([]string{"ou", "cn"}))
	})

	t.Run("empty first falls through", func(t *testing.T) {
		t.Parallel()

		ou := &LDAPOU{Attributes: map[string][]string{
			"ou": {""},
			"cn": {"SalesContainer"},
		}}
		assert.Equal(t, "SalesContainer",
			ou.GetFirstNonNullAttributeValue([]string{"ou", "cn"}))
	})

	t.Run("all missing returns empty", func(t *testing.T) {
		t.Parallel()

		ou := &LDAPOU{}
		assert.Empty(t, ou.GetFirstNonNullAttributeValue([]string{"ou", "cn"}))
	})

	t.Run("nil alternatives", func(t *testing.T) {
		t.Parallel()

		ou := &LDAPOU{Attributes: map[string][]string{"ou": {"sales"}}}
		assert.Empty(t, ou.GetFirstNonNullAttributeValue(nil))
	})
}

// ================== DN field ==================

func TestLDAPOU_DNIsPreservedVerbatim(t *testing.T) {
	t.Parallel()

	dn := "OU=Sales,DC=Example,DC=Com"
	ou := &LDAPOU{DN: dn}

	assert.Equal(t, dn, ou.DN)
	assert.Empty(t, ou.GetAttributeValue("ou"),
		"getters read Attributes, not DN")
}

// ================== nil-attributes value ==================

func TestLDAPOU_ZeroValueDoesNotPanic(t *testing.T) {
	t.Parallel()

	var ou LDAPOU
	assert.Empty(t, ou.GetAttributeValue("ou"))
	assert.Empty(t, ou.GetFirstNonNullAttributeValue([]string{"ou", "cn"}))
}
