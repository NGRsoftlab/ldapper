// Copyright 2020-2026 NGR Softlab
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ================== GetAttributeValue ==================

func TestLDAPUser_GetAttributeValue(t *testing.T) {
	t.Parallel()

	user := &LDAPUser{
		DN: "cn=alice,dc=x",
		Attributes: map[string][]string{
			"cn":   {"alice", "Alice Smith"},
			"mail": {"alice@example.com"},
		},
	}

	t.Run("returns first value", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "alice", user.GetAttributeValue("cn"))
	})

	t.Run("missing attribute", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, user.GetAttributeValue("telephoneNumber"))
	})

	t.Run("nil Attributes", func(t *testing.T) {
		t.Parallel()
		empty := &LDAPUser{DN: "cn=x"}
		assert.Empty(t, empty.GetAttributeValue("cn"))
	})
}

// ================== GetFirstNonNullAttributeValue ==================

func TestLDAPUser_GetFirstNonNullAttributeValue(t *testing.T) {
	t.Parallel()

	user := &LDAPUser{
		Attributes: map[string][]string{
			"thumbnailPhoto": {""}, // present but empty
			"jpegPhoto":      {"data"},
		},
	}

	t.Run("skips empty and picks the next alternative", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "data",
			user.GetFirstNonNullAttributeValue([]string{"thumbnailPhoto", "jpegPhoto"}))
	})

	t.Run("all alternatives missing", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t,
			user.GetFirstNonNullAttributeValue([]string{"a", "b"}))
	})

	t.Run("nil alternatives", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, user.GetFirstNonNullAttributeValue(nil))
	})
}

// ================== GetAttributeRawValue ==================

func TestLDAPUser_GetAttributeRawValue(t *testing.T) {
	t.Parallel()

	binary := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	user := &LDAPUser{
		Attributes: map[string][]string{
			"jpegPhoto": {string(binary)},
		},
	}

	t.Run("preserves non-UTF-8 bytes", func(t *testing.T) {
		t.Parallel()

		got := user.GetAttributeRawValue("jpegPhoto")
		require.Len(t, got, len(binary))
		for i := range binary {
			assert.Equal(t, binary[i], got[i], "byte %d must match", i)
		}
	})

	t.Run("missing attribute returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, user.GetAttributeRawValue("thumbnailPhoto"))
	})

	t.Run("explicit empty value is non-nil", func(t *testing.T) {
		t.Parallel()

		u := &LDAPUser{Attributes: map[string][]string{"photo": {""}}}
		got := u.GetAttributeRawValue("photo")
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
}

// ================== GetFirstNonNullAttributeRawValue ==================

func TestLDAPUser_GetFirstNonNullAttributeRawValue(t *testing.T) {
	t.Parallel()

	thumb := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE1}

	t.Run("first present wins", func(t *testing.T) {
		t.Parallel()

		u := &LDAPUser{Attributes: map[string][]string{
			"thumbnailPhoto": {string(thumb)},
			"jpegPhoto":      {string(jpeg)},
		}}
		assert.Equal(t, thumb,
			u.GetFirstNonNullAttributeRawValue([]string{"thumbnailPhoto", "jpegPhoto"}))
	})

	t.Run("empty first falls through to second", func(t *testing.T) {
		t.Parallel()

		u := &LDAPUser{Attributes: map[string][]string{
			"thumbnailPhoto": {""},
			"jpegPhoto":      {string(jpeg)},
		}}
		assert.Equal(t, jpeg,
			u.GetFirstNonNullAttributeRawValue([]string{"thumbnailPhoto", "jpegPhoto"}))
	})

	t.Run("none present returns nil", func(t *testing.T) {
		t.Parallel()

		u := &LDAPUser{}
		assert.Nil(t, u.GetFirstNonNullAttributeRawValue([]string{"a", "b"}))
	})
}

// ================== DN field ==================

func TestLDAPUser_DNIsPreservedVerbatim(t *testing.T) {
	t.Parallel()

	// DN is a plain field — the getters never touch it, and no
	// normalization happens in this layer (that is canonicalDN's job in
	// the ldapper package). Pin the contract: whatever the caller set
	// is what the getter returns via .DN.
	dn := "CN=Alice Smith,OU=Sales,DC=Example,DC=Com"
	user := &LDAPUser{DN: dn}

	assert.Equal(t, dn, user.DN)
	assert.Empty(t, user.GetAttributeValue("cn"),
		"getters read Attributes, not DN")
}

// ================== nil receiver ==================

func TestLDAPUser_ZeroValueDoesNotPanic(t *testing.T) {
	t.Parallel()

	// The helpers tolerate a nil Attributes map. A nil *LDAPUser is a
	// programming error on the caller side, but GetAttributeValue must
	// not panic merely because Attributes is absent from a value that
	// does exist. We do not test nil *LDAPUser (it would be a bug to
	// call a method on one); the value form with nil Attributes is the
	// realistic "empty entry" case.
	var user LDAPUser
	assert.Empty(t, user.GetAttributeValue("cn"))
	assert.Empty(t, user.GetFirstNonNullAttributeValue([]string{"cn"}))
	assert.Nil(t, user.GetAttributeRawValue("cn"))
	assert.Nil(t, user.GetFirstNonNullAttributeRawValue([]string{"cn"}))
}
