// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- attrsToMap ---

func TestAttrsToMap(t *testing.T) {
	t.Parallel()

	entry := newLDAPEntry("cn=user,dc=example", map[string][]string{
		"cn":   {"user", "User Name"},
		"mail": {"user@example.com"},
	})

	got := attrsToMap(entry, []string{"cn", "mail", "absent"})

	require.Len(t, got, 3)
	assert.Equal(t, []string{"user", "User Name"}, got["cn"])
	assert.Equal(t, []string{"user@example.com"}, got["mail"])
	// Every requested key is present; missing attributes map to an
	// empty, non-nil slice (go-ldap's GetAttributeValues contract),
	// not to nil.
	val, ok := got["absent"]
	assert.True(t, ok)
	assert.Empty(t, val)
}

func TestAttrsToMap_EmptyAttributes(t *testing.T) {
	t.Parallel()

	entry := newLDAPEntry("cn=user", map[string][]string{"cn": {"user"}})
	got := attrsToMap(entry, nil)

	assert.NotNil(t, got)
	assert.Empty(t, got)
}

// TestAttrsToMap_DeduplicatesNames pins H1: a duplicate name in the
// `attributes` slice must not depend on map-assignment ordering. Prior
// behaviour was "last write wins" (Go evaluates the right-hand side
// before the assignment, and the map just stores the result). With
// dedup via "first occurrence wins", the result is deterministic and
// the entry is queried once per distinct name.
func TestAttrsToMap_DeduplicatesNames(t *testing.T) {
	t.Parallel()

	entry := newLDAPEntry("cn=user,dc=example", map[string][]string{
		"cn": {"user"},
	})

	// Duplicates: "cn" appears three times.
	got := attrsToMap(entry, []string{"cn", "cn", "cn"})

	require.Len(t, got, 1)
	assert.Equal(t, []string{"user"}, got["cn"])
}

// --- escapeFilterArgs ---

func TestEscapeFilterArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []any
		want []any
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "plain string",
			in:   []any{"alice"},
			want: []any{"alice"},
		},
		{
			name: "special chars escaped",
			in:   []any{"a*b(c)"},
			want: []any{`a\2ab\28c\29`},
		},
		{
			name: "backslash escaped",
			in:   []any{`a\b`},
			want: []any{`a\5cb`},
		},
		{
			name: "nil element becomes empty string",
			in:   []any{"x", nil, "y"},
			want: []any{"x", "", "y"},
		},
		{
			name: "non-string rendered via fmt.Sprint",
			in:   []any{42},
			want: []any{"42"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, escapeFilterArgs(tt.in))
		})
	}
}

// --- parentDNOf ---

func TestParentDNOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dn   string
		want string
	}{
		{
			name: "user under dc",
			dn:   "cn=user,dc=example,dc=com",
			want: "dc=example,dc=com",
		},
		{
			name: "single RDN has no parent",
			dn:   "dc=example",
			want: "",
		},
		{
			name: "empty DN",
			dn:   "",
			want: "",
		},
		{
			name: "invalid DN falls back to empty",
			dn:   "not-a-dn",
			want: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, parentDNOf(tt.dn))
		})
	}
}

func TestParentDNOf_MultiValuedRDNPreservedAsOneRDN(t *testing.T) {
	t.Parallel()

	got := parentDNOf("cn=user,ou=sales+ou=east,dc=example")

	parsed, err := ldap.ParseDN(got)
	require.NoError(t, err, "parentDNOf must return a parsable DN: %q", got)
	require.Len(t, parsed.RDNs, 2,
		"the multi-valued RDN must stay intact, not be split")

	// go-ldap does not guarantee attribute order inside a multi-valued
	// RDN, so assert on the set of attributes, not on the literal string.
	attrs := parsed.RDNs[0].Attributes
	require.Len(t, attrs, 2)
	assert.ElementsMatch(t,
		[]string{"ou=sales", "ou=east"},
		[]string{
			attrs[0].Type + "=" + attrs[0].Value,
			attrs[1].Type + "=" + attrs[1].Value,
		})
	assert.Equal(t, "dc=example", parsed.RDNs[1].String())
}

// --- canonicalDN ---

func TestCanonicalDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		b    string
	}{
		{
			name: "case-insensitive attribute types",
			a:    "CN=user,DC=example",
			b:    "cn=user,dc=example",
		},
		{
			name: "case-insensitive values",
			a:    "cn=User,dc=example",
			b:    "cn=user,dc=example",
		},
		{
			name: "multi-valued RDN order does not matter",
			a:    "cn=a+sn=b,dc=x",
			b:    "sn=b+cn=a,dc=x",
		},
		{
			name: "leading and trailing spaces in value are trimmed",
			a:    "cn=  user  ,dc=x",
			b:    "cn=user,dc=x",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, canonicalDN(tt.a), canonicalDN(tt.b))
		})
	}

	// RDN order is significant — different parents must not collide.
	assert.NotEqual(t,
		canonicalDN("cn=user,ou=a,dc=x"),
		canonicalDN("cn=user,ou=b,dc=x"),
	)

	// Malformed DNs fall back to lowercased raw string (documented behaviour):
	// downstream AncestorOfFold will reject them, so we only assert the
	// fallback is deterministic and case-folded.
	assert.Equal(t, "not-a-dn", canonicalDN("NOT-A-DN"))
}

func TestCanonicalDN_EquivalenceWithParseDN(t *testing.T) {
	t.Parallel()

	// Escaped and unescaped forms of the same value must produce the same
	// canonical key. ldap.ParseDN normalizes escapes to underlying octets.
	parsed, err := ldap.ParseDN("cn=Smith\\, John,dc=example")
	require.NoError(t, err)

	assert.Equal(t,
		canonicalDN(parsed.String()),
		canonicalDN("cn=Smith\\, John,dc=example"),
	)
}

// TestCanonicalDN_StructuralAmbiguity pins the B4 contract: structurally
// different DNs that previously collapsed to the same key at a join point
// must now produce distinct keys, while semantically equivalent spellings
// keep mapping to the same key.
func TestCanonicalDN_StructuralAmbiguity(t *testing.T) {
	t.Parallel()

	t.Run("comma in value must not alias with RDN separator", func(t *testing.T) {
		t.Parallel()

		// cn=a,ou=b    → two RDNs:  {cn=a}, {ou=b}
		// cn=a\,ou=b   → one RDN:   {cn="a,ou=b"}
		// Before escaping these produced the same canonical string.
		assert.NotEqual(t,
			canonicalDN(`cn=a,ou=b`),
			canonicalDN(`cn=a\,ou=b`),
			"comma in value must not alias with RDN separator")
	})

	t.Run("plus in value must not alias with attribute separator", func(t *testing.T) {
		t.Parallel()

		// cn=a+ou=b    → one RDN, two attributes
		// cn=a\+ou=b   → one RDN, one attribute with value "a+ou=b"
		assert.NotEqual(t,
			canonicalDN(`cn=a+ou=b`),
			canonicalDN(`cn=a\+ou=b`),
			"plus in value must not alias with attribute separator")
	})

	t.Run("escaped and unescaped equals in value are the same DN", func(t *testing.T) {
		t.Parallel()

		// Both spellings parse to cn="a=b"; the canonical key must agree.
		assert.Equal(t,
			canonicalDN(`cn=a=b`),
			canonicalDN(`cn=a\=b`),
			"escaped and unescaped equals in value are the same DN")
	})

	t.Run("backslash: hex and escape spellings agree", func(t *testing.T) {
		t.Parallel()

		// \5c and \\ both decode to a single literal backslash.
		assert.Equal(t,
			canonicalDN(`cn=a\5cb,dc=x`),
			canonicalDN(`cn=a\\b,dc=x`),
			"hex and escaped backslash must produce the same key")
	})

	t.Run("escaped comma does not alias with structural plus", func(t *testing.T) {
		t.Parallel()

		// cn=a\,dc=x   → one RDN: {cn="a,dc=x"}
		// cn=a+dc=x    → one RDN: {cn=a, dc=x}
		// Same attribute count, same types, different structure — must differ.
		assert.NotEqual(t,
			canonicalDN(`cn=a\,dc=x`),
			canonicalDN(`cn=a+dc=x`),
			"escaped comma and structural plus describe different DNs")
	})
}

// TestEscapeCanonicalValue pins the escaping rules applied to the value
// before joining. The output is an opaque key, so the exact spelling is
// asserted to catch accidental changes that would break the wire format
// of keys produced for the catalog tree.
func TestEscapeCanonicalValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "no special chars", in: "alice", want: "alice"},
		{name: "comma", in: "a,b", want: `a\,b`},
		{name: "plus", in: "a+b", want: `a\+b`},
		{name: "equals", in: "a=b", want: `a\=b`},
		{name: "backslash", in: `a\b`, want: `a\\b`},
		{name: "multiple", in: `a,b+c=d\e`, want: `a\,b\+c\=d\\e`},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, escapeCanonicalValue(tt.in))
		})
	}
}
