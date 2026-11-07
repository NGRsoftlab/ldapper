// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ================== ouNameFromDN ==================

func TestOuNameFromDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dn   string
		want string
	}{
		{
			name: "simple OU",
			dn:   "ou=sales,dc=example,dc=com",
			want: "sales",
		},
		{
			name: "single RDN",
			dn:   "ou=sales",
			want: "sales",
		},
		{
			name: "user DN returns first RDN value",
			dn:   "cn=Alice,ou=sales,dc=example",
			want: "Alice",
		},
		{
			name: "escaped comma preserved",
			dn:   `ou=Sales\, East,dc=example`,
			want: "Sales, East",
		},
		{
			name: "multi-valued RDN takes the first attribute",
			dn:   "ou=sales+description=x,dc=example",
			want: "sales",
		},
		{
			name: "empty DN falls back to raw",
			dn:   "",
			want: "",
		},
		{
			name: "invalid DN falls back to raw",
			dn:   "not-a-dn",
			want: "not-a-dn",
		},
		{
			name: "malformed with comma-only falls back",
			dn:   ",",
			want: ",",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, ouNameFromDN(tt.dn))
		})
	}
}

func TestOuNameFromDN_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	// ldap.ParseDN does not mutate the input string; ouNameFromDN must
	// return a value derived from it, never the input itself when parsing
	// succeeds. This is a sanity check on the fallback path: the returned
	// string on success must NOT be identical to the full input.
	dn := "ou=sales,dc=example"
	got := ouNameFromDN(dn)

	assert.NotEqual(t, dn, got)
	assert.Equal(t, "sales", got)
}

// ================== appendRDN ==================

func TestAppendRDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		attrTyp string
		value   string
		baseDN  string
		want    string
		wantErr bool
	}{
		{
			name:    "simple prepend",
			attrTyp: "uid",
			value:   "alice",
			baseDN:  "dc=example,dc=com",
			want:    "uid=alice,dc=example,dc=com",
		},
		{
			name:    "single RDN base",
			attrTyp: "cn",
			value:   "users",
			baseDN:  "dc=example",
			want:    "cn=users,dc=example",
		},
		{
			name:    "comma in value must be escaped",
			attrTyp: "cn",
			value:   "Smith, John",
			baseDN:  "dc=example",
			want:    `cn=Smith\, John,dc=example`,
		},
		{
			name:    "plus in value must be escaped",
			attrTyp: "cn",
			value:   "a+b",
			baseDN:  "dc=example",
			want:    `cn=a\+b,dc=example`,
		},
		{
			name:    "equals in value is not escaped (RFC 4514)",
			attrTyp: "cn",
			value:   "a=b",
			baseDN:  "dc=example",
			want:    "cn=a=b,dc=example", // '=' is literal in the value position
		},
		{
			name:    "backslash in value must be escaped",
			attrTyp: "cn",
			value:   `a\b`,
			baseDN:  "dc=example",
			want:    `cn=a\\b,dc=example`,
		},
		{
			name:    "invalid base DN",
			attrTyp: "uid",
			value:   "alice",
			baseDN:  "not-a-dn",
			wantErr: true,
		},
		{
			name:    "empty base DN yields a single-RDN DN (root DSE)",
			attrTyp: "uid",
			value:   "alice",
			baseDN:  "",
			want:    "uid=alice",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := appendRDN(tt.attrTyp, tt.value, tt.baseDN)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAppendRDN_ProducesParsableDN(t *testing.T) {
	t.Parallel()

	// Whatever appendRDN produces must itself round-trip through
	// ldap.ParseDN — that's the real invariant bind principals rely on.
	// The specific escaping style is implementation detail; parsability
	// is the contract.
	cases := []struct{ typ, val, base string }{
		{"uid", "alice", "dc=example,dc=com"},
		{"cn", "Smith, John", "dc=example"},
		{"cn", `weird\value+with=specials`, "dc=x"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.val, func(t *testing.T) {
			t.Parallel()

			got, err := appendRDN(c.typ, c.val, c.base)
			require.NoError(t, err)

			parsed, err := ldap.ParseDN(got)
			require.NoError(t, err, "appendRDN must produce a parsable DN: %q", got)
			require.NotNil(t, parsed)
			require.NotEmpty(t, parsed.RDNs)

			// The prepended RDN must be first and carry the original value.
			require.Len(t, parsed.RDNs[0].Attributes, 1)
			assert.Equal(t, c.typ, parsed.RDNs[0].Attributes[0].Type)
			assert.Equal(t, c.val, parsed.RDNs[0].Attributes[0].Value,
				"round-trip must yield the original value")
		})
	}
}

func TestAppendRDN_ChainedPrependPreservesOrder(t *testing.T) {
	t.Parallel()

	// FreeIPA adapter chains appendRDN to build uid=<login>,cn=users,
	// cn=accounts,<baseDN>. The chain relies on the first argument
	// appearing leftmost in the result.
	first, err := appendRDN("cn", "accounts", "dc=example")
	require.NoError(t, err)

	second, err := appendRDN("cn", "users", first)
	require.NoError(t, err)

	third, err := appendRDN("uid", "alice", second)
	require.NoError(t, err)

	assert.Equal(t, "uid=alice,cn=users,cn=accounts,dc=example", third)
}
