// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/types"
)

// newLDAPUser returns a types.LDAPUser ready for adapter tests.
//
// A nil attrs map is replaced with a non-nil empty map. GetAttributeValue and
// GetFirstNonNullAttributeValue already tolerate a nil map, but an explicit
// empty map reads cleaner when a test fails and the struct is dumped to the
// log — you see "Attributes: map[]" rather than "Attributes: map[]" with no
// indication of whether nil was intentional.
func newLDAPUser(dn string, attrs map[string][]string) types.LDAPUser {
	if attrs == nil {
		attrs = map[string][]string{}
	}
	return types.LDAPUser{DN: dn, Attributes: attrs}
}

// attrMap converts a single-valued attribute map into the multi-valued form
// used by types.LDAPUser.Attributes. The vast majority of user and OU
// attributes carry exactly one value, so this builder removes a layer of
// literal boilerplate:
//
//	newLDAPUser("cn=a,dc=x", attrMap(map[string]string{
//	    "cn":   "Alice",
//	    "mail": "alice@example.com",
//	}))
//
// instead of:
//
//	newLDAPUser("cn=a,dc=x", map[string][]string{
//	    "cn":   {"Alice"},
//	    "mail": {"alice@example.com"},
//	})
//
// Do not use it for genuinely multi-valued attributes (member, memberOf,
// objectClass, ...) — build those inline so the multiplicity stays visible
// in the test source and a future reader cannot accidentally "fix" the test
// by collapsing to attrMap.
//
// A nil input yields a nil result, matching map semantics.
func attrMap(m map[string]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}

// newLDAPEntry builds an ldap.Entry from a DN and an attribute map.
//
// Attribute order in the resulting entry is unspecified — production code
// (adapter GetNormalized* methods) looks attributes up by name, so order
// never matters, and keeping the helper trivial avoids accidentally
// encoding an ordering assumption into tests.
//
// The value form (ldap.Entry, not *ldap.Entry) matches the signature of
// CatalogAdapter.GetNormalizedOUInfoFromEntry, so tests can pass the result
// directly without a dereference:
//
//	info := ALDPROAdapter{}.GetNormalizedOUInfoFromEntry(
//	    newLDAPEntry("ou=Sales,dc=x", attrMap(map[string]string{"ou": "Sales"})))
func newLDAPEntry(dn string, attrs map[string][]string) ldap.Entry {
	entry := ldap.Entry{DN: dn}
	for name, values := range attrs {
		byteValues := make([][]byte, len(values))
		for i, v := range values {
			byteValues[i] = []byte(v)
		}
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
			Name:       name,
			Values:     values,
			ByteValues: byteValues,
		})
	}
	return entry
}

// requireValidFilter parses filter via go-ldap and fails the test with a
// helpful message on any syntax error.
//
// Adapter tests use it to validate that a template plus escaped args
// produces a well-formed LDAP filter without dialing a real server. Kept as
// a helper rather than inlined so that every filter assertion in the package
// reports the same diagnostic format, including the raw filter text (which
// is what you actually want when a template edit breaks parsing).
func requireValidFilter(t *testing.T, filter string) {
	t.Helper()
	_, err := ldap.CompileFilter(filter)
	require.NoError(t, err, "invalid LDAP filter: %q", filter)
}
