// Copyright 2020-2026 NGR Softlab
package adapters

import "testing"

// TestOuNameFromDN covers the shared fallback behaviour used by every
// adapter: extract the first RDN value when the DN parses; otherwise return
// the DN verbatim so that tree discovery does not crash on malformed data.
func TestOuNameFromDN(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{
			name: "simple ou",
			dn:   "ou=Sales,dc=example,dc=com",
			want: "Sales",
		},
		{
			name: "cn as first rdn",
			dn:   "cn=John Doe,ou=Users,dc=example,dc=com",
			want: "John Doe",
		},
		{
			name: "no dc suffix",
			dn:   "ou=Empty",
			want: "Empty",
		},
		{
			name: "escaped comma in value",
			dn:   `ou=Research\,Development,dc=example,dc=com`,
			want: `Research,Development`,
		},
		{
			name: "empty dn falls back to input",
			dn:   "",
			want: "",
		},
		{
			name: "malformed dn falls back to input",
			dn:   "this is not a dn",
			want: "this is not a dn",
		},
		{
			name: "multi-valued rdn returns first attribute value",
			dn:   "ou=Sales+cn=Secondary,dc=example,dc=com",
			want: "Sales",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ouNameFromDN(tc.dn); got != tc.want {
				t.Fatalf("ouNameFromDN(%q) = %q, want %q", tc.dn, got, tc.want)
			}
		})
	}
}
