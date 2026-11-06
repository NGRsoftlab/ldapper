// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"testing"
)

// TestValidateDN covers the permissive variant. The only contract:
//   - syntactically parseable DN → nil,
//   - otherwise → ErrInvalidArgument.
//
// NB: an empty string is a valid DN (root DSE) at this layer — callers
// that require a non-empty base must use validateBaseDN instead.
func TestValidateDN(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{"simple dc pair", "dc=example,dc=com", false},
		{"ou with cn", "cn=John Doe,ou=Users,dc=example,dc=com", false},
		{"multi-valued rdn", "cn=foo+sn=bar,dc=example,dc=com", false},
		{"escaped comma", `cn=Doe\, John,dc=example,dc=com`, false},
		{"empty dn is valid (root DSE)", "", false},
		{"no equals sign", "this is not a dn", true},
		{"trailing comma", "cn=foo,", true},
		{"unbalanced escape", `cn=foo\`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDN(tc.dn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateDN(%q) = nil, want error", tc.dn)
				}
				if !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("validateDN(%q) error = %v, want ErrInvalidArgument", tc.dn, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateDN(%q) = %v, want nil", tc.dn, err)
			}
		})
	}
}

// TestValidateBaseDN covers the strict variant used by search methods: an
// empty DN would trigger a full-tree search, so it must be rejected.
func TestValidateBaseDN(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{"valid base", "dc=example,dc=com", false},
		{"empty base rejected", "", true},
		{"invalid base rejected", "not a dn", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBaseDN(tc.dn)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateBaseDN(%q) = nil, want error", tc.dn)
				}
				if !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("validateBaseDN(%q) error = %v, want ErrInvalidArgument", tc.dn, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateBaseDN(%q) = %v, want nil", tc.dn, err)
			}
		})
	}
}

// TestValidateHost covers the host-string guard that prevents URL-injection
// into the ldap/ldaps URI template.
func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"dns name", "ldap.example.com", false},
		{"simple dns", "ldap", false},
		{"ipv4", "192.168.1.10", false},
		{"ipv6 without brackets", "::1", false},
		{"ipv6 long form", "2001:db8::1", false},
		{"empty host", "", true},
		{"dns with port", "example.com:389", true},
		{"dns with path", "example.com/path", true},
		{"dns with scheme", "ldap://example.com", true},
		{"ipv4 with slash", "10.0.0.1/24", true},
		{"ipv6 in brackets", "[::1]", true},
		{"with query char", "example.com?x", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHost(tc.host)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateHost(%q) = nil, want error", tc.host)
				}
				if !errors.Is(err, ErrInvalidArgument) {
					t.Fatalf("validateHost(%q) error = %v, want ErrInvalidArgument", tc.host, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateHost(%q) = %v, want nil", tc.host, err)
			}
		})
	}
}

// TestFormatHost covers URI host formatting: IPv6 literals must be enclosed
// in brackets per RFC 3986; everything else is passed through untouched.
func TestFormatHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"ipv4 untouched", "192.168.1.10", "192.168.1.10"},
		{"dns untouched", "ldap.example.com", "ldap.example.com"},
		{"ipv6 gets brackets", "::1", "[::1]"},
		{"ipv6 long form gets brackets", "2001:db8::1", "[2001:db8::1]"},
		{"empty untouched", "", ""},
		{"not-an-ip untouched", "not-an-ip", "not-an-ip"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatHost(tc.host); got != tc.want {
				t.Fatalf("formatHost(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}
