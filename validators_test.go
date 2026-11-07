// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- validateDN ---

func TestValidateDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		// Valid DNs
		{name: "simple", dn: "cn=user", wantErr: false},
		{name: "full tree", dn: "cn=user,dc=example,dc=com", wantErr: false},
		{name: "single RDN domain", dn: "dc=example", wantErr: false},
		{name: "with spaces in value", dn: "cn=John Doe,dc=example,dc=com", wantErr: false},
		{name: "escaped comma in value", dn: `cn=Smith\, John,dc=example,dc=com`, wantErr: false},
		{name: "multi-valued RDN", dn: "cn=user+uid=u1,dc=example,dc=com", wantErr: false},

		// Invalid DNs
		{name: "no equal sign", dn: "not-a-dn", wantErr: true},
		{name: "garbage", dn: "((((", wantErr: true},
		{name: "leading comma", dn: ",cn=user", wantErr: true},
		{name: "trailing comma", dn: "cn=user,", wantErr: true},
		{name: "empty middle RDN", dn: "cn=user,,dc=example", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateDN(tt.dn)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidArgument)
				return
			}
			require.NoError(t, err)
		})
	}
}

// --- validateBaseDN ---

func TestValidateBaseDN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dn      string
		wantErr bool
	}{
		{name: "valid subtree", dn: "dc=example,dc=com", wantErr: false},
		{name: "single RDN", dn: "dc=example", wantErr: false},
		{name: "empty", dn: "", wantErr: true},
		{name: "invalid DN", dn: "not-a-dn", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateBaseDN(tt.dn)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidArgument)
				return
			}
			require.NoError(t, err)
		})
	}
}

// --- validateHost ---

func TestValidateHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// Empty
		{name: "empty", host: "", wantErr: true},

		// IPv4
		{name: "ipv4 simple", host: "192.168.1.1", wantErr: false},
		{name: "ipv4 private", host: "10.0.0.1", wantErr: false},
		{name: "ipv4 loopback", host: "127.0.0.1", wantErr: false},

		// IPv6 (unbracketed — the only accepted form)
		{name: "ipv6 loopback", host: "::1", wantErr: false},
		{name: "ipv6 global", host: "2001:db8::1", wantErr: false},
		{name: "ipv6 with brackets", host: "[::1]", wantErr: true},

		// DNS names
		{name: "dns simple", host: "example.com", wantErr: false},
		{name: "dns fqdn", host: "ldap.example.com", wantErr: false},
		{name: "dns with hyphen", host: "ldap-1.example.com", wantErr: false},

		// URL-special characters
		{name: "with slash", host: "1.2.3.4/24", wantErr: true},
		{name: "with at", host: "user@host", wantErr: true},
		{name: "with colon", host: "host:389", wantErr: true},
		{name: "with hash", host: "host#x", wantErr: true},
		{name: "with question", host: "host?x", wantErr: true},
		{name: "with brackets", host: "host[x]", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateHost(tt.host)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidArgument)
				return
			}
			require.NoError(t, err)
		})
	}
}

// --- formatHost ---

func TestFormatHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "ipv4 unchanged", host: "192.168.1.1", want: "192.168.1.1"},
		{name: "ipv6 loopback bracketed", host: "::1", want: "[::1]"},
		{name: "ipv6 global bracketed", host: "2001:db8::1", want: "[2001:db8::1]"},
		{name: "dns unchanged", host: "example.com", want: "example.com"},
		{name: "empty unchanged", host: "", want: ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, formatHost(tt.host))
		})
	}
}
