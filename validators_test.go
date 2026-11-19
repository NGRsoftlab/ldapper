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

		// F7: the empty string is a valid DN per RFC 4514 — it denotes
		// the root DSE. validateDN accepts it; validateBaseDN rejects it.
		// This distinction is a load-bearing part of the contract: search
		// methods must not silently turn "" into a whole-tree search.
		{name: "empty DN (root DSE)", dn: "", wantErr: false},

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
		// F7: the empty DN parses (validateDN returns nil), but search
		// methods must reject it — an empty base DN would read the whole
		// tree. validateBaseDN is the strict variant that enforces this.
		{name: "empty (rejected by validateBaseDN)", dn: "", wantErr: true},
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

		// F4: IPv6 scoped literals (fe80::1%zone) are not supported.
		// net.ParseIP rejects the "%zone" suffix, the input falls into
		// the DNS branch, and the ":" character causes rejection. This
		// is documented in validateHost's godoc — the test pins the
		// limitation so a future "helpful" change to ParseIP handling
		// cannot silently accept unsupported forms.
		{name: "ipv6 with zone id rejected", host: "fe80::1%eth0", wantErr: true},
		{name: "ipv6 with zone id and brackets rejected", host: "[fe80::1%eth0]", wantErr: true},

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
		// F4 companion: formatHost does not strip or understand the zone
		// suffix either. An IPv6 scoped literal is not parsed as an IP
		// by net.ParseIP, so formatHost falls through to the raw form.
		// This is consistent with validateHost's rejection upstream — a
		// scoped literal never reaches formatHost in production code.
		{name: "ipv6 zone not bracketed (not an IP)", host: "fe80::1%eth0", want: "fe80::1%eth0"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, formatHost(tt.host))
		})
	}
}

// --- isIPLiteral (E5) ---

// TestIsIPLiteral pins the shared IP-vs-DNS detection that validateHost
// and formatHost now rely on. If this behaviour drifts, both callers drift
// together — which is the point of extracting it in the first place.
func TestIsIPLiteral(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		host     string
		wantIP   bool
		wantTo4  bool // meaningful only when wantIP is true
		anyIPNil bool // true when wantIP is true and we don't care about v4/v6
	}{
		// IPv4
		{name: "ipv4 simple", host: "192.168.1.1", wantIP: true, wantTo4: true},
		{name: "ipv4 loopback", host: "127.0.0.1", wantIP: true, wantTo4: true},

		// IPv6
		{name: "ipv6 loopback", host: "::1", wantIP: true, wantTo4: false},
		{name: "ipv6 global", host: "2001:db8::1", wantIP: true, wantTo4: false},

		// Not an IP
		{name: "dns name", host: "example.com", wantIP: false},
		{name: "empty", host: "", wantIP: false},
		{name: "scoped ipv6 not an IP", host: "fe80::1%eth0", wantIP: false},
		{name: "bracketed ipv6 not an IP", host: "[::1]", wantIP: false},
		{name: "host:port not an IP", host: "host:389", wantIP: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ip, ok := isIPLiteral(tt.host)
			require.Equal(t, tt.wantIP, ok, "isIPLiteral(%q) ok mismatch", tt.host)
			if !ok {
				assert.Nil(t, ip)
				return
			}
			require.NotNil(t, ip)
			assert.Equal(t, tt.wantTo4, ip.To4() != nil,
				"IPv4/IPv6 classification mismatch for %q", tt.host)
		})
	}
}
