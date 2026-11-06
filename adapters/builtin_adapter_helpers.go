// Copyright 2020-2026 NGR Softlab
package adapters

import "github.com/go-ldap/ldap/v3"

// ouNameFromDN extracts the first RDN value; falls back to the whole DN
// when the server returns something unparsable — discovery must not crash.
func ouNameFromDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return dn
	}
	return parsed.RDNs[0].Attributes[0].Value
}
