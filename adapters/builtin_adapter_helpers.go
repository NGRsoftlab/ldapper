// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// ouNameFromDN extracts the first RDN value; falls back to the whole DN
// when the server returns something unparsable — discovery must not crash.
func ouNameFromDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return dn
	}
	return parsed.RDNs[0].Attributes[0].Value
}

// appendRDN returns a DN built by prepending rdn (type=value) to baseDN.
// Escaping of value is handled by ldap.DN.String(), so the caller can pass
// raw login strings containing , + = \ safely.
func appendRDN(attrType, value, baseDN string) (string, error) {
	base, err := ldap.ParseDN(baseDN)
	if err != nil {
		return "", fmt.Errorf("invalid baseDN %q: %w", baseDN, err)
	}
	rdn := &ldap.RelativeDN{
		Attributes: []*ldap.AttributeTypeAndValue{{Type: attrType, Value: value}},
	}
	combined := &ldap.DN{RDNs: append([]*ldap.RelativeDN{rdn}, base.RDNs...)}
	return combined.String(), nil
}
