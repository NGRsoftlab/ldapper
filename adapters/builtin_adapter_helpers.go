// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ouNameFromDN extracts the first RDN value; falls back to the whole DN
// when the server returns something unparsable — discovery must not crash.
//
// "First RDN value" is taken literally: ouNameFromDN does NOT check that
// the first RDN's attribute type is "ou". For a real organizationalUnit
// DN like "ou=sales,dc=example" this returns "sales" (the ou value); for
// a user DN like "cn=Alice,ou=people,dc=example" it returns "Alice" (the
// cn value). Shipped adapters call this only from
// GetNormalizedOUInfoFromEntry, where the entry passed OUObjectFilter and
// therefore IS a container — but the helper itself makes no such
// assumption, and callers that feed it arbitrary DNs will get the first
// RDN value, whatever it happens to be.
//
// The returned string is suitable for display (tree labels, log lines),
// not for identification. Use entry.DN for that.
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
//
// attrType is validated upfront (see validateAttrType). ldap.DN.String()
// happily renders any string as an attribute type ("foo bar=x") but
// ldap.ParseDN rejects the result, so a downstream bind would fail with a
// confusing "invalid DN" from the server instead of a clear error here.
// Shipped adapters pass literal "uid"/"cn", so the guard only affects
// custom callers.
func appendRDN(attrType, value, baseDN string) (string, error) {
	if err := validateAttrType(attrType); err != nil {
		return "", err
	}
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

// validateAttrType rejects attribute types that do not match RFC 4514's
// grammar:
//
//	attributeType = descr / numericoid
//	descr         = ALPHA *( ALPHA / DIGIT / HYPHEN )
//	numericoid    = number 1*( DOT number )
//
// A full numeric-OID validation (leading-zero rules, etc.) is not needed —
// shipped callers use short descr names, and the leading-digit branch here
// blocks the obvious misuses (e.g. a numeric type mixed with letters).
func validateAttrType(t string) error {
	if t == "" {
		return fmt.Errorf("invalid attribute type: empty")
	}
	if t[0] >= '0' && t[0] <= '9' {
		// Numeric OID form: only digits and dots.
		for _, r := range t {
			if !(r >= '0' && r <= '9' || r == '.') {
				return fmt.Errorf("invalid attribute type %q: non-OID character %q", t, r)
			}
		}
		return nil
	}
	if !(t[0] >= 'a' && t[0] <= 'z' || t[0] >= 'A' && t[0] <= 'Z') {
		return fmt.Errorf("invalid attribute type %q: must start with a letter or digit", t)
	}
	for _, r := range t {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("invalid attribute type %q: invalid character %q", t, r)
		}
	}
	return nil
}

// hasRDN reports whether dn contains a single-valued RDN of the form
// <typ>=<value>, compared case-insensitively per RFC 4512 (attribute types
// and, for caseIgnoreMatch attributes like cn, values are case-insensitive).
//
// Multi-valued RDNs (e.g. "cn=a+sn=b") never match: FreeIPA's cn=accounts
// and cn=users are single-valued naming attributes, and matching a
// multi-valued RDN there would be ambiguous — better to miss than to add a
// duplicate.
//
// This helper exists because substring matching on DN strings is unsound:
// it is case-sensitive (CN=ACCOUNTS would not match cn=accounts) and
// false-positive-prone (pcn=accounts matches but is a different RDN). See
// FREEIPAAdapter.BindIdentity for the specific bug this prevents.
func hasRDN(dn *ldap.DN, typ, value string) bool {
	if dn == nil {
		return false
	}
	for _, rdn := range dn.RDNs {
		if len(rdn.Attributes) != 1 {
			continue
		}
		a := rdn.Attributes[0]
		if strings.EqualFold(a.Type, typ) && strings.EqualFold(a.Value, value) {
			return true
		}
	}
	return false
}
