// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func attrsToMap(entry *ldap.Entry, attributes []string) map[string][]string {
	m := make(map[string][]string, len(attributes))
	for _, attr := range attributes {
		m[attr] = entry.GetAttributeValues(attr)
	}
	return m
}

// escapeFilterArgs converts each argument to its RFC 4515 escaped form,
// suitable for substitution into an LDAP filter template via fmt.Sprintf.
// NB: nil args are rendered as "" — callers must not pass nil if the
// resulting filter would be ambiguous (e.g. "(cn=)").
func escapeFilterArgs(args []any) []any {
	if len(args) == 0 {
		return nil
	}
	out := make([]any, len(args))
	for i, arg := range args {
		if arg == nil {
			out[i] = ""
			continue
		}
		out[i] = ldap.EscapeFilter(fmt.Sprint(arg))
	}
	return out
}

// parentDNOf returns the parent DN string, or "" for the topmost RDN.
func parentDNOf(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) <= 1 {
		return ""
	}
	parent := &ldap.DN{RDNs: parsed.RDNs[1:]}
	return parent.String()
}

// canonicalDN returns a stable, case-folded representation of a DN suitable
// for use as an equivalence key in tree construction. It approximates LDAP
// DN equality by:
//   - parsing with RFC 4514 rules (ldap.ParseDN normalizes escape sequences
//     to the underlying octets);
//   - lowercasing attribute types (schema attribute names are case-
//     insensitive per RFC 4512);
//   - lowercasing and trimming attribute values (approximation of
//     caseIgnoreMatch, the default for most naming attributes);
//   - sorting multi-valued RDN attributes by type+value, so that
//     "cn=a+sn=b" and "sn=b+cn=a" produce the same key;
//   - preserving RDN order (RDN order is significant).
//
// It is NOT a full RFC 4517 matching-rules implementation — that requires
// the schema. It deliberately over-merges: two DNs that differ only in
// value case are treated as equivalent, which is correct for caseIgnoreMatch
// attributes (cn, ou, dc, ...) and may over-merge for caseExactMatch ones.
// This trade-off is acceptable for tree linking: the alternative (raw
// server string) under-merges and produces spurious roots.
//
// Malformed DNs fall back to strings.ToLower(dn). The entry will then be
// rejected by AncestorOfFold checks upstream and skipped — the correct
// fail-safe behaviour.
func canonicalDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || parsed == nil {
		return strings.ToLower(dn)
	}

	rdnParts := make([]string, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		attrParts := make([]string, 0, len(rdn.Attributes))
		for _, a := range rdn.Attributes {
			attrParts = append(attrParts,
				strings.ToLower(a.Type)+"="+strings.ToLower(strings.TrimSpace(a.Value)))
		}
		sort.Strings(attrParts)
		rdnParts = append(rdnParts, strings.Join(attrParts, "+"))
	}
	return strings.Join(rdnParts, ",")
}
