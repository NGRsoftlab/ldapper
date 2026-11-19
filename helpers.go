// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// attrsToMap reads the named attributes from entry into a map. Names
// listed more than once in `attributes` are deduplicated (first occurrence
// wins) so the result does not depend on the order of the input slice — the
// previous map assignment was overwrite-based, which made the effective
// contract "last duplicate wins" without documenting it. All shipped
// adapters pass distinct names, so the fix only affects custom adapters
// that accidentally list a name twice.
//
// A key is always present in the map, even when the entry has no such
// attribute: the value is an empty, non-nil slice (go-ldap's
// GetAttributeValues contract).
func attrsToMap(entry *ldap.Entry, attributes []string) map[string][]string {
	m := make(map[string][]string, len(attributes))
	for _, attr := range attributes {
		if _, seen := m[attr]; seen {
			continue
		}
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
//   - escaping the ",", "+", "=" and "\" characters inside values, so
//     that two structurally different DNs (cn=a,ou=b vs cn=a\,ou=b)
//     cannot collide at a join point;
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
// The result is an opaque equivalence key. It is NEVER re-parsed as a DN
// and must not be surfaced as one; the escaping applied to values makes it
// distinct from any RFC 4514 form a server could emit.
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
				strings.ToLower(a.Type)+"="+
					escapeCanonicalValue(strings.ToLower(strings.TrimSpace(a.Value))))
		}
		sort.Strings(attrParts)
		rdnParts = append(rdnParts, strings.Join(attrParts, "+"))
	}
	return strings.Join(rdnParts, ",")
}

// escapeCanonicalValue escapes the characters that would collide with the
// join separators used to build the canonical key. Without this, two
// structurally different DNs could produce the same string:
//
//	cn=a,ou=b    (two RDNs: cn=a, ou=b)   → "cn=a,ou=b"
//	cn=a\,ou=b   (one RDN:  cn="a,ou=b")  → "cn=a,ou=b"   ← collision
//
// Only ",", "+", "=" and "\" are escaped. Attribute types are already
// constrained by RFC 4514 (they cannot contain these characters), and the
// value is lowercased+trimmed by the caller, so escaping the value is
// sufficient to keep the key injective at every join point:
//
//   - ","  separates RDNs        → escape as "\,"  inside values
//   - "+"  separates attributes  → escape as "\+"  inside values
//   - "="  separates type/value  → escape as "\="  inside values
//   - "\"  is our own escape char → escape as "\\" inside values
//
// The result is NOT a re-parseable DN. It is an opaque equivalence key only.
func escapeCanonicalValue(v string) string {
	// Fast path: most values (cn, ou, dc, ...) contain none of the
	// structural characters, so no allocation is needed.
	if !strings.ContainsAny(v, `,+\=`) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case ',':
			b.WriteString(`\,`)
		case '+':
			b.WriteString(`\+`)
		case '=':
			b.WriteString(`\=`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
