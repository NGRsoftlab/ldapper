// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
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

// trimDepth returns a copy of nodes truncated to maxDepth (1 = only roots).
func trimDepth(nodes []*types.OUNormalizedInfo, maxDepth int) []*types.OUNormalizedInfo {
	out := make([]*types.OUNormalizedInfo, 0, len(nodes))
	for _, n := range nodes {
		clone := *n
		if maxDepth <= 1 {
			clone.Children = make([]*types.OUNormalizedInfo, 0)
		} else {
			clone.Children = trimDepth(n.Children, maxDepth-1)
		}
		out = append(out, &clone)
	}
	return out
}
